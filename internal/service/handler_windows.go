package service

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/vlqri7qwml/cx/internal/checker"
	"github.com/vlqri7qwml/cx/internal/config"
	"github.com/vlqri7qwml/cx/internal/firewall"
	"github.com/vlqri7qwml/cx/internal/ipc"
	"github.com/vlqri7qwml/cx/internal/socks5"
)

// Handle 实现 ipc.Handler，是托盘所有请求的入口。
//
// 只读请求就地应答；会改变隧道状态的请求交给 Run 的控制循环串行执行。
func (m *Manager) Handle(req ipc.Request) ipc.Response {
	switch req.Op {
	case ipc.OpStatus:
		return ipc.Response{OK: true, Status: m.Status()}

	case ipc.OpGetConfig:
		m.mu.RLock()
		cfg := m.cfg.Sanitized()
		m.mu.RUnlock()
		return ipc.Response{OK: true, Config: cfg}

	case ipc.OpTestNode:
		return m.testNode(req.Index)

	case ipc.OpCheckExitIP:
		return m.checkExitIP()

	case ipc.OpConnect, ipc.OpDisconnect, ipc.OpSelectNode,
		ipc.OpSaveConfig, ipc.OpSetPassword, ipc.OpExit:
		return m.dispatch(req)
	}
	return ipc.Failf("不支持的操作 %q", req.Op)
}

// dispatch 把请求交给控制循环并等待结果。
func (m *Manager) dispatch(req ipc.Request) ipc.Response {
	c := &command{req: req, resp: make(chan ipc.Response, 1)}
	select {
	case m.cmds <- c:
	case <-time.After(cmdTimeout):
		return ipc.Failf("服务正忙，请稍后再试")
	case <-m.exitCh:
		return ipc.Failf("服务正在退出")
	}
	select {
	case resp := <-c.resp:
		return resp
	case <-time.After(cmdTimeout):
		return ipc.Failf("操作超时")
	}
}

// Status 返回当前状态快照。
func (m *Manager) Status() *ipc.Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	nodes := make([]ipc.NodeBrief, 0, len(m.cfg.Nodes))
	for i, n := range m.cfg.Nodes {
		lat, ok := m.latency[i]
		if !ok {
			lat = -1
		}
		nodes = append(nodes, ipc.NodeBrief{
			Index:     i,
			Label:     n.Label(),
			Addr:      n.Addr(),
			LatencyMS: lat,
			Region:    m.regions[i],
		})
	}

	st := &ipc.Status{
		State:       m.state,
		Message:     m.message,
		NodeIndex:   m.cfg.Active,
		Nodes:       nodes,
		AllowLAN:    m.cfg.AllowLAN,
		BlockQUIC:   m.cfg.BlockQUIC,
		HasPassword: m.cfg.HasPassword(),
		TunName:     m.cfg.TunName,
		Exit:        m.exitInfo,
		Stats:       m.stats.Snapshot(),
		Since:       m.since,
		Version:     Version,
		LogDir:      config.LogDir(),
	}
	if n, ok := m.cfg.ActiveNode(); ok {
		st.NodeLabel = n.Label()
	}
	if m.engine != nil {
		st.ProxyAddr = m.engine.ProxyAddr()
	}
	st.KillSwitch = m.killSwitchActive()
	return st
}

// killSwitchCacheTTL 控制向 WFP 求证断网保护状态的频率。
//
// 托盘每 2 秒拉一次状态，而每次 firewall.Installed() 都要开关一次 WFP 引擎会话。
// 这个状态只会因为本服务自己的操作而改变，短暂缓存既不影响可信度，
// 又避免了长期运行下的无谓开销。
const killSwitchCacheTTL = 5 * time.Second

// killSwitchActive 返回持久化断网保护规则是否在位。
//
// 这个值必须向 WFP 求证，而不是凭内存里的标志 ——
// 它是托盘上“保护中”指示的唯一可信来源。
func (m *Manager) killSwitchActive() bool {
	now := time.Now()

	m.ksMu.Lock()
	if now.Sub(m.ksAt) < killSwitchCacheTTL {
		v := m.ksOn
		m.ksMu.Unlock()
		return v
	}
	m.ksMu.Unlock()

	ok, err := firewall.Installed()
	if err != nil {
		// 查不到就沿用上一次的结论，不要因为一次 RPC 失败就在界面上
		// 误报“保护已失效”，那会让员工以为可以放心直连。
		m.ksMu.Lock()
		v := m.ksOn
		m.ksMu.Unlock()
		return v
	}

	m.ksMu.Lock()
	m.ksOn, m.ksAt = ok, now
	m.ksMu.Unlock()
	return ok
}

// testNode 测试指定节点的连通性与握手延迟。
func (m *Manager) testNode(index int) ipc.Response {
	m.mu.RLock()
	monitor := m.monitor
	var node config.Node
	if index < 0 || index >= len(m.cfg.Nodes) {
		m.mu.RUnlock()
		return ipc.Failf("节点序号 %d 不存在", index)
	}
	node = m.cfg.Nodes[index]
	m.mu.RUnlock()

	if monitor == nil {
		return ipc.Failf("网卡监视器不可用")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	addrs, err := monitor.ResolveProxyHost(ctx, node.Host, 6*time.Second)
	if err != nil {
		return ipc.Fail(err)
	}

	client := &socks5.Client{
		Addr:     net.JoinHostPort(addrs[0].String(), fmt.Sprint(node.Port)),
		Username: node.Username,
		Password: node.Password,
		Dial:     monitor.Dialer(8 * time.Second),
		Timeout:  8 * time.Second,
	}
	d, err := client.Probe(ctx)
	if err != nil {
		return ipc.Fail(err)
	}

	ms := int(d.Milliseconds())
	m.mu.Lock()
	m.latency[index] = ms
	m.mu.Unlock()

	return ipc.Response{OK: true, LatencyMS: ms}
}

// checkExitIP 经当前隧道探测出口 IP。
func (m *Manager) checkExitIP() ipc.Response {
	m.mu.RLock()
	engine, state := m.engine, m.state
	m.mu.RUnlock()

	if state != ipc.StateConnected || engine == nil {
		return ipc.Failf("尚未连接，无法探测出口 IP")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	info, err := checker.Check(ctx, func(ctx context.Context, target string) (net.Conn, error) {
		return engine.Client().DialContext(ctx, target)
	}, nil, 12*time.Second)
	if err != nil {
		return ipc.Fail(err)
	}

	m.mu.Lock()
	if m.engine == engine {
		m.exitInfo = info
		if idx := m.cfg.Active; idx >= 0 {
			m.regions[idx] = info.Region
		}
	}
	m.mu.Unlock()

	return ipc.Response{OK: true, Exit: info}
}

// handleControl 在控制循环内串行处理会改变状态的请求。
func (m *Manager) handleControl(req ipc.Request) ipc.Response {
	switch req.Op {
	case ipc.OpConnect:
		m.mu.Lock()
		m.manual = false
		m.mu.Unlock()
		m.doConnect()
		if st := m.currentState(); st != ipc.StateConnected {
			m.mu.RLock()
			msg := m.message
			m.mu.RUnlock()
			return ipc.Failf("连接失败：%s", msg)
		}
		return ipc.Response{OK: true, Status: m.Status()}

	case ipc.OpDisconnect:
		m.mu.Lock()
		m.manual = true
		m.mu.Unlock()
		m.teardownTunnel()
		m.setState(ipc.StateDisconnected, "已手动断开，整机当前无法联网")
		return ipc.Response{OK: true, Status: m.Status()}

	case ipc.OpSelectNode:
		m.mu.Lock()
		if req.Index < 0 || req.Index >= len(m.cfg.Nodes) {
			m.mu.Unlock()
			return ipc.Failf("节点序号 %d 不存在", req.Index)
		}
		m.cfg.Active = req.Index
		m.manual = false
		cfg := m.cfg
		m.mu.Unlock()

		if err := config.Save(m.cfgPath, cfg); err != nil {
			return ipc.Failf("保存配置失败: %v", err)
		}
		m.doConnect()
		if st := m.currentState(); st != ipc.StateConnected {
			m.mu.RLock()
			msg := m.message
			m.mu.RUnlock()
			return ipc.Failf("已切换节点，但连接失败：%s", msg)
		}
		return ipc.Response{OK: true, Status: m.Status()}

	case ipc.OpSaveConfig:
		return m.saveConfig(req)

	case ipc.OpSetPassword:
		return m.setPassword(req)

	case ipc.OpExit:
		return m.exitProtection(req)
	}
	return ipc.Failf("不支持的操作 %q", req.Op)
}

// requirePassword 校验管理员密码（带失败限速）。
//
// 尚未设置密码时允许通过：首次安装后必须有一条路径能进去设置密码。
func (m *Manager) requirePassword(pw string) error {
	m.mu.RLock()
	cfg := m.cfg
	hasPW := cfg.HasPassword()
	m.mu.RUnlock()

	if !hasPW {
		return nil
	}
	return m.throttle.Verify(cfg, pw)
}

func (m *Manager) saveConfig(req ipc.Request) ipc.Response {
	if req.Config == nil {
		return ipc.Failf("请求缺少配置内容")
	}
	if err := m.requirePassword(req.Password); err != nil {
		return ipc.Fail(err)
	}

	m.mu.Lock()
	old := m.cfg
	newCfg := *req.Config
	// 界面不持有明文代理密码，掩码占位符要回填为原值。
	newCfg.MergeSecrets(old)
	// 管理员密码只能通过 OpSetPassword 修改，保存配置时一律沿用旧哈希。
	newCfg.PasswordHash = old.PasswordHash
	newCfg.Normalize()
	if err := newCfg.Validate(); err != nil {
		m.mu.Unlock()
		return ipc.Fail(err)
	}
	lanChanged := newCfg.AllowLAN != old.AllowLAN
	needReconnect := lanChanged ||
		newCfg.BlockQUIC != old.BlockQUIC ||
		newCfg.Active != old.Active ||
		newCfg.TunName != old.TunName ||
		!sameNodes(newCfg.Nodes, old.Nodes) ||
		!sameStrings(newCfg.DNSServers, old.DNSServers)
	m.cfg = &newCfg
	m.mu.Unlock()

	if err := config.Save(m.cfgPath, &newCfg); err != nil {
		return ipc.Failf("保存配置失败: %v", err)
	}
	m.logger.Printf("配置已更新（允许局域网=%v，阻止 QUIC=%v，节点 %d 个）",
		newCfg.AllowLAN, newCfg.BlockQUIC, len(newCfg.Nodes))

	// 局域网放行范围变了就要重建持久规则。整个过程在一个 WFP 事务里完成，
	// 不会出现中途放行的窗口。
	if lanChanged {
		if err := firewall.Enable(firewall.Options{AllowLAN: newCfg.AllowLAN}); err != nil {
			return ipc.Failf("更新断网保护规则失败: %v", err)
		}
		m.logger.Printf("断网保护规则已重建（允许局域网=%v）", newCfg.AllowLAN)
	}

	if needReconnect && m.currentState() == ipc.StateConnected {
		m.doConnect()
	}
	return ipc.Response{OK: true, Status: m.Status()}
}

func (m *Manager) setPassword(req ipc.Request) ipc.Response {
	if err := config.CheckPasswordStrength(req.NewPassword); err != nil {
		return ipc.Fail(err)
	}
	if err := m.requirePassword(req.Password); err != nil {
		return ipc.Fail(err)
	}

	m.mu.Lock()
	newCfg := *m.cfg
	newCfg.Nodes = append([]config.Node(nil), m.cfg.Nodes...)
	if err := newCfg.SetPassword(req.NewPassword); err != nil {
		m.mu.Unlock()
		return ipc.Fail(err)
	}
	m.cfg = &newCfg
	m.mu.Unlock()

	if err := config.Save(m.cfgPath, &newCfg); err != nil {
		return ipc.Failf("保存配置失败: %v", err)
	}
	m.logger.Printf("管理员密码已更新")
	return ipc.Response{OK: true, Status: m.Status()}
}

// exitProtection 是恢复直连的唯一出口：校验管理员密码后拆掉全部规则并停止服务。
func (m *Manager) exitProtection(req ipc.Request) ipc.Response {
	m.mu.RLock()
	hasPW := m.cfg.HasPassword()
	m.mu.RUnlock()

	if !hasPW {
		// 没设密码就谁都能退出保护，等于没有保护。
		// 安装完成后托盘会强制先设密码，这里只是兜底。
		return ipc.Failf("尚未设置管理员密码，无法退出保护；请先在设置中设置密码")
	}
	if err := m.requirePassword(req.Password); err != nil {
		return ipc.Fail(err)
	}

	m.setState(ipc.StateStopping, "正在拆除断网保护")
	m.teardownTunnel()
	if err := firewall.Disable(); err != nil {
		m.setState(ipc.StateError, fmt.Sprintf("拆除断网保护失败: %v", err))
		return ipc.Failf("拆除断网保护失败: %v（可用管理员权限执行 cxproxy.exe unblock 应急恢复）", err)
	}
	m.logger.Printf("管理员已退出保护，断网保护规则已全部移除，网络恢复直连")

	// 先把成功应答留给托盘，再让主循环退出。
	go func() {
		time.Sleep(400 * time.Millisecond)
		m.signalExit()
	}()
	return ipc.Response{OK: true}
}

func (m *Manager) signalExit() {
	select {
	case <-m.exitCh:
	default:
		close(m.exitCh)
	}
}

func sameNodes(a, b []config.Node) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
