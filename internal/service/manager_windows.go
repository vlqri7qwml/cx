package service

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/vlqri7qwml/cx/internal/checker"
	"github.com/vlqri7qwml/cx/internal/config"
	"github.com/vlqri7qwml/cx/internal/firewall"
	"github.com/vlqri7qwml/cx/internal/ipc"
	"github.com/vlqri7qwml/cx/internal/logx"
	"github.com/vlqri7qwml/cx/internal/netbind"
	"github.com/vlqri7qwml/cx/internal/route"
	"github.com/vlqri7qwml/cx/internal/tunnel"
)

const (
	// healthInterval 是健康检查周期。
	healthInterval = 15 * time.Second
	// healthTimeout 是单次健康检查的超时。
	healthTimeout = 8 * time.Second
	// healthFailuresBeforeReconnect 连续失败多少次才重连，避免偶发抖动触发重连。
	healthFailuresBeforeReconnect = 2

	// retryMin / retryMax 是自动重连的退避区间。
	retryMin = 5 * time.Second
	retryMax = 60 * time.Second

	// cmdTimeout 是 IPC 命令等待控制循环处理的上限。
	cmdTimeout = 90 * time.Second
)

// Manager 是服务的核心状态机。
//
// 所有会改变隧道状态的操作都被串行化到 Run 的控制循环里处理，
// 只有状态查询走读锁快照 —— 这样托盘每秒轮询状态时，
// 不会被一次耗时十几秒的连接过程卡住。
type Manager struct {
	cfgPath string
	logger  *logx.Logger

	mu       sync.RWMutex
	cfg      *config.Config
	state    ipc.State
	message  string
	since    time.Time
	engine   *tunnel.Engine
	exitInfo *checker.ExitInfo
	latency  map[int]int
	regions  map[int]string

	stats    *tunnel.Stats
	monitor  *netbind.Monitor
	throttle *config.Throttle

	// 断网保护状态的短缓存，单独用一把锁，免得被 doConnect 这类长操作挡住。
	ksMu sync.Mutex
	ksOn bool
	ksAt time.Time

	cmds     chan *command
	ifaceCh  chan struct{}
	exitCh   chan struct{}
	manual   bool // 用户主动断开，此时不自动重连
	failures int
}

type command struct {
	req  ipc.Request
	resp chan ipc.Response
}

// NewManager 构造管理器并载入配置。
func NewManager(cfgPath string, logger *logx.Logger) (*Manager, error) {
	cfg, found, err := config.Load(cfgPath)
	if err != nil {
		// 配置损坏不能让服务起不来：退回默认值并记录，
		// 否则一台机器的配置文件坏掉就等于永久断网且无法补救。
		logger.Printf("警告：读取配置失败，已退回默认配置: %v", err)
		cfg = config.Default()
	}
	if !found {
		logger.Printf("未找到配置文件 %s，使用默认配置", cfgPath)
	}

	return &Manager{
		cfgPath:  cfgPath,
		logger:   logger,
		cfg:      cfg,
		state:    ipc.StateDisconnected,
		since:    time.Now(),
		latency:  make(map[int]int),
		regions:  make(map[int]string),
		stats:    &tunnel.Stats{},
		throttle: config.NewThrottle(),
		cmds:     make(chan *command, 16),
		ifaceCh:  make(chan struct{}, 1),
		exitCh:   make(chan struct{}),
	}, nil
}

// Run 执行服务主循环，返回时服务即停止。
//
// 启动顺序刻意如此：先装断网保护，再做其他任何事。
// 这样即使后面任何一步失败（配置错误、代理不可达、驱动缺失），
// 机器也只会“没有网”，而绝不会以真实 IP 裸奔。
func (m *Manager) Run(ctx context.Context) error {
	m.mu.RLock()
	allowLAN := m.cfg.AllowLAN
	m.mu.RUnlock()

	if err := firewall.Enable(firewall.Options{AllowLAN: allowLAN}); err != nil {
		// 这是致命错误：装不上阻断规则就没有保护可言，宁可让服务起不来，
		// 由 SCM 的恢复策略反复重试，也不能假装一切正常。
		return fmt.Errorf("安装断网保护规则失败: %w", err)
	}
	m.logger.Printf("断网保护已生效（允许局域网=%v）", allowLAN)

	monitor, err := netbind.NewMonitor(0, func(iface netbind.Iface, ok bool) {
		if ok {
			m.logger.Printf("物理出口网卡变为 %s", iface)
		} else {
			m.logger.Printf("当前没有可用的物理出口网卡")
		}
		select {
		case m.ifaceCh <- struct{}{}:
		default:
		}
	})
	if err != nil {
		m.logger.Printf("警告：网卡监视器启动失败，网络切换后可能需要手动重连: %v", err)
	} else {
		defer monitor.Close()
	}

	m.mu.Lock()
	m.monitor = monitor
	m.mu.Unlock()

	ln, err := ipc.Listen()
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		if err := ipc.Serve(ctx, ln, m); err != nil {
			m.logger.Printf("IPC 服务退出: %v", err)
		}
	}()

	health := time.NewTicker(healthInterval)
	defer health.Stop()

	var (
		retryTimer = time.NewTimer(retryMin)
		retryDelay = retryMin
	)
	retryTimer.Stop()
	defer retryTimer.Stop()

	armRetry := func() {
		if !m.autoConnectWanted() {
			return
		}
		retryTimer.Reset(retryDelay)
		m.logger.Printf("将在 %s 后重试连接", retryDelay)
	}

	if m.autoConnectWanted() {
		m.doConnect()
		// 开机时代理多半还连不上（网卡刚起来、DHCP 还没拿到地址），
		// 首次失败必须也排上重试，否则机器会一直停在“无网”上等人来点。
		if m.currentState() != ipc.StateConnected {
			armRetry()
		}
	} else {
		m.setState(ipc.StateDisconnected, "未配置节点或未开启自动连接")
	}

	for {
		select {
		case <-ctx.Done():
			m.logger.Printf("服务收到停止信号：关闭隧道，但保留断网保护规则")
			m.teardownTunnel()
			return nil

		case <-m.exitCh:
			// 管理员已通过托盘校验密码并要求退出保护，此处正常返回即可。
			return nil

		case c := <-m.cmds:
			c.resp <- m.handleControl(c.req)
			if m.currentState() == ipc.StateError {
				armRetry()
			}

		case <-m.ifaceCh:
			if m.currentState() == ipc.StateConnected {
				m.logger.Printf("网络环境变化，重新建立隧道")
				m.doConnect()
			} else if m.autoConnectWanted() {
				m.doConnect()
			}
			if m.currentState() == ipc.StateError {
				armRetry()
			}

		case <-retryTimer.C:
			if m.autoConnectWanted() && m.currentState() != ipc.StateConnected {
				m.doConnect()
			}
			if m.currentState() == ipc.StateConnected {
				retryDelay = retryMin
			} else {
				retryDelay *= 2
				if retryDelay > retryMax {
					retryDelay = retryMax
				}
				armRetry()
			}

		case <-health.C:
			if m.checkHealth() {
				m.logger.Printf("健康检查连续失败，重新建立隧道")
				m.doConnect()
				if m.currentState() == ipc.StateError {
					armRetry()
				}
			}
		}
	}
}

// autoConnectWanted 判断当前是否应该（重新）建立隧道。
func (m *Manager) autoConnectWanted() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.manual || !m.cfg.AutoConnect {
		return false
	}
	_, ok := m.cfg.ActiveNode()
	return ok
}

func (m *Manager) currentState() ipc.State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *Manager) setState(state ipc.State, msg string) {
	m.mu.Lock()
	changed := m.state != state || m.message != msg
	m.state, m.message = state, msg
	if changed {
		m.since = time.Now()
	}
	m.mu.Unlock()
	if changed {
		if msg != "" {
			m.logger.Printf("状态：%s —— %s", state.Label(), msg)
		} else {
			m.logger.Printf("状态：%s", state.Label())
		}
	}
}

// checkHealth 返回是否需要重连。
func (m *Manager) checkHealth() bool {
	m.mu.RLock()
	engine, state := m.engine, m.state
	m.mu.RUnlock()

	if state != ipc.StateConnected || engine == nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), healthTimeout)
	defer cancel()
	if _, err := engine.Client().Probe(ctx); err != nil {
		m.failures++
		m.logger.Printf("健康检查失败（第 %d 次）: %v", m.failures, err)
		return m.failures >= healthFailuresBeforeReconnect
	}
	m.failures = 0
	return false
}

// doConnect 拆掉现有隧道并按当前配置重新建立。
//
// 任何一步失败都只是“连不上”，断网保护规则始终不动，
// 因此失败状态下机器依然无法用真实 IP 出网。
func (m *Manager) doConnect() {
	m.teardownTunnel()

	m.mu.RLock()
	cfg := m.cfg
	node, ok := cfg.ActiveNode()
	monitor := m.monitor
	m.mu.RUnlock()

	if !ok {
		m.setState(ipc.StateError, "没有可用的代理节点，请在设置里添加")
		return
	}
	if monitor == nil {
		m.setState(ipc.StateError, "网卡监视器不可用")
		return
	}

	m.setState(ipc.StateConnecting, fmt.Sprintf("正在连接 %s", node.Label()))

	engine, err := tunnel.Start(tunnel.Options{
		TunName:    cfg.TunName,
		MTU:        config.DefaultTunMTU,
		Node:       node,
		DNSServers: cfg.DNSServers,
		BlockQUIC:  cfg.BlockQUIC,
		BlockAAAA:  true, // 整机只走 IPv4，与 WFP 阻断 IPv6 保持一致
		Monitor:    monitor,
		Stats:      m.stats,
		Logf:       m.logger.Printf,
	})
	if err != nil {
		m.setState(ipc.StateError, err.Error())
		return
	}

	luid := engine.LUID()
	// 排除自家 TUN，避免之后把到代理的连接又绑回 TUN 上。
	monitor.SetExclude(winipcfg.LUID(luid))

	// 先放行 TUN，再把路由引过来：顺序反了会出现几百毫秒的“全断”。
	if err := firewall.PermitTun(luid); err != nil {
		engine.Close()
		m.setState(ipc.StateError, err.Error())
		return
	}

	addr, dnsAddr := engine.TunAddr()
	if err := route.Apply(route.Config{
		LUID: winipcfg.LUID(luid),
		Addr: addr,
		DNS:  []netip.Addr{dnsAddr},
		MTU:  engine.MTU(),
	}); err != nil {
		firewall.RevokeTun()
		engine.Close()
		m.setState(ipc.StateError, fmt.Sprintf("配置 TUN 路由失败: %v", err))
		return
	}

	m.mu.Lock()
	m.engine = engine
	m.exitInfo = nil
	m.mu.Unlock()

	m.failures = 0
	m.setState(ipc.StateConnected, fmt.Sprintf("出口 %s", node.Label()))

	// 出口探测比较慢（要跑一次 HTTP），放到后台做，不拖住连接流程。
	go m.refreshExitInfo(engine)
}

// teardownTunnel 拆掉隧道与路由，但保留断网保护规则。
func (m *Manager) teardownTunnel() {
	m.mu.Lock()
	engine := m.engine
	m.engine = nil
	m.mu.Unlock()

	if engine == nil {
		return
	}
	luid := winipcfg.LUID(engine.LUID())
	if err := route.Clear(luid); err != nil {
		m.logger.Printf("清理 TUN 路由时出错（通常无害）: %v", err)
	}
	firewall.RevokeTun()
	engine.Close()
	m.logger.Printf("隧道已关闭")
}

// refreshExitInfo 经代理探测出口 IP 与归属地。
func (m *Manager) refreshExitInfo(engine *tunnel.Engine) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	info, err := checker.Check(ctx, func(ctx context.Context, target string) (net.Conn, error) {
		return engine.Client().DialContext(ctx, target)
	}, nil, 12*time.Second)
	if err != nil {
		m.logger.Printf("出口探测失败: %v", err)
		return
	}

	m.mu.Lock()
	// 期间可能已经换了隧道，避免把旧结果写到新连接上。
	if m.engine == engine {
		m.exitInfo = info
		if idx := m.cfg.Active; idx >= 0 {
			m.regions[idx] = info.Region
		}
	}
	m.mu.Unlock()
	m.logger.Printf("出口确认：%s（来源 %s）", info.Label(), info.Source)
}
