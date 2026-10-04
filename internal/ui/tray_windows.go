package ui

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/lxn/walk"
	"golang.org/x/sys/windows"

	"github.com/vlqri7qwml/cx/internal/config"
	"github.com/vlqri7qwml/cx/internal/ipc"
	"github.com/vlqri7qwml/cx/internal/service"
)

// pollInterval 是托盘刷新状态的周期。
const pollInterval = 2 * time.Second

// singleInstanceMutex 保证同一个会话里只有一个托盘。
const singleInstanceMutex = `Local\CXProxyTray`

type tray struct {
	mw  *walk.MainWindow
	ni  *walk.NotifyIcon
	cli *client

	iconConnected   *walk.Icon
	iconConnecting  *walk.Icon
	iconBlocked     *walk.Icon
	iconUnprotected *walk.Icon

	actState    *walk.Action
	actExitInfo *walk.Action
	nodeMenu    *walk.Menu
	actNodeMenu *walk.Action
	nodeActions []*walk.Action
	actConnect  *walk.Action
	actDiscon   *walk.Action
	actCheckIP  *walk.Action
	actSettings *walk.Action
	actLogs     *walk.Action
	actStartSvc *walk.Action
	actQuit     *walk.Action

	mu        sync.Mutex
	status    *ipc.Status
	nodeSig   string
	busy      bool
	logf      func(string, ...any)
	firstShow bool
}

// Run 启动托盘，直到用户退出保护或系统注销才返回。
//
// openSettings 为 true 时启动后立刻打开设置窗口（安装程序安装完成后用它
// 引导管理员设置密码与粘贴代理）。
func Run(logf func(string, ...any), openSettings bool) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}

	released, err := acquireSingleInstance()
	if err != nil {
		return err
	}
	defer released()

	installed, err := service.Installed()
	if err != nil {
		logf("查询服务安装状态失败: %v", err)
	}
	if !installed {
		walk.MsgBox(nil, "CXProxy",
			"CXProxy 服务尚未安装。\n\n请以管理员身份运行安装程序，或执行：cxproxy.exe install",
			walk.MsgBoxIconError)
		return fmt.Errorf("服务未安装")
	}

	t := &tray{cli: newClient(), logf: logf, firstShow: openSettings}
	if err := t.build(); err != nil {
		return err
	}
	defer t.ni.Dispose()
	defer t.mw.Dispose()

	go t.poll()

	t.mw.SetVisible(false)
	t.mw.Run()
	return nil
}

// acquireSingleInstance 用命名互斥体挡住重复启动的托盘。
func acquireSingleInstance() (func(), error) {
	name, err := windows.UTF16PtrFromString(singleInstanceMutex)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		if err == windows.ERROR_ALREADY_EXISTS {
			return nil, fmt.Errorf("CXProxy 托盘已在运行")
		}
		return nil, err
	}
	return func() { windows.CloseHandle(h) }, nil
}

func (t *tray) build() error {
	mw, err := walk.NewMainWindow()
	if err != nil {
		return err
	}
	t.mw = mw
	mw.SetTitle("CXProxy")

	t.iconConnected, err = walk.NewIconFromImageForDPI(makeStatusIcon(colorConnected), 96)
	if err != nil {
		return err
	}
	t.iconConnecting, err = walk.NewIconFromImageForDPI(makeStatusIcon(colorConnecting), 96)
	if err != nil {
		return err
	}
	t.iconBlocked, err = walk.NewIconFromImageForDPI(makeStatusIcon(colorBlocked), 96)
	if err != nil {
		return err
	}
	t.iconUnprotected, err = walk.NewIconFromImageForDPI(makeStatusIcon(colorUnprotected), 96)
	if err != nil {
		return err
	}

	ni, err := walk.NewNotifyIcon(mw)
	if err != nil {
		return err
	}
	t.ni = ni
	_ = ni.SetIcon(t.iconUnprotected)
	_ = ni.SetToolTip("CXProxy —— 正在获取状态…")
	_ = ni.SetVisible(true)

	menu := ni.ContextMenu()

	t.actState = walk.NewAction()
	_ = t.actState.SetText("状态：正在获取…")
	_ = t.actState.SetEnabled(false)
	_ = menu.Actions().Add(t.actState)

	t.actExitInfo = walk.NewAction()
	_ = t.actExitInfo.SetText("出口：未知")
	_ = t.actExitInfo.SetEnabled(false)
	_ = menu.Actions().Add(t.actExitInfo)

	_ = menu.Actions().Add(walk.NewSeparatorAction())

	t.nodeMenu, err = walk.NewMenu()
	if err != nil {
		return err
	}
	t.actNodeMenu = walk.NewMenuAction(t.nodeMenu)
	_ = t.actNodeMenu.SetText("节点")
	_ = menu.Actions().Add(t.actNodeMenu)

	_ = menu.Actions().Add(walk.NewSeparatorAction())

	t.actConnect = walk.NewAction()
	_ = t.actConnect.SetText("连接")
	t.actConnect.Triggered().Attach(t.connect)
	_ = menu.Actions().Add(t.actConnect)

	t.actDiscon = walk.NewAction()
	_ = t.actDiscon.SetText("断开（整机将无网）")
	t.actDiscon.Triggered().Attach(t.disconnect)
	_ = menu.Actions().Add(t.actDiscon)

	t.actCheckIP = walk.NewAction()
	_ = t.actCheckIP.SetText("检测出口 IP")
	t.actCheckIP.Triggered().Attach(t.checkExitIP)
	_ = menu.Actions().Add(t.actCheckIP)

	_ = menu.Actions().Add(walk.NewSeparatorAction())

	t.actSettings = walk.NewAction()
	_ = t.actSettings.SetText("设置…")
	t.actSettings.Triggered().Attach(func() { t.openSettings(false) })
	_ = menu.Actions().Add(t.actSettings)

	t.actLogs = walk.NewAction()
	_ = t.actLogs.SetText("打开日志目录")
	t.actLogs.Triggered().Attach(t.openLogs)
	_ = menu.Actions().Add(t.actLogs)

	t.actStartSvc = walk.NewAction()
	_ = t.actStartSvc.SetText("启动保护")
	_ = t.actStartSvc.SetVisible(false)
	t.actStartSvc.Triggered().Attach(t.startService)
	_ = menu.Actions().Add(t.actStartSvc)

	_ = menu.Actions().Add(walk.NewSeparatorAction())

	t.actQuit = walk.NewAction()
	_ = t.actQuit.SetText("退出（恢复网络）…")
	t.actQuit.Triggered().Attach(t.quit)
	_ = menu.Actions().Add(t.actQuit)

	ni.MouseUp().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			t.openSettings(false)
		}
	})
	return nil
}

// poll 周期性拉取状态并刷新界面。
func (t *tray) poll() {
	tick := time.NewTicker(pollInterval)
	defer tick.Stop()

	first := true
	for {
		st, err := t.cli.status()
		t.mw.Synchronize(func() {
			t.apply(st, err)
			if first && t.firstShow && err == nil {
				first = false
				t.openSettings(st != nil && !st.HasPassword)
			}
		})
		if first && err == nil {
			first = false
		}
		<-tick.C
	}
}

// apply 把状态映射到图标、提示与菜单项。
func (t *tray) apply(st *ipc.Status, err error) {
	t.mu.Lock()
	t.status = st
	t.mu.Unlock()

	if err != nil || st == nil {
		_ = t.ni.SetIcon(t.iconUnprotected)
		_ = t.ni.SetToolTip("CXProxy —— 保护未启动（服务未运行）")
		_ = t.actState.SetText("状态：保护未启动（服务未运行）")
		_ = t.actExitInfo.SetText("出口：未知")
		_ = t.actStartSvc.SetVisible(true)
		_ = t.actConnect.SetEnabled(false)
		_ = t.actDiscon.SetEnabled(false)
		_ = t.actCheckIP.SetEnabled(false)
		_ = t.actSettings.SetEnabled(false)
		_ = t.actQuit.SetEnabled(false)
		_ = t.actNodeMenu.SetEnabled(false)
		return
	}

	_ = t.actStartSvc.SetVisible(false)
	_ = t.actSettings.SetEnabled(true)
	_ = t.actQuit.SetEnabled(true)
	_ = t.actNodeMenu.SetEnabled(len(st.Nodes) > 0)
	_ = t.actConnect.SetEnabled(st.State != ipc.StateConnected && st.State != ipc.StateConnecting)
	_ = t.actDiscon.SetEnabled(st.State == ipc.StateConnected)
	_ = t.actCheckIP.SetEnabled(st.State == ipc.StateConnected)

	switch st.State {
	case ipc.StateConnected:
		_ = t.ni.SetIcon(t.iconConnected)
	case ipc.StateConnecting, ipc.StateStopping:
		_ = t.ni.SetIcon(t.iconConnecting)
	default:
		_ = t.ni.SetIcon(t.iconBlocked)
	}

	stateText := st.State.Label()
	if st.NodeLabel != "" {
		stateText += " · " + st.NodeLabel
	}
	_ = t.actState.SetText("状态：" + stateText)

	exitText := st.Exit.Label()
	_ = t.actExitInfo.SetText("出口：" + exitText)

	tip := "CXProxy · " + st.State.Label()
	if st.State == ipc.StateConnected {
		tip += "\n" + exitText
	} else if st.Message != "" {
		tip += "\n" + truncate(st.Message, 80)
	}
	if !st.KillSwitch {
		tip += "\n⚠ 断网保护规则不在位"
	}
	// 托盘提示在部分 Windows 版本上最多 127 个字符。
	_ = t.ni.SetToolTip(truncate(tip, 120))

	t.rebuildNodeMenu(st)
}

// rebuildNodeMenu 仅在节点列表变化时重建子菜单，避免每 2 秒闪一次。
func (t *tray) rebuildNodeMenu(st *ipc.Status) {
	var sb strings.Builder
	for _, n := range st.Nodes {
		fmt.Fprintf(&sb, "%d|%s|%d;", n.Index, n.Label, n.LatencyMS)
	}
	fmt.Fprintf(&sb, "active=%d", st.NodeIndex)
	sig := sb.String()
	if sig == t.nodeSig {
		// 列表没变，只同步选中标记。
		for i, a := range t.nodeActions {
			_ = a.SetChecked(i == st.NodeIndex)
		}
		return
	}
	t.nodeSig = sig

	for t.nodeMenu.Actions().Len() > 0 {
		_ = t.nodeMenu.Actions().RemoveAt(0)
	}
	t.nodeActions = nil

	if len(st.Nodes) == 0 {
		a := walk.NewAction()
		_ = a.SetText("（未配置节点，请在设置中添加）")
		_ = a.SetEnabled(false)
		_ = t.nodeMenu.Actions().Add(a)
		return
	}

	for _, n := range st.Nodes {
		idx := n.Index
		text := n.Label
		if n.LatencyMS >= 0 {
			text += fmt.Sprintf("  (%d ms)", n.LatencyMS)
		}
		if n.Region != "" {
			text += "  [" + n.Region + "]"
		}
		a := walk.NewAction()
		_ = a.SetText(text)
		_ = a.SetCheckable(true)
		_ = a.SetChecked(idx == st.NodeIndex)
		a.Triggered().Attach(func() { t.selectNode(idx) })
		_ = t.nodeMenu.Actions().Add(a)
		t.nodeActions = append(t.nodeActions, a)
	}
}

// withBusy 串行化耗时操作，避免用户连点把服务打爆。
func (t *tray) withBusy(what string, fn func() error) {
	t.mu.Lock()
	if t.busy {
		t.mu.Unlock()
		return
	}
	t.busy = true
	t.mu.Unlock()

	_ = t.actState.SetText("状态：" + what)

	go func() {
		err := fn()
		// 状态刷新同样是一次阻塞的管道往返，必须留在后台线程里做，
		// 否则界面会被卡住几秒。
		st, serr := t.cli.status()

		t.mw.Synchronize(func() {
			t.mu.Lock()
			t.busy = false
			t.mu.Unlock()
			if err != nil {
				t.logf("%s失败: %v", what, err)
				showError(t.mw, what+"失败", err)
			}
			t.apply(st, serr)
		})
	}()
}

func (t *tray) connect() {
	t.withBusy("正在连接…", func() error {
		_, err := t.cli.callWithTimeout(ipc.Request{Op: ipc.OpConnect}, 60*time.Second)
		return err
	})
}

func (t *tray) disconnect() {
	if !confirm(t.mw, "断开代理",
		"断开后整机将立即无法上网（断网保护仍然生效）。\n确定断开吗？") {
		return
	}
	t.withBusy("正在断开…", func() error {
		_, err := t.cli.callWithTimeout(ipc.Request{Op: ipc.OpDisconnect}, 30*time.Second)
		return err
	})
}

func (t *tray) selectNode(index int) {
	t.withBusy("正在切换节点…", func() error {
		_, err := t.cli.callWithTimeout(ipc.Request{Op: ipc.OpSelectNode, Index: index}, 60*time.Second)
		return err
	})
}

func (t *tray) checkExitIP() {
	t.withBusy("正在检测出口 IP…", func() error {
		resp, err := t.cli.callWithTimeout(ipc.Request{Op: ipc.OpCheckExitIP}, 40*time.Second)
		if err != nil {
			return err
		}
		info := resp.Exit
		t.mw.Synchronize(func() {
			msg := "出口 IP：" + info.Label()
			if info.ISP != "" {
				msg += "\nISP：" + info.ISP
			}
			if info.InRegion("Texas") {
				msg += "\n\n✓ 出口位于 Texas，符合要求。"
			} else {
				msg += "\n\n⚠ 出口不在 Texas，请检查所用节点。"
			}
			showInfo(t.mw, "出口检测结果", msg)
		})
		return nil
	})
}

func (t *tray) openSettings(forcePassword bool) {
	t.mu.Lock()
	st := t.status
	t.mu.Unlock()
	if st == nil {
		showWarn(t.mw, "服务未运行", "无法连接 CXProxy 服务，请先点「启动保护」。")
		return
	}
	showSettings(t.mw, t.cli, st, forcePassword)
}

func (t *tray) openLogs() {
	dir := config.LogDir()
	t.mu.Lock()
	if t.status != nil && t.status.LogDir != "" {
		dir = t.status.LogDir
	}
	t.mu.Unlock()
	// 用资源管理器打开日志目录，方便员工把日志发给 IT。
	cmd := exec.Command("explorer.exe", dir)
	_ = cmd.Start()
}

func (t *tray) startService() {
	t.withBusy("正在启动保护…", func() error {
		return service.StartService()
	})
}

// quit 是恢复直连的唯一入口：必须输入管理员密码。
func (t *tray) quit() {
	t.mu.Lock()
	st := t.status
	t.mu.Unlock()

	if st != nil && !st.HasPassword {
		showWarn(t.mw, "无法退出保护",
			"尚未设置管理员密码，无法退出断网保护。\n请先在「设置」中设置管理员密码。")
		return
	}
	if !confirm(t.mw, "退出断网保护",
		"退出后将拆除断网保护规则，整机恢复直连 —— 此时流量会使用本机真实 IP。\n\n"+
			"下次开机 CXProxy 会再次自动接管流量。\n\n确定退出吗？") {
		return
	}
	pw, ok := askPassword(t.mw, "退出断网保护", "请输入管理员密码：")
	if !ok {
		return
	}

	if _, err := t.cli.callWithTimeout(ipc.Request{Op: ipc.OpExit, Password: pw}, 60*time.Second); err != nil {
		showError(t.mw, "退出失败", err)
		return
	}
	showInfo(t.mw, "已退出保护", "断网保护已拆除，网络已恢复直连。")
	walk.App().Exit(0)
}
