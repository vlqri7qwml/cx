package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/vlqri7qwml/cx/internal/config"
	"github.com/vlqri7qwml/cx/internal/firewall"
	"github.com/vlqri7qwml/cx/internal/ipc"
	"github.com/vlqri7qwml/cx/internal/logx"
	"github.com/vlqri7qwml/cx/internal/service"
	"github.com/vlqri7qwml/cx/internal/ui"
)

func run() {
	// 由 SCM 启动时不会带参数，直接进入服务模式。
	if service.IsWindowsService() {
		runAsService()
		return
	}

	args := os.Args[1:]
	cmd := ""
	if len(args) > 0 {
		cmd = strings.ToLower(strings.TrimLeft(args[0], "-/"))
		args = args[1:]
	}

	// 托盘是 GUI，不需要控制台；其余子命令都要能在命令行里看到输出。
	// 这里不能用 defer：下面的失败分支会走 os.Exit，defer 不会执行，
	// 自开控制台时窗口就会一闪而过。
	closeConsole := func() {}
	if cmd != "" && cmd != "tray" {
		closeConsole = attachConsole()
	}

	var err error
	switch cmd {
	case "", "tray":
		err = runTray(args)
	case "install":
		err = runInstall(args)
	case "uninstall":
		err = runUninstall()
	case "run":
		err = runForeground()
	case "unblock":
		err = runUnblock()
	case "status":
		err = runStatus()
	case "version", "v":
		fmt.Printf("CXProxy %s\n", service.Version)
	case "help", "h", "?":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "未知命令 %q\n\n", cmd)
		usage()
		closeConsole()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "错误：%v\n", err)
		closeConsole()
		os.Exit(1)
	}
	closeConsole()
}

func usage() {
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintf(w, "CXProxy %s —— TUN 全局代理与断网保护\n\n", service.Version)
	fmt.Fprint(w, "用法：cxproxy.exe <命令>\n\n")
	for _, l := range [][2]string{
		{"(无参数) / --tray", "启动右下角托盘"},
		{"install", "安装服务（开机自启）并登记托盘自启动  [需管理员]"},
		{"uninstall", "卸载服务并拆除断网保护，恢复直连      [需管理员]"},
		{"run", "前台运行，便于排障                    [需管理员]"},
		{"unblock", "应急：只拆除断网保护规则，恢复直连    [需管理员]"},
		{"status", "打印当前状态"},
		{"version", "打印版本号"},
	} {
		fmt.Fprintf(w, "  %s\t%s\n", l[0], l[1])
	}
	w.Flush()
}

// runAsService 以 Windows 服务身份运行。
func runAsService() {
	logger, lerr := logx.New(logx.Options{Path: config.ServiceLogPath()})
	defer logger.Close()
	if lerr != nil {
		// 日志写不了也要继续跑：断网保护比日志重要。
		logger.Printf("警告：无法写入日志文件: %v", lerr)
	}
	if err := service.RunService(config.Path(), logger); err != nil {
		logger.Printf("服务退出，错误: %v", err)
		os.Exit(1)
	}
}

func runTray(args []string) error {
	fs := flag.NewFlagSet("tray", flag.ContinueOnError)
	openSettings := fs.Bool("settings", false, "启动后立刻打开设置窗口")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger, _ := logx.New(logx.Options{Path: config.UserLogPath(), MaxSize: 1 << 20, Keep: 1})
	defer logger.Close()

	return ui.Run(logger.Printf, *openSettings)
}

func runInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	exe := fs.String("exe", "", "服务可执行文件路径（默认取当前程序）")
	noTray := fs.Bool("no-tray", false, "不启动托盘（静默部署时使用）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireAdmin(); err != nil {
		return err
	}

	if err := service.Install(*exe); err != nil {
		return err
	}
	fmt.Println("CXProxy 服务已安装并启动，开机将自动接管整机流量。")
	fmt.Printf("配置文件：%s\n日志目录：%s\n", config.Path(), config.LogDir())

	cfg, _, err := config.Load(config.Path())
	if err == nil && !cfg.HasPassword() {
		fmt.Println()
		fmt.Println("请注意：尚未设置管理员密码。在设置密码之前无法退出断网保护。")
		fmt.Println("请在托盘中打开「设置」完成初始化（设置密码 + 粘贴 SOCKS5 代理）。")
	}

	if !*noTray {
		if err := launchTray(); err != nil {
			fmt.Fprintf(os.Stderr, "提示：托盘启动失败（下次登录会自动启动）：%v\n", err)
		}
	}
	return nil
}

// launchTray 启动托盘。
//
// 这里是「管理员在命令行手动执行 install」的路径，托盘会继承当前这个
// 管理员会话，符合预期。安装程序走的是另一条路：Inno Setup 的
// runasoriginaluser 标志会以真正的登录用户身份拉起托盘，
// 避免托盘长期带着管理员令牌运行。
func launchTray() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return startDetached(exe, "--tray", "--settings")
}

func runUninstall() error {
	if err := requireAdmin(); err != nil {
		return err
	}

	// 顺序很关键：先拆断网保护再删服务。
	// 反了的话一旦删服务后拆规则失败，机器就会留在“永久无网且没有程序可管”的状态。
	if err := firewall.Disable(); err != nil {
		return fmt.Errorf("拆除断网保护失败（网络可能仍被阻断）: %w", err)
	}
	fmt.Println("断网保护规则已拆除，网络恢复直连。")

	if err := service.Uninstall(); err != nil {
		return err
	}
	fmt.Println("CXProxy 服务已卸载，托盘自启动已移除。")
	fmt.Printf("配置与日志仍保留在 %s，如需彻底清理请手动删除。\n", config.Dir())
	return nil
}

func runForeground() error {
	if err := requireAdmin(); err != nil {
		return err
	}
	logger, _ := logx.New(logx.Options{Path: config.ServiceLogPath(), Extra: os.Stdout})
	defer logger.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Println("按 Ctrl+C 停止。注意：停止后断网保护规则仍然保留（整机无网）。")
	fmt.Println("要恢复直连，请执行 cxproxy.exe unblock。")
	return service.RunForeground(ctx, config.Path(), logger)
}

func runUnblock() error {
	if err := requireAdmin(); err != nil {
		return err
	}
	installed, err := firewall.Installed()
	if err != nil {
		fmt.Fprintf(os.Stderr, "提示：查询断网保护状态失败：%v\n", err)
	}
	if !installed {
		fmt.Println("当前没有检测到 CXProxy 的断网保护规则，无需处理。")
	}
	if err := firewall.Disable(); err != nil {
		return err
	}
	fmt.Println("已移除 CXProxy 的全部断网保护规则，网络恢复直连。")
	fmt.Println("注意：CXProxy 服务若仍在运行，可能会重新装上规则；")
	fmt.Println("如需彻底停用，请执行 cxproxy.exe uninstall。")
	return nil
}

func runStatus() error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	resp, err := ipc.Call(ctx, ipc.Request{Op: ipc.OpStatus}, 5*time.Second)
	if err != nil {
		if errors.Is(err, ipc.ErrServiceNotRunning) {
			fmt.Println("状态：服务未运行")
			if ok, ferr := firewall.Installed(); ferr == nil && ok {
				fmt.Println("断网保护：仍然生效（整机无网）")
			}
			return nil
		}
		return err
	}
	if err := resp.Err(); err != nil {
		return err
	}
	st := resp.Status

	w := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintf(w, "版本：\t%s\n", st.Version)
	fmt.Fprintf(w, "状态：\t%s", st.State.Label())
	if st.Message != "" {
		fmt.Fprintf(w, "（%s）", st.Message)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "断网保护：\t%s\n", yesNo(st.KillSwitch, "生效", "未生效"))
	fmt.Fprintf(w, "允许局域网：\t%s\n", yesNo(st.AllowLAN, "是", "否"))
	fmt.Fprintf(w, "阻止 QUIC：\t%s\n", yesNo(st.BlockQUIC, "是", "否"))
	fmt.Fprintf(w, "管理员密码：\t%s\n", yesNo(st.HasPassword, "已设置", "未设置"))
	if st.NodeLabel != "" {
		fmt.Fprintf(w, "当前节点：\t%s\n", st.NodeLabel)
	}
	if st.ProxyAddr != "" {
		fmt.Fprintf(w, "代理地址：\t%s\n", st.ProxyAddr)
	}
	fmt.Fprintf(w, "出口：\t%s\n", st.Exit.Label())
	fmt.Fprintf(w, "流量：\t上行 %s / 下行 %s\n",
		humanBytes(st.Stats.BytesUp), humanBytes(st.Stats.BytesDown))
	fmt.Fprintf(w, "连接数：\tTCP %d / UDP %d（累计 TCP %d、DNS %d、丢弃 %d）\n",
		st.Stats.TCPActive, st.Stats.UDPActive, st.Stats.TCPTotal, st.Stats.DNSTotal, st.Stats.Dropped)
	fmt.Fprintf(w, "日志目录：\t%s\n", st.LogDir)
	if len(st.Nodes) > 0 {
		fmt.Fprintln(w, "\n节点列表：")
		for _, n := range st.Nodes {
			mark := "  "
			if n.Index == st.NodeIndex {
				mark = "* "
			}
			lat := "—"
			if n.LatencyMS >= 0 {
				lat = fmt.Sprintf("%d ms", n.LatencyMS)
			}
			fmt.Fprintf(w, "%s%d\t%s\t%s\t%s\t%s\n", mark, n.Index, n.Label, n.Addr, lat, n.Region)
		}
	}
	return w.Flush()
}

func yesNo(v bool, yes, no string) string {
	if v {
		return yes
	}
	return no
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	v := float64(n)
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	for _, u := range units {
		v /= unit
		if v < unit {
			return fmt.Sprintf("%.1f %s", v, u)
		}
	}
	return fmt.Sprintf("%.1f PiB", v/unit)
}

// requireAdmin 确认当前进程以管理员权限运行。
func requireAdmin() error {
	if isElevated() {
		return nil
	}
	return errors.New("该命令需要管理员权限：请在“以管理员身份运行”的命令提示符中执行")
}

func isElevated() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

// startDetached 启动一个与当前进程无关的子进程。
func startDetached(name string, args ...string) error {
	exe, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	cmdline := windows.ComposeCommandLine(append([]string{name}, args...))
	cl, err := windows.UTF16PtrFromString(cmdline)
	if err != nil {
		return err
	}
	si := windows.StartupInfo{}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(exe, cl, nil, nil, false,
		windows.CREATE_NEW_PROCESS_GROUP|windows.DETACHED_PROCESS,
		nil, nil, &si, &pi); err != nil {
		return err
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return nil
}
