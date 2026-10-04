package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// serviceSDDL 控制谁能对服务做什么。
//
//	SY = LocalSystem        ：常规服务权限
//	BA = Administrators     ：完全控制（含停止、删除、改配置）
//	IU = Interactive Users  ：查询状态 + 启动（RP），但**不含**停止（WP）
//	SU = Service            ：查询状态
//
// 刻意不给交互用户 WP（SERVICE_STOP）：让登录用户能在服务意外没起来时
// 自己点一下「启动保护」，但不能把保护停掉。
// 要退出保护只有一条路 —— 托盘里输入管理员密码。
const serviceSDDL = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)" +
	"(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" +
	"(A;;CCLCSWRPLOCRRC;;;IU)" +
	"(A;;CCLCSWLOCRRC;;;SU)"

// trayRunKey 是托盘自启动所用的注册表位置。
const (
	trayRunKey   = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	trayRunValue = "CXProxy"
)

// ErrNeedAdmin 表示当前进程没有管理员权限。
var ErrNeedAdmin = errors.New("该操作需要管理员权限，请以管理员身份运行")

// Install 注册并启动服务，同时登记托盘自启动。
//
// 可重复执行：已存在时更新配置而不是报错，便于升级覆盖安装。
func Install(exePath string) error {
	if exePath == "" {
		p, err := os.Executable()
		if err != nil {
			return err
		}
		exePath = p
	}
	exePath, err := filepath.Abs(exePath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(exePath); err != nil {
		return fmt.Errorf("找不到程序文件 %s: %w", exePath, err)
	}

	mm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNeedAdmin, err)
	}
	defer mm.Disconnect()

	cfg := mgr.Config{
		ServiceType:    windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:      mgr.StartAutomatic,
		ErrorControl:   mgr.ErrorNormal,
		DisplayName:    DisplayName,
		Description:    Description,
		BinaryPathName: exePath,
		// 让服务进程的令牌带上服务 SID：WFP 的放行规则要靠它把
		// “以服务身份运行的 cxproxy”与“以用户身份运行的托盘”区分开。
		SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED,
		// 不延迟启动：越早装上断网保护越好。
		DelayedAutoStart: false,
	}

	s, err := mm.OpenService(Name)
	if err == nil {
		defer s.Close()
		if err := s.UpdateConfig(cfg); err != nil {
			return fmt.Errorf("更新服务配置失败: %w", err)
		}
	} else {
		s, err = mm.CreateService(Name, exePath, cfg)
		if err != nil {
			return fmt.Errorf("创建服务失败: %w", err)
		}
		defer s.Close()
	}

	// 进程崩溃或异常退出（非零退出码）都要自动拉起，1 秒后重试。
	// 这样“用任务管理器结束进程”只能让它消失 1 秒。
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
	}, 86400); err != nil {
		return fmt.Errorf("设置服务恢复策略失败: %w", err)
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("设置非崩溃失败恢复策略失败: %w", err)
	}

	if err := applyServiceSDDL(Name); err != nil {
		return fmt.Errorf("设置服务访问权限失败: %w", err)
	}
	if err := registerTrayAutostart(exePath); err != nil {
		return fmt.Errorf("登记托盘自启动失败: %w", err)
	}

	if err := startService(s); err != nil {
		return err
	}
	return nil
}

// Uninstall 停止并删除服务，清掉托盘自启动，并拆除断网保护规则。
func Uninstall() error {
	mm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNeedAdmin, err)
	}
	defer mm.Disconnect()

	s, err := mm.OpenService(Name)
	if err == nil {
		defer s.Close()
		if st, qerr := s.Query(); qerr == nil && st.State != svc.Stopped {
			if _, cerr := s.Control(svc.Stop); cerr != nil {
				return fmt.Errorf("停止服务失败: %w", cerr)
			}
			_ = waitForState(s, svc.Stopped, 30*time.Second)
		}
		if derr := s.Delete(); derr != nil {
			return fmt.Errorf("删除服务失败: %w", derr)
		}
	}

	if err := unregisterTrayAutostart(); err != nil {
		return err
	}
	return nil
}

// Installed 返回服务是否已安装。
func Installed() (bool, error) {
	mm, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer mm.Disconnect()

	s, err := mm.OpenService(Name)
	if err != nil {
		return false, nil
	}
	s.Close()
	return true, nil
}

// Running 返回服务当前是否在运行。
func Running() (bool, error) {
	mm, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer mm.Disconnect()

	s, err := mm.OpenService(Name)
	if err != nil {
		return false, nil
	}
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return false, err
	}
	return st.State == svc.Running || st.State == svc.StartPending, nil
}

// StartService 启动服务。托盘发现服务没运行时会调用它 ——
// 服务 DACL 已授予交互用户启动权限，因此无需弹 UAC。
func StartService() error {
	mm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("连接服务控制管理器失败: %w", err)
	}
	defer mm.Disconnect()

	s, err := mm.OpenService(Name)
	if err != nil {
		return fmt.Errorf("找不到 %s 服务，请重新安装: %w", Name, err)
	}
	defer s.Close()
	return startService(s)
}

func startService(s *mgr.Service) error {
	st, err := s.Query()
	if err == nil && (st.State == svc.Running || st.State == svc.StartPending) {
		return nil
	}
	if err := s.Start(); err != nil {
		// ERROR_SERVICE_ALREADY_RUNNING 视为成功。
		if errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return nil
		}
		return fmt.Errorf("启动服务失败: %w", err)
	}
	return waitForState(s, svc.Running, 30*time.Second)
}

func waitForState(s *mgr.Service, want svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == want {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("等待服务进入 %v 状态超时", want)
}

// applyServiceSDDL 收紧/放开服务对象的访问控制。
func applyServiceSDDL(name string) error {
	sd, err := windows.SecurityDescriptorFromString(serviceSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		name,
		windows.SE_SERVICE,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
}

// registerTrayAutostart 写入 HKLM Run，使任何用户登录后都自动拉起托盘。
//
// 写 HKLM 而不是 HKCU：这是公司统一部署的策略，换个账号登录同样要有托盘，
// 否则用户看不到当前状态，也没有合法途径退出保护。
func registerTrayAutostart(exePath string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, trayRunKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	// 注意不能用 %q：Go 的 %q 会把 Windows 路径里的反斜杠转义成 \\，
	// 写进注册表后这条命令根本启动不了。
	return k.SetStringValue(trayRunValue, `"`+exePath+`" --tray`)
}

func unregisterTrayAutostart() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, trayRunKey, registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	defer k.Close()
	if err := k.DeleteValue(trayRunValue); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}
