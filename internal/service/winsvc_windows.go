package service

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows/svc"

	"github.com/vlqri7qwml/cx/internal/logx"
)

// winService 把 Manager 接到 Windows 服务控制管理器上。
type winService struct {
	m      *Manager
	logger *logx.Logger
}

// Execute 由 svc.Run 调用，负责响应 SCM 的控制请求。
func (ws *winService) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	s <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErr := make(chan error, 1)
	go func() { runErr <- ws.m.Run(ctx) }()

	s <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				ws.logger.Printf("收到 SCM %v 请求", c.Cmd)
				s <- svc.Status{State: svc.StopPending}
				cancel()
				<-runErr
				return false, 0
			default:
				ws.logger.Printf("忽略不支持的服务控制命令 %v", c.Cmd)
			}

		case err := <-runErr:
			if err != nil {
				ws.logger.Printf("服务异常退出: %v", err)
				s <- svc.Status{State: svc.StopPending}
				// 返回非零退出码，让 SCM 按恢复策略在 1 秒后重启服务。
				// 装不上断网保护等致命错误就靠这条路径不断重试。
				return false, 1
			}
			s <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
}

// RunService 以 Windows 服务方式运行。
func RunService(cfgPath string, logger *logx.Logger) error {
	m, err := NewManager(cfgPath, logger)
	if err != nil {
		return err
	}
	logger.Printf("CXProxy 服务 %s 启动", Version)
	if err := svc.Run(Name, &winService{m: m, logger: logger}); err != nil {
		return fmt.Errorf("服务运行失败: %w", err)
	}
	logger.Printf("CXProxy 服务已停止")
	return nil
}

// RunForeground 以前台方式运行（便于排障：管理员命令行执行 cxproxy.exe run）。
func RunForeground(ctx context.Context, cfgPath string, logger *logx.Logger) error {
	m, err := NewManager(cfgPath, logger)
	if err != nil {
		return err
	}
	logger.Printf("CXProxy %s 以前台模式运行（Ctrl+C 停止，断网保护规则会保留）", Version)
	return m.Run(ctx)
}

// IsWindowsService 判断当前进程是否由 SCM 启动。
func IsWindowsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}
