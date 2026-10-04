package ipc

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"

	"github.com/vlqri7qwml/cx/internal/config"
)

// pipeSDDL 控制谁能连上管道。
//
//	SY = LocalSystem        ：完全控制（服务自己）
//	BA = Administrators     ：完全控制（管理员排障）
//	IU = Interactive Users  ：读写（本机登录用户运行的托盘）
//
// 刻意不授予 Everyone / Network：远程进程连不上这个管道。
// 托盘即便连上了，改配置与退出保护也还要过管理员密码。
const pipeSDDL = "O:SYG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

// PipeName 返回管道名称。
func PipeName() string { return config.DefaultPipeName }

// Listen 在命名管道上监听。
func Listen() (net.Listener, error) {
	ln, err := winio.ListenPipe(PipeName(), &winio.PipeConfig{
		SecurityDescriptor: pipeSDDL,
		InputBufferSize:    64 << 10,
		OutputBufferSize:   64 << 10,
	})
	if err != nil {
		return nil, fmt.Errorf("监听管道 %s 失败: %w", PipeName(), err)
	}
	return ln, nil
}

// Serve 接受连接并逐条处理请求，直到 ctx 取消或监听器关闭。
func Serve(ctx context.Context, ln net.Listener, h Handler) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go ServeConn(conn, h)
	}
}

// ErrServiceNotRunning 表示连不上服务（通常是服务未启动）。
var ErrServiceNotRunning = fmt.Errorf("连接 CXProxy 服务失败：服务可能未运行")

// Dial 连接服务端管道。
func Dial(ctx context.Context, timeout time.Duration) (*Codec, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := winio.DialPipeContext(ctx, PipeName())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrServiceNotRunning, err)
	}
	return NewCodec(conn), nil
}

// Call 完成一次“连接 → 发请求 → 读应答 → 关闭”的往返。
func Call(ctx context.Context, req Request, timeout time.Duration) (Response, error) {
	c, err := Dial(ctx, timeout)
	if err != nil {
		return Response{}, err
	}
	defer c.Close()

	if err := c.WriteRequest(req); err != nil {
		return Response{}, fmt.Errorf("发送请求失败: %w", err)
	}
	resp, err := c.ReadResponse()
	if err != nil {
		return Response{}, fmt.Errorf("读取应答失败: %w", err)
	}
	return resp, nil
}
