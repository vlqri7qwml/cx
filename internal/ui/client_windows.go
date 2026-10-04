package ui

import (
	"context"
	"time"

	"github.com/vlqri7qwml/cx/internal/ipc"
)

// client 是对命名管道的薄封装：托盘的每个动作都是一次往返请求。
type client struct {
	timeout time.Duration
}

func newClient() *client { return &client{timeout: 10 * time.Second} }

func (c *client) call(req ipc.Request) (ipc.Response, error) {
	return c.callWithTimeout(req, c.timeout)
}

// callWithTimeout 用于耗时较长的操作（连接、测速、出口探测）。
func (c *client) callWithTimeout(req ipc.Request, timeout time.Duration) (ipc.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
	defer cancel()

	resp, err := ipc.Call(ctx, req, timeout)
	if err != nil {
		return resp, err
	}
	return resp, resp.Err()
}

// status 查询服务状态。
func (c *client) status() (*ipc.Status, error) {
	resp, err := c.callWithTimeout(ipc.Request{Op: ipc.OpStatus}, 5*time.Second)
	if err != nil {
		return nil, err
	}
	return resp.Status, nil
}
