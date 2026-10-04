package ipc

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/vlqri7qwml/cx/internal/checker"
	"github.com/vlqri7qwml/cx/internal/config"
)

func TestCodecRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	server := NewCodec(a)
	client := NewCodec(b)

	go func() {
		req, err := server.ReadRequest()
		if err != nil {
			t.Error(err)
			return
		}
		if req.Op != OpSelectNode || req.Index != 2 || req.Password != "pw" {
			t.Errorf("服务端收到的请求不对: %+v", req)
		}
		_ = server.WriteResponse(Response{
			OK: true,
			Status: &Status{
				State:      StateConnected,
				NodeIndex:  2,
				NodeLabel:  "休斯顿-2",
				KillSwitch: true,
				Exit:       &checker.ExitInfo{IP: "203.0.113.5", Region: "Texas", City: "Houston"},
				Since:      time.Date(2026, 10, 4, 8, 0, 0, 0, time.UTC),
			},
		})
	}()

	if err := client.WriteRequest(Request{Op: OpSelectNode, Index: 2, Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	resp, err := client.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Err(); err != nil {
		t.Fatalf("应答应为成功: %v", err)
	}
	if resp.Status.State != StateConnected || resp.Status.NodeLabel != "休斯顿-2" {
		t.Errorf("状态解析不对: %+v", resp.Status)
	}
	if !resp.Status.KillSwitch {
		t.Error("KillSwitch 应为 true")
	}
	if resp.Status.Exit.Label() != "203.0.113.5 · Texas, Houston" {
		t.Errorf("出口信息不对: %q", resp.Status.Exit.Label())
	}
}

// 托盘会在同一条连接上长期轮询，累计字节数远超单条消息上限，
// 这个用例守住“上限是每条消息”的语义。
func TestCodecHandlesManyMessagesOnOneConnection(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	go ServeConn(a, HandlerFunc(func(req Request) Response {
		return Response{OK: true, Status: &Status{State: StateConnected, Message: strings.Repeat("状态", 200)}}
	}))

	client := NewCodec(b)
	for i := 0; i < 500; i++ {
		if err := client.WriteRequest(Request{Op: OpStatus}); err != nil {
			t.Fatalf("第 %d 次请求失败: %v", i, err)
		}
		resp, err := client.ReadResponse()
		if err != nil {
			t.Fatalf("第 %d 次应答失败: %v", i, err)
		}
		if !resp.OK {
			t.Fatalf("第 %d 次应答非成功: %+v", i, resp)
		}
	}
}

func TestServeConnStopsOnClose(t *testing.T) {
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() {
		ServeConn(a, HandlerFunc(func(Request) Response { return Response{OK: true} }))
		close(done)
	}()
	b.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("对端关闭后 ServeConn 未退出")
	}
}

func TestReadRequestRejectsGarbage(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() {
		b.Write([]byte("这不是 JSON\n"))
		b.Close()
	}()
	if _, err := NewCodec(a).ReadRequest(); err == nil {
		t.Fatal("畸形输入应报错")
	}
}

func TestReadRequestSkipsBlankLines(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() {
		b.Write([]byte("\n\n   \n{\"op\":\"status\"}\n"))
	}()
	req, err := NewCodec(a).ReadRequest()
	if err != nil {
		t.Fatal(err)
	}
	if req.Op != OpStatus {
		t.Errorf("op = %q", req.Op)
	}
}

func TestReadResponseEOF(t *testing.T) {
	a, b := net.Pipe()
	b.Close()
	if _, err := NewCodec(a).ReadResponse(); !errors.Is(err, io.EOF) && err == nil {
		t.Fatalf("关闭后应返回错误，实际 %v", err)
	}
}

func TestResponseErrHelpers(t *testing.T) {
	var nilResp *Response
	if nilResp.Err() == nil {
		t.Error("nil 应答应报错")
	}
	if (&Response{OK: true}).Err() != nil {
		t.Error("成功应答不应报错")
	}
	if got := (&Response{}).Err(); got == nil || got.Error() != "服务返回未知错误" {
		t.Errorf("空错误串应有兜底文案，实际 %v", got)
	}
	if got := Fail(nil); got.OK || got.Error != "未知错误" {
		t.Errorf("Fail(nil) = %+v", got)
	}
	if got := Failf("密码错误 %d 次", 3); got.Error != "密码错误 3 次" {
		t.Errorf("Failf = %+v", got)
	}
}

func TestStateLabels(t *testing.T) {
	for state, want := range map[State]string{
		StateDisconnected: "已断开（整机无网）",
		StateConnecting:   "正在连接…",
		StateConnected:    "已连接",
		StateError:        "连接失败（整机无网）",
		StateStopping:     "正在退出保护…",
	} {
		if got := state.Label(); got != want {
			t.Errorf("%s.Label() = %q, want %q", state, got, want)
		}
	}
	if got := State("odd").Label(); got != "odd" {
		t.Errorf("未知状态应原样返回，实际 %q", got)
	}
}

func TestConfigTravelsWithMaskedPasswords(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	cfg := config.Default()
	cfg.Nodes = []config.Node{{Host: "1.2.3.4", Port: 1080, Username: "u", Password: "真密码"}}
	cfg.Active = 0

	go func() {
		s := NewCodec(a)
		if _, err := s.ReadRequest(); err != nil {
			return
		}
		_ = s.WriteResponse(Response{OK: true, Config: cfg.Sanitized()})
	}()

	client := NewCodec(b)
	if err := client.WriteRequest(Request{Op: OpGetConfig}); err != nil {
		t.Fatal(err)
	}
	resp, err := client.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if resp.Config.Nodes[0].Password != config.MaskedPassword {
		t.Errorf("经 IPC 传出的配置必须掩码密码，实际 %q", resp.Config.Nodes[0].Password)
	}
	if resp.Config.PasswordHash != "" {
		t.Error("管理员密码哈希不应经 IPC 下发")
	}
}
