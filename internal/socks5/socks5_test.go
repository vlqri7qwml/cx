package socks5

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestDialNoAuth(t *testing.T) {
	srv := newTestServer(t, "", "")
	target := echoTCP(t)

	c := &Client{Addr: srv.addr()}
	conn, err := c.DialContext(context.Background(), target)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	want := []byte("hello texas")
	if _, err := conn.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("回显不一致: got %q want %q", got, want)
	}
}

func TestDialUserPass(t *testing.T) {
	srv := newTestServer(t, "u1", "p@ss:word")
	target := echoTCP(t)

	c := &Client{Addr: srv.addr(), Username: "u1", Password: "p@ss:word"}
	conn, err := c.DialContext(context.Background(), target)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(conn, b); err != nil {
		t.Fatal(err)
	}
}

func TestDialWrongPassword(t *testing.T) {
	srv := newTestServer(t, "u1", "right")
	c := &Client{Addr: srv.addr(), Username: "u1", Password: "wrong"}
	_, err := c.DialContext(context.Background(), echoTCP(t))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("期望 ErrAuthFailed，实际 %v", err)
	}
}

func TestDialNoAcceptableAuth(t *testing.T) {
	// 服务端要求用户名密码，客户端没有配置。
	srv := newTestServer(t, "u1", "p1")
	c := &Client{Addr: srv.addr()}
	_, err := c.DialContext(context.Background(), echoTCP(t))
	if !errors.Is(err, ErrNoAcceptableAuth) {
		t.Fatalf("期望 ErrNoAcceptableAuth，实际 %v", err)
	}
}

func TestDialReplyError(t *testing.T) {
	srv := newTestServer(t, "", "")
	srv.replyErr = 0x02
	c := &Client{Addr: srv.addr()}
	_, err := c.DialContext(context.Background(), "1.2.3.4:80")
	if err == nil {
		t.Fatal("期望失败")
	}
	var re replyError
	if !errors.As(err, &re) || byte(re) != 0x02 {
		t.Fatalf("期望 replyError(0x02)，实际 %v", err)
	}
}

func TestDialDomainTarget(t *testing.T) {
	srv := newTestServer(t, "", "")
	// 目标用域名，交由代理解析；localhost 在测试环境可解析。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Write([]byte("ok"))
		c.Close()
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	c := &Client{Addr: srv.addr()}
	conn, err := c.DialContext(context.Background(), "localhost:"+port)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	b := make([]byte, 2)
	if _, err := io.ReadFull(conn, b); err != nil {
		t.Fatal(err)
	}
	if string(b) != "ok" {
		t.Errorf("got %q", b)
	}
}

func TestDialUsesCustomDialer(t *testing.T) {
	srv := newTestServer(t, "", "")
	called := false
	c := &Client{
		Addr: srv.addr(),
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			called = true
			if addr != srv.addr() {
				t.Errorf("Dialer 收到的地址不对: %s", addr)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	conn, err := c.DialContext(context.Background(), echoTCP(t))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if !called {
		t.Error("自定义 Dialer 未被使用")
	}
}

func TestDialContextCancelled(t *testing.T) {
	// 连一个不会应答握手的监听端口，确认 ctx 取消能及时返回。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			time.Sleep(5 * time.Second)
			c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	c := &Client{Addr: ln.Addr().String(), Timeout: 30 * time.Second}
	start := time.Now()
	if _, err := c.DialContext(ctx, "1.2.3.4:80"); err == nil {
		t.Fatal("期望超时失败")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("ctx 取消未及时生效，耗时 %v", d)
	}
}

func TestProbe(t *testing.T) {
	srv := newTestServer(t, "u", "p")
	c := &Client{Addr: srv.addr(), Username: "u", Password: "p"}
	if _, err := c.Probe(context.Background()); err != nil {
		t.Fatalf("Probe: %v", err)
	}

	bad := &Client{Addr: srv.addr(), Username: "u", Password: "zzz"}
	if _, err := bad.Probe(context.Background()); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("期望认证失败，实际 %v", err)
	}
}

func TestUDPAssociateEcho(t *testing.T) {
	srv := newTestServer(t, "u", "p")
	echo := echoUDP(t)

	c := &Client{Addr: srv.addr(), Username: "u", Password: "p"}
	u, err := c.UDPAssociate(context.Background())
	if err != nil {
		t.Fatalf("UDPAssociate: %v", err)
	}
	defer u.Close()

	payload := []byte("udp-ping")
	if _, err := u.WriteTo(payload, echo); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	u.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, src, err := u.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("回显不一致: %q", buf[:n])
	}
	if src != echo {
		t.Errorf("来源地址不对: got %s want %s", src, echo)
	}
}

func TestUDPAssociateBndZeroFallsBackToProxyIP(t *testing.T) {
	srv := newTestServer(t, "", "")
	srv.bndZero = true
	echo := echoUDP(t)

	c := &Client{Addr: srv.addr()}
	u, err := c.UDPAssociate(context.Background())
	if err != nil {
		t.Fatalf("UDPAssociate: %v", err)
	}
	defer u.Close()
	if !u.relayAddr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("BND.ADDR 为 0.0.0.0 时应回退为代理 IP，实际 %v", u.relayAddr)
	}
	if _, err := u.WriteTo([]byte("x"), echo); err != nil {
		t.Fatal(err)
	}
	u.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	if _, _, err := u.ReadFrom(buf); err != nil {
		t.Fatalf("回退地址后仍应能收到回包: %v", err)
	}
}

func TestUDPAssociateUnsupported(t *testing.T) {
	srv := newTestServer(t, "", "")
	srv.noUDP = true
	c := &Client{Addr: srv.addr()}
	if _, err := c.UDPAssociate(context.Background()); err == nil {
		t.Fatal("代理不支持 UDP 时应返回错误")
	}
}

func TestUDPClosesWhenControlConnDies(t *testing.T) {
	srv := newTestServer(t, "", "")
	c := &Client{Addr: srv.addr()}
	u, err := c.UDPAssociate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// 关闭服务端监听并直接断开控制连接：会话应自行结束。
	u.ctrl.Close()
	select {
	case <-u.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("控制连接断开后 UDP 会话未关闭")
	}
}

func TestAppendAddrForms(t *testing.T) {
	b, err := appendAddr(nil, "1.2.3.4", 1080)
	if err != nil || b[0] != atypIPv4 || mustUint16(b[5:7]) != 1080 {
		t.Errorf("IPv4 编码错误: %v %v", b, err)
	}
	b, err = appendAddr(nil, "2001:db8::1", 443)
	if err != nil || b[0] != atypIPv6 || mustUint16(b[17:19]) != 443 {
		t.Errorf("IPv6 编码错误: %v %v", b, err)
	}
	b, err = appendAddr(nil, "example.com", 80)
	if err != nil || b[0] != atypDomain || int(b[1]) != len("example.com") {
		t.Errorf("域名编码错误: %v %v", b, err)
	}
	if _, err := appendAddr(nil, "", 80); err == nil {
		t.Error("空域名应报错")
	}
	if _, err := appendAddr(nil, "a", 70000); err == nil {
		t.Error("端口越界应报错")
	}
}

func TestParseUDPHeaderMalformed(t *testing.T) {
	for _, b := range [][]byte{
		{},
		{atypIPv4, 1, 2},
		{atypIPv6, 1},
		{atypDomain},
		{atypDomain, 5, 'a'},
		{0x09, 1, 2, 3},
	} {
		if _, _, _, err := parseUDPHeader(b); err == nil {
			t.Errorf("畸形输入 %v 应报错", b)
		}
	}
}

func TestUDPReadFromReusesBuffer(t *testing.T) {
	srv := newTestServer(t, "", "")
	echo := echoUDP(t)

	c := &Client{Addr: srv.addr()}
	u, err := c.UDPAssociate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	// 连续多个数据报都要正确收发，确认复用缓冲没有串包。
	for i := 0; i < 20; i++ {
		payload := []byte{byte(i), byte(i + 1), byte(i + 2)}
		if _, err := u.WriteTo(payload, echo); err != nil {
			t.Fatalf("第 %d 次发送失败: %v", i, err)
		}
		u.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 16)
		n, src, err := u.ReadFrom(buf)
		if err != nil {
			t.Fatalf("第 %d 次读取失败: %v", i, err)
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Fatalf("第 %d 次回显不一致: got %v want %v", i, buf[:n], payload)
		}
		if src != echo {
			t.Fatalf("第 %d 次来源地址不对: %s", i, src)
		}
	}
}

func TestUDPReadFromTruncatesToCallerBuffer(t *testing.T) {
	srv := newTestServer(t, "", "")
	echo := echoUDP(t)

	c := &Client{Addr: srv.addr()}
	u, err := c.UDPAssociate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	if _, err := u.WriteTo([]byte("0123456789"), echo); err != nil {
		t.Fatal(err)
	}
	u.SetReadDeadline(time.Now().Add(3 * time.Second))
	small := make([]byte, 4)
	n, _, err := u.ReadFrom(small)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 || string(small[:n]) != "0123" {
		t.Fatalf("截断行为不对: n=%d buf=%q", n, small[:n])
	}
}
