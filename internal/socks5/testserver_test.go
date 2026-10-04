package socks5

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// testServer 是一个仅供测试使用的最小 SOCKS5 服务端，
// 支持无认证 / 用户名密码认证、CONNECT 与 UDP ASSOCIATE。
type testServer struct {
	ln       net.Listener
	user     string
	pass     string
	denyAuth bool // 认证时一律返回失败
	replyErr byte // 非 0 时对 CONNECT 返回该错误码
	noUDP    bool // 对 UDP ASSOCIATE 返回“命令不支持”
	bndZero  bool // UDP ASSOCIATE 应答里 BND.ADDR 填 0.0.0.0
	wg       sync.WaitGroup
}

func newTestServer(t *testing.T, user, pass string) *testServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testServer{ln: ln, user: user, pass: pass}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(func() {
		ln.Close()
		// 关掉监听器只能让 Accept 返回；某条用例若忘了关自己的连接，
		// 对应的 handle 协程会一直阻塞在 Read 上。这里设上限，
		// 让它变成一条明确的失败信息，而不是把 CI 挂到 10 分钟超时。
		done := make(chan struct{})
		go func() {
			s.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("SOCKS5 测试服务未能在 10 秒内收尾：某条连接没有被关闭")
		}
	})
	return s
}

func (s *testServer) addr() string { return s.ln.Addr().String() }

func (s *testServer) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer c.Close()
			s.handle(c)
		}()
	}
}

func (s *testServer) handle(c net.Conn) {
	// 握手
	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}

	want := byte(authNone)
	if s.user != "" {
		want = authUserPass
	}
	found := false
	for _, m := range methods {
		if m == want {
			found = true
			break
		}
	}
	if !found {
		c.Write([]byte{version5, authNoneOK})
		return
	}
	c.Write([]byte{version5, want})

	if want == authUserPass {
		var h [2]byte
		if _, err := io.ReadFull(c, h[:]); err != nil {
			return
		}
		u := make([]byte, h[1])
		if _, err := io.ReadFull(c, u); err != nil {
			return
		}
		var pl [1]byte
		if _, err := io.ReadFull(c, pl[:]); err != nil {
			return
		}
		p := make([]byte, pl[0])
		if _, err := io.ReadFull(c, p); err != nil {
			return
		}
		if s.denyAuth || string(u) != s.user || string(p) != s.pass {
			c.Write([]byte{authVersion, 0x01})
			return
		}
		c.Write([]byte{authVersion, 0x00})
	}

	// 请求
	reqHead := make([]byte, 4)
	if _, err := io.ReadFull(c, reqHead); err != nil {
		return
	}
	host, port, err := readAddrBody(c, reqHead[3])
	if err != nil {
		return
	}

	switch reqHead[1] {
	case cmdConnect:
		s.handleConnect(c, host, port)
	case cmdUDPAssociate:
		s.handleUDP(c)
	default:
		writeReply(c, 0x07, "0.0.0.0", 0)
	}
}

func (s *testServer) handleConnect(c net.Conn, host string, port int) {
	if s.replyErr != 0 {
		writeReply(c, s.replyErr, "0.0.0.0", 0)
		return
	}
	up, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		writeReply(c, 0x05, "0.0.0.0", 0)
		return
	}
	defer up.Close()

	la := up.LocalAddr().(*net.TCPAddr)
	writeReply(c, 0x00, la.IP.String(), la.Port)

	done := make(chan struct{})
	go func() {
		io.Copy(up, c)
		if tc, ok := up.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		close(done)
	}()
	io.Copy(c, up)
	<-done
}

func (s *testServer) handleUDP(c net.Conn) {
	if s.noUDP {
		writeReply(c, 0x07, "0.0.0.0", 0)
		return
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		writeReply(c, 0x01, "0.0.0.0", 0)
		return
	}
	defer relay.Close()

	ra := relay.LocalAddr().(*net.UDPAddr)
	bnd := ra.IP.String()
	if s.bndZero {
		bnd = "0.0.0.0"
	}
	writeReply(c, 0x00, bnd, ra.Port)

	// 向上游转发用的 socket
	up, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	defer up.Close()

	var (
		mu         sync.Mutex
		clientAddr *net.UDPAddr
		lastTarget *net.UDPAddr
	)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := up.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			ca := clientAddr
			mu.Unlock()
			if ca == nil {
				continue
			}
			out := []byte{0x00, 0x00, 0x00}
			out, _ = appendAddr(out, src.IP.String(), src.Port)
			out = append(out, buf[:n]...)
			relay.WriteToUDP(out, ca)
		}
	}()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := relay.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 4 || buf[2] != 0 {
				continue
			}
			host, port, payload, err := parseUDPHeader(buf[3:n])
			if err != nil {
				continue
			}
			target, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
				continue
			}
			mu.Lock()
			clientAddr = src
			lastTarget = target
			mu.Unlock()
			_ = lastTarget
			up.WriteToUDP(payload, target)
		}
	}()

	// 保持控制连接直到对端关闭。
	var b [1]byte
	c.Read(b[:])
}

func writeReply(c net.Conn, code byte, host string, port int) {
	b := []byte{version5, code, 0x00}
	b, err := appendAddr(b, host, port)
	if err != nil {
		b = append([]byte{version5, code, 0x00, atypIPv4, 0, 0, 0, 0}, 0, 0)
	}
	c.Write(b)
}

// echoTCP 启动一个把收到内容原样回写的 TCP 服务。
func echoTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// echoUDP 启动一个 UDP 回显服务。
func echoUDP(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pc.WriteToUDP(buf[:n], src)
		}
	}()
	return pc.LocalAddr().String()
}

func mustUint16(b []byte) int { return int(binary.BigEndian.Uint16(b)) }
