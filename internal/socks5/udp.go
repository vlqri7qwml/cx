package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// maxUDPPayload 为单个 UDP 数据报的缓冲上限。
const maxUDPPayload = 64 * 1024

// UDPConn 是一条 SOCKS5 UDP ASSOCIATE 会话。
//
// 按 RFC 1928，控制用的 TCP 连接必须在整个 UDP 会话期间保持打开：
// 一旦它断开，代理就会释放 UDP 中继端口。因此 UDPConn 同时持有
// 控制连接与中继 socket，并在控制连接断开时主动关闭自己。
type UDPConn struct {
	ctrl  net.Conn
	relay *net.UDPConn
	// relayAddr 是代理返回的 UDP 中继地址。
	relayAddr *net.UDPAddr

	closed chan struct{}
	once   sync.Once

	// rMu 保护 rBuf。每个数据报都临时分配一个 64 KiB 缓冲会给 GC 很大压力，
	// 而一条 UDP 流上的读取本来就是串行的，复用一块缓冲即可。
	rMu  sync.Mutex
	rBuf []byte
}

// UDPAssociate 申请一条 UDP 中继会话。
func (c *Client) UDPAssociate(ctx context.Context) (*UDPConn, error) {
	ctrl, err := c.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("连接代理 %s 失败: %w", c.Addr, err)
	}
	ok := false
	defer func() {
		if !ok {
			ctrl.Close()
		}
	}()

	var bndHost string
	var bndPort int
	if err := c.withDeadline(ctx, ctrl, func() error {
		if err := c.handshake(ctrl); err != nil {
			return err
		}
		// 客户端此时尚不知道自己将用哪个源端口发包，按 RFC 建议填全零。
		var e error
		bndHost, bndPort, e = c.request(ctrl, cmdUDPAssociate, "0.0.0.0", 0)
		return e
	}); err != nil {
		return nil, err
	}

	relayAddr, err := c.resolveRelay(ctrl, bndHost, bndPort)
	if err != nil {
		return nil, err
	}

	// 按中继地址族选择本地监听族，避免 v4/v6 混用。
	laddr := &net.UDPAddr{IP: net.IPv4zero}
	if relayAddr.IP.To4() == nil {
		laddr = &net.UDPAddr{IP: net.IPv6zero}
	}
	relay, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, fmt.Errorf("创建本地 UDP socket 失败: %w", err)
	}

	u := &UDPConn{
		ctrl:      ctrl,
		relay:     relay,
		relayAddr: relayAddr,
		closed:    make(chan struct{}),
	}
	ok = true

	// 控制连接一旦断开就终止整条会话。
	go func() {
		var b [1]byte
		_, _ = ctrl.Read(b[:])
		u.Close()
	}()

	return u, nil
}

// resolveRelay 解析代理返回的中继地址。许多代理会返回 0.0.0.0，
// 此时按 RFC 1928 的建议回退为控制连接的对端地址。
func (c *Client) resolveRelay(ctrl net.Conn, host string, port int) (*net.UDPAddr, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("代理返回的 UDP 端口不合法: %d", port)
	}

	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		ra, ok := ctrl.RemoteAddr().(*net.TCPAddr)
		if !ok {
			return nil, errors.New("无法推断代理 UDP 中继地址")
		}
		ip = ra.IP
	}
	return &net.UDPAddr{IP: ip, Port: port}, nil
}

// WriteTo 把负载经代理发往 target（host:port，host 可为域名，由代理解析）。
func (u *UDPConn) WriteTo(p []byte, target string) (int, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return 0, fmt.Errorf("目标地址格式错误 %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("目标端口格式错误 %q: %w", portStr, err)
	}

	// RSV(2) + FRAG(1) + ATYP + ADDR + PORT + DATA
	buf := make([]byte, 0, 3+1+len(host)+2+len(p)+16)
	buf = append(buf, 0x00, 0x00, 0x00)
	buf, err = appendAddr(buf, host, port)
	if err != nil {
		return 0, err
	}
	buf = append(buf, p...)

	if _, err := u.relay.WriteToUDP(buf, u.relayAddr); err != nil {
		return 0, err
	}
	return len(p), nil
}

// ReadFrom 读取一个经代理返回的 UDP 数据报，返回负载与原始来源地址。
//
// 负载会被拷贝进 p；p 装不下时多余部分会被丢弃（UDP 本就允许截断）。
func (u *UDPConn) ReadFrom(p []byte) (int, string, error) {
	u.rMu.Lock()
	defer u.rMu.Unlock()

	if u.rBuf == nil {
		u.rBuf = make([]byte, maxUDPPayload)
	}
	buf := u.rBuf
	for {
		n, _, err := u.relay.ReadFromUDP(buf)
		if err != nil {
			return 0, "", err
		}
		if n < 5 {
			continue // 畸形报文，丢弃
		}
		if buf[2] != 0x00 {
			// 不支持分片（RFC 1928 允许实现直接丢弃）。
			continue
		}
		host, port, body, err := parseUDPHeader(buf[3:n])
		if err != nil {
			continue
		}
		copied := copy(p, body)
		return copied, net.JoinHostPort(host, strconv.Itoa(port)), nil
	}
}

// parseUDPHeader 解析 ATYP 起的地址，并返回其后的负载。
func parseUDPHeader(b []byte) (host string, port int, payload []byte, err error) {
	if len(b) < 1 {
		return "", 0, nil, errors.New("数据报过短")
	}
	switch b[0] {
	case atypIPv4:
		if len(b) < 1+4+2 {
			return "", 0, nil, errors.New("IPv4 数据报过短")
		}
		return net.IP(b[1:5]).String(), int(binary.BigEndian.Uint16(b[5:7])), b[7:], nil
	case atypIPv6:
		if len(b) < 1+16+2 {
			return "", 0, nil, errors.New("IPv6 数据报过短")
		}
		return net.IP(b[1:17]).String(), int(binary.BigEndian.Uint16(b[17:19])), b[19:], nil
	case atypDomain:
		if len(b) < 2 {
			return "", 0, nil, errors.New("域名数据报过短")
		}
		l := int(b[1])
		if len(b) < 2+l+2 {
			return "", 0, nil, errors.New("域名数据报长度不符")
		}
		return string(b[2 : 2+l]), int(binary.BigEndian.Uint16(b[2+l : 4+l])), b[4+l:], nil
	}
	return "", 0, nil, fmt.Errorf("未知地址类型 0x%02x", b[0])
}

// SetReadDeadline 设置读取超时。
func (u *UDPConn) SetReadDeadline(t time.Time) error { return u.relay.SetReadDeadline(t) }

// SetWriteDeadline 设置写入超时。
func (u *UDPConn) SetWriteDeadline(t time.Time) error { return u.relay.SetWriteDeadline(t) }

// Done 在会话结束时关闭，便于调用方感知控制连接断开。
func (u *UDPConn) Done() <-chan struct{} { return u.closed }

// Close 关闭中继 socket 与控制连接。可重复调用。
func (u *UDPConn) Close() error {
	u.once.Do(func() {
		close(u.closed)
		_ = u.relay.Close()
		_ = u.ctrl.Close()
	})
	return nil
}
