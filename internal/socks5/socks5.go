// Package socks5 实现 RFC 1928 / RFC 1929 的 SOCKS5 客户端，
// 支持 CONNECT 与 UDP ASSOCIATE，并允许调用方注入自定义 Dialer，
// 以便把到代理服务器的连接强制绑定在物理网卡上（避免被自家 TUN 回环）。
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	version5 = 0x05

	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03

	authNone     = 0x00
	authUserPass = 0x02
	authNoneOK   = 0xFF

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	authVersion = 0x01
)

// DefaultTimeout 为握手默认超时。
const DefaultTimeout = 10 * time.Second

// Dialer 用于建立到 SOCKS5 服务器的底层连接。
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Client 是一个无状态的 SOCKS5 客户端配置。
type Client struct {
	// Addr 是 SOCKS5 服务器地址（host:port）。
	Addr string
	// Username / Password 为空表示使用无认证方式。
	Username string
	Password string
	// Dial 用于连接 SOCKS5 服务器；为 nil 时使用 net.Dialer。
	Dial Dialer
	// Timeout 控制握手阶段的超时，为 0 时取 DefaultTimeout。
	Timeout time.Duration
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	if c.Dial != nil {
		return c.Dial(ctx, "tcp", c.Addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", c.Addr)
}

// replyError 描述 SOCKS5 服务端返回的失败应答。
type replyError byte

func (e replyError) Error() string {
	switch byte(e) {
	case 0x01:
		return "代理服务器内部错误 (general SOCKS server failure)"
	case 0x02:
		return "代理规则不允许此连接 (connection not allowed by ruleset)"
	case 0x03:
		return "代理报告网络不可达 (network unreachable)"
	case 0x04:
		return "代理报告主机不可达 (host unreachable)"
	case 0x05:
		return "目标拒绝连接 (connection refused)"
	case 0x06:
		return "TTL 超时 (TTL expired)"
	case 0x07:
		return "代理不支持该命令 (command not supported)"
	case 0x08:
		return "代理不支持该地址类型 (address type not supported)"
	}
	return fmt.Sprintf("代理返回未知错误码 0x%02x", byte(e))
}

// ErrAuthFailed 表示用户名密码被代理拒绝。
var ErrAuthFailed = errors.New("代理认证失败：用户名或密码错误")

// ErrNoAcceptableAuth 表示代理不接受我们支持的认证方式。
var ErrNoAcceptableAuth = errors.New("代理不接受所提供的认证方式")

// handshake 完成版本协商与认证。
func (c *Client) handshake(conn net.Conn) error {
	methods := []byte{authNone}
	if c.Username != "" {
		methods = []byte{authUserPass, authNone}
	}

	req := make([]byte, 0, 2+len(methods))
	req = append(req, version5, byte(len(methods)))
	req = append(req, methods...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("发送握手请求失败: %w", err)
	}

	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("读取握手应答失败: %w", err)
	}
	if resp[0] != version5 {
		return fmt.Errorf("对端不是 SOCKS5 服务器（版本 0x%02x）", resp[0])
	}

	switch resp[1] {
	case authNone:
		return nil
	case authUserPass:
		if c.Username == "" {
			return ErrNoAcceptableAuth
		}
		return c.authUserPass(conn)
	case authNoneOK:
		return ErrNoAcceptableAuth
	default:
		return fmt.Errorf("代理要求不支持的认证方式 0x%02x", resp[1])
	}
}

func (c *Client) authUserPass(conn net.Conn) error {
	if len(c.Username) > 255 || len(c.Password) > 255 {
		return errors.New("用户名或密码超过 255 字节")
	}
	buf := make([]byte, 0, 3+len(c.Username)+len(c.Password))
	buf = append(buf, authVersion, byte(len(c.Username)))
	buf = append(buf, c.Username...)
	buf = append(buf, byte(len(c.Password)))
	buf = append(buf, c.Password...)
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("发送认证信息失败: %w", err)
	}
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("读取认证应答失败: %w", err)
	}
	if resp[1] != 0x00 {
		return ErrAuthFailed
	}
	return nil
}

// request 发送一条 SOCKS5 请求并解析应答，返回 BND.ADDR / BND.PORT。
func (c *Client) request(conn net.Conn, cmd byte, host string, port int) (bndHost string, bndPort int, err error) {
	req := []byte{version5, cmd, 0x00}
	req, err = appendAddr(req, host, port)
	if err != nil {
		return "", 0, err
	}
	if _, err := conn.Write(req); err != nil {
		return "", 0, fmt.Errorf("发送请求失败: %w", err)
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", 0, fmt.Errorf("读取应答失败: %w", err)
	}
	if head[0] != version5 {
		return "", 0, fmt.Errorf("应答版本错误 0x%02x", head[0])
	}
	if head[1] != 0x00 {
		// 先把地址读完，保持连接状态干净（随后无论如何都会关闭）。
		_, _, _ = readAddrBody(conn, head[3])
		return "", 0, replyError(head[1])
	}
	return readAddrBody(conn, head[3])
}

// readAddrBody 读取 ATYP 之后的地址与端口。
func readAddrBody(r io.Reader, atyp byte) (host string, port int, err error) {
	switch atyp {
	case atypIPv4:
		var b [6]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", 0, err
		}
		return net.IP(b[:4]).String(), int(binary.BigEndian.Uint16(b[4:])), nil
	case atypIPv6:
		var b [18]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", 0, err
		}
		return net.IP(b[:16]).String(), int(binary.BigEndian.Uint16(b[16:])), nil
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", 0, err
		}
		b := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		return string(b[:l[0]]), int(binary.BigEndian.Uint16(b[l[0]:])), nil
	}
	return "", 0, fmt.Errorf("应答中出现未知地址类型 0x%02x", atyp)
}

// appendAddr 以 SOCKS5 地址格式追加 host:port。
func appendAddr(b []byte, host string, port int) ([]byte, error) {
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("端口不合法: %d", port)
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b = append(b, atypIPv4)
			b = append(b, v4...)
		} else {
			b = append(b, atypIPv6)
			b = append(b, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("域名长度不合法: %d", len(host))
		}
		b = append(b, atypDomain, byte(len(host)))
		b = append(b, host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}

// DialContext 通过代理建立到 target（host:port）的 TCP 连接。
func (c *Client) DialContext(ctx context.Context, target string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("目标地址格式错误 %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("目标端口格式错误 %q: %w", portStr, err)
	}

	conn, err := c.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("连接代理 %s 失败: %w", c.Addr, err)
	}

	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()

	if err := c.withDeadline(ctx, conn, func() error {
		if err := c.handshake(conn); err != nil {
			return err
		}
		_, _, err := c.request(conn, cmdConnect, host, port)
		return err
	}); err != nil {
		return nil, err
	}

	ok = true
	return conn, nil
}

// withDeadline 在握手期间施加超时与 ctx 取消。
func (c *Client) withDeadline(ctx context.Context, conn net.Conn, fn func() error) error {
	deadline := time.Now().Add(c.timeout())
	if d, hasDeadline := ctx.Deadline(); hasDeadline && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			// 让阻塞中的 Read/Write 立刻返回。
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}()

	if err := fn(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}
	// 清除握手期的 deadline，之后由调用方自行控制。
	return conn.SetDeadline(time.Time{})
}

// Probe 只做握手，用于校验代理可用性与认证信息，返回握手耗时。
func (c *Client) Probe(ctx context.Context) (time.Duration, error) {
	start := time.Now()
	conn, err := c.dial(ctx)
	if err != nil {
		return 0, fmt.Errorf("连接代理 %s 失败: %w", c.Addr, err)
	}
	defer conn.Close()
	if err := c.withDeadline(ctx, conn, func() error { return c.handshake(conn) }); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}
