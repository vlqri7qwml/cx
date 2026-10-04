package tunnel

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/vlqri7qwml/cx/internal/dnsproxy"
	"github.com/vlqri7qwml/cx/internal/socks5"
)

const (
	// tcpIdleTimeout 是单向无数据的最长等待时间。TCP 连接可能长时间空闲
	// （长轮询、数据库连接池），因此给得比较宽松。
	tcpIdleTimeout = 15 * time.Minute
	// udpIdleTimeout 对应一条 UDP 流的保活时间。
	udpIdleTimeout = 90 * time.Second
	// dnsIdleTimeout 是同一个 DNS 流上等待下一个查询的时间。
	dnsIdleTimeout = 30 * time.Second

	relayBufSize = 32 * 1024
	udpBufSize   = 64 * 1024

	dnsPort  = 53
	quicPort = 443
)

// handler 实现 tun2socks 的 adapter.TransportHandler。
type handler struct {
	client    *socks5.Client
	resolver  *dnsproxy.Resolver
	blockQUIC bool
	udpOK     bool
	stats     *Stats
	logf      func(format string, args ...any)

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

var _ adapter.TransportHandler = (*handler)(nil)

func (h *handler) log(format string, args ...any) {
	if h.logf != nil {
		h.logf(format, args...)
	}
}

// HandleTCP 由协议栈在每条新 TCP 流上调用，必须立刻返回。
func (h *handler) HandleTCP(conn adapter.TCPConn) {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		h.serveTCP(conn)
	}()
}

// HandleUDP 由协议栈在每条新 UDP 流上调用，必须立刻返回。
func (h *handler) HandleUDP(conn adapter.UDPConn) {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		h.serveUDP(conn)
	}()
}

func (h *handler) serveTCP(conn adapter.TCPConn) {
	defer conn.Close()

	target := destination(conn.ID().LocalAddress, conn.ID().LocalPort)
	if target == "" {
		return
	}

	h.stats.tcpOpened()
	defer h.stats.tcpClosed()

	ctx, cancel := context.WithTimeout(h.ctx, socks5.DefaultTimeout)
	remote, err := h.client.DialContext(ctx, target)
	cancel()
	if err != nil {
		if h.ctx.Err() == nil {
			h.log("TCP %s 经代理连接失败: %v", target, err)
		}
		h.stats.drop()
		return
	}
	defer remote.Close()

	h.relayTCP(conn, remote)
}

// relayTCP 在应用与代理之间双向搬运数据。
//
// 任一方向读完（EOF）时只关闭对端的写侧，而不是直接断开整条连接：
// HTTP 这类协议会先发完请求再半关闭，然后继续等应答。
func (h *handler) relayTCP(local, remote net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n := copyStream(remote, local, tcpIdleTimeout)
		h.stats.addUp(n)
		closeWrite(remote)
	}()
	go func() {
		defer wg.Done()
		n := copyStream(local, remote, tcpIdleTimeout)
		h.stats.addDown(n)
		closeWrite(local)
	}()

	wg.Wait()
}

// copyStream 搬运数据直到出错或空闲超时，返回搬运的字节数。
func copyStream(dst, src net.Conn, idle time.Duration) int {
	buf := make([]byte, relayBufSize)
	total := 0
	for {
		_ = src.SetReadDeadline(time.Now().Add(idle))
		n, err := src.Read(buf)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(idle))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total
			}
			total += n
		}
		if err != nil {
			return total
		}
	}
}

// closeWrite 只关闭写侧；对端不支持半关闭时退化为整体关闭。
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

func (h *handler) serveUDP(conn adapter.UDPConn) {
	defer conn.Close()

	id := conn.ID()
	port := id.LocalPort

	switch {
	case port == dnsPort:
		h.serveDNS(conn)

	case h.blockQUIC && port == quicPort:
		// 丢弃 QUIC：浏览器拿不到 UDP/443 的应答后会自动回落到 TCP。
		// 住宅类 SOCKS5 代理普遍不支持 UDP 中继，回落比放任超时体验更好。
		h.stats.drop()

	case !h.udpOK:
		h.stats.drop()

	default:
		target := destination(id.LocalAddress, id.LocalPort)
		if target == "" {
			return
		}
		h.relayUDP(conn, target)
	}
}

// serveDNS 把这条流上的所有 DNS 查询交给本地解析器（它经代理以 TCP 查询上游）。
func (h *handler) serveDNS(conn adapter.UDPConn) {
	buf := make([]byte, udpBufSize)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(dnsIdleTimeout))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		h.stats.dnsQuery()

		req := make([]byte, n)
		copy(req, buf[:n])

		ctx, cancel := context.WithTimeout(h.ctx, 8*time.Second)
		resp, err := h.resolver.Query(ctx, req)
		cancel()
		if err != nil {
			h.log("DNS 查询失败: %v", err)
			resp = dnsproxy.ServFail(req)
			if resp == nil {
				continue
			}
		}
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(resp); err != nil {
			return
		}
	}
}

// relayUDP 为这条 UDP 流申请一个 SOCKS5 UDP 中继会话并双向转发。
func (h *handler) relayUDP(conn adapter.UDPConn, target string) {
	ctx, cancel := context.WithTimeout(h.ctx, socks5.DefaultTimeout)
	sess, err := h.client.UDPAssociate(ctx)
	cancel()
	if err != nil {
		if h.ctx.Err() == nil {
			h.log("UDP %s 申请中继失败（代理可能不支持 UDP）: %v", target, err)
		}
		h.stats.drop()
		return
	}
	defer sess.Close()

	h.stats.udpOpened()
	defer h.stats.udpClosed()

	var wg sync.WaitGroup
	wg.Add(2)

	// 应用 → 代理
	go func() {
		defer wg.Done()
		defer sess.Close()
		buf := make([]byte, udpBufSize)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			n, err := conn.Read(buf)
			if n > 0 {
				_ = sess.SetWriteDeadline(time.Now().Add(udpIdleTimeout))
				if _, werr := sess.WriteTo(buf[:n], target); werr != nil {
					return
				}
				h.stats.addUp(n)
			}
			if err != nil {
				return
			}
		}
	}()

	// 代理 → 应用
	go func() {
		defer wg.Done()
		defer conn.Close()
		buf := make([]byte, udpBufSize)
		for {
			_ = sess.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			n, _, err := sess.ReadFrom(buf)
			if n > 0 {
				_ = conn.SetWriteDeadline(time.Now().Add(udpIdleTimeout))
				if _, werr := conn.Write(buf[:n]); werr != nil {
					return
				}
				h.stats.addDown(n)
			}
			if err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

// destination 把协议栈给出的目的地址端口拼成 host:port。
func destination(addr tcpip.Address, port uint16) string {
	ip, ok := netipAddr(addr)
	if !ok {
		return ""
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
}

// netipAddr 把 gVisor 的地址类型转成 netip.Addr。
func netipAddr(addr tcpip.Address) (netip.Addr, bool) {
	switch addr.Len() {
	case 4:
		return netip.AddrFrom4(addr.As4()), true
	case 16:
		a := netip.AddrFrom16(addr.As16())
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}

// wait 等待所有转发协程结束，最多等 d。
func (h *handler) wait(d time.Duration) error {
	done := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(d):
		return errors.New("仍有转发协程未退出")
	}
}
