package netbind

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// fallbackResolvers 在物理网卡没有可用 DNS（或内网 DNS 不通）时兜底。
var fallbackResolvers = []netip.Addr{
	netip.MustParseAddr("8.8.8.8"),
	netip.MustParseAddr("1.1.1.1"),
}

// ErrResolveFailed 表示代理服务器域名解析失败。
var ErrResolveFailed = errors.New("代理服务器域名解析失败")

// ResolveProxyHost 解析代理服务器地址。
//
// 这一步必须绕过代理自身：此刻 TUN 可能已经接管了路由，而走代理的 DNS
// 又依赖代理先连上，构成循环。因此这里直接用物理网卡的 DNS，
// 并把查询 socket 绑定在物理网卡上。
//
// host 本身就是 IP 时直接返回，不做任何查询。
func (m *Monitor) ResolveProxyHost(ctx context.Context, host string, timeout time.Duration) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}
	if host == "" {
		return nil, fmt.Errorf("%w: 地址为空", ErrResolveFailed)
	}

	iface, ok := m.Current()
	if !ok {
		return nil, ErrNoDefaultRoute
	}

	m.mu.RLock()
	exclude := m.excludeLUID
	m.mu.RUnlock()

	servers, err := PhysicalDNS(exclude)
	if err != nil || len(servers) == 0 {
		servers = nil
	}
	servers = append(servers, fallbackResolvers...)

	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			return control(iface.Index, network, c)
		},
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), dns.TypeA)
	msg.RecursionDesired = true

	var lastErr error
	for _, srv := range servers {
		if ctx.Err() != nil {
			break
		}
		addrs, err := queryA(ctx, dialer, srv, msg)
		if err != nil {
			lastErr = err
			continue
		}
		if len(addrs) > 0 {
			return addrs, nil
		}
		lastErr = fmt.Errorf("%s 未返回 A 记录", srv)
	}
	if lastErr == nil {
		lastErr = errors.New("没有可用的 DNS 服务器")
	}
	return nil, fmt.Errorf("%w (%s): %v", ErrResolveFailed, host, lastErr)
}

func queryA(ctx context.Context, dialer *net.Dialer, server netip.Addr, msg *dns.Msg) ([]netip.Addr, error) {
	target := net.JoinHostPort(server.String(), "53")

	exchange := func(network string) (*dns.Msg, error) {
		c := &dns.Client{Net: network, Dialer: dialer, Timeout: dialer.Timeout}
		resp, _, err := c.ExchangeContext(ctx, msg, target)
		return resp, err
	}

	resp, err := exchange("udp")
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		if tcpResp, tcpErr := exchange("tcp"); tcpErr == nil {
			resp = tcpResp
		}
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS 返回 %s", dns.RcodeToString[resp.Rcode])
	}

	var out []netip.Addr
	for _, rr := range resp.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		if addr, ok := netip.AddrFromSlice(a.A); ok {
			out = append(out, addr.Unmap())
		}
	}
	return out, nil
}
