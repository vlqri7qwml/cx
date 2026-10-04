// Package dnsproxy 实现经 SOCKS5 以 TCP 转发的 DNS 解析器。
//
// 整机的 DNS 查询会被 TUN 协议栈劫持到这里，再通过代理以 TCP（DNS-over-TCP）
// 发往上游，因此不存在经物理网卡泄露 DNS 的可能。同时按需过滤 AAAA，
// 使整机实际只走 IPv4，与 WFP 阻断 IPv6 的策略一致。
package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DialFunc 通过代理建立到 target（host:port）的 TCP 连接。
type DialFunc func(ctx context.Context, target string) (net.Conn, error)

// Resolver 是一个带缓存的 DNS 转发器。
type Resolver struct {
	// Dial 必须非 nil，通常就是 socks5.Client.DialContext。
	Dial DialFunc
	// Servers 为上游 DNS，元素可写 "8.8.8.8" 或 "8.8.8.8:53"。
	Servers []string
	// BlockAAAA 为 true 时对 AAAA 查询直接回空应答（NOERROR / 0 条记录）。
	BlockAAAA bool
	// Timeout 为单次上游查询超时，默认 5 秒。
	Timeout time.Duration
	// MaxCacheEntries 为缓存条目上限，默认 4096；为负数表示禁用缓存。
	MaxCacheEntries int

	// Logf 可选，用于记录上游失败。
	Logf func(format string, args ...any)

	once  sync.Once
	cache *cache
}

// ErrNoUpstream 表示没有可用上游 DNS。
var ErrNoUpstream = errors.New("没有可用的上游 DNS 服务器")

const (
	defaultTimeout  = 5 * time.Second
	defaultCacheCap = 4096

	minTTL         = 10
	maxTTL         = 3600
	maxNegativeTTL = 600
)

func (r *Resolver) init() {
	r.once.Do(func() {
		capacity := r.MaxCacheEntries
		if capacity == 0 {
			capacity = defaultCacheCap
		}
		if capacity > 0 {
			r.cache = newCache(capacity)
		}
	})
}

func (r *Resolver) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return defaultTimeout
}

func (r *Resolver) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

// upstreams 返回规范化后的上游列表（补齐 :53）。
func (r *Resolver) upstreams() []string {
	out := make([]string, 0, len(r.Servers))
	for _, s := range r.Servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			if ip := net.ParseIP(s); ip != nil && ip.To4() == nil {
				s = "[" + s + "]:53"
			} else {
				s = s + ":53"
			}
		}
		out = append(out, s)
	}
	return out
}

// Query 处理一个 DNS 报文（线序字节），返回应答字节。
func (r *Resolver) Query(ctx context.Context, wire []byte) ([]byte, error) {
	req := new(dns.Msg)
	if err := req.Unpack(wire); err != nil {
		return nil, fmt.Errorf("DNS 报文解析失败: %w", err)
	}
	resp, err := r.QueryMsg(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Pack()
}

// QueryMsg 处理一个已解析的 DNS 查询。
func (r *Resolver) QueryMsg(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	r.init()

	if len(req.Question) != 1 {
		// 只处理单问题查询，其余按 FORMERR 回复，避免缓存键歧义。
		return errorReply(req, dns.RcodeFormatError), nil
	}
	q := req.Question[0]

	// 过滤 AAAA：回空应答，浏览器与系统解析器会立刻改用 A 记录。
	if r.BlockAAAA && q.Qtype == dns.TypeAAAA {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Rcode = dns.RcodeSuccess
		m.RecursionAvailable = true
		return m, nil
	}

	key := cacheKey(q)
	if r.cache != nil {
		if cached, ok := r.cache.get(key); ok {
			return adapt(cached, req), nil
		}
	}

	resp, err := r.exchange(ctx, req)
	if err != nil {
		return nil, err
	}
	if r.cache != nil && cacheable(resp) {
		r.cache.put(key, resp, ttlOf(resp))
	}
	return adapt(resp, req), nil
}

// exchange 向所有上游并发发起查询，采用最先返回的成功结果。
func (r *Resolver) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	servers := r.upstreams()
	if len(servers) == 0 {
		return nil, ErrNoUpstream
	}
	if r.Dial == nil {
		return nil, errors.New("dnsproxy: 未配置代理 Dial")
	}

	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()

	type result struct {
		msg *dns.Msg
		err error
	}
	ch := make(chan result, len(servers))
	for _, srv := range servers {
		go func(srv string) {
			m, err := r.exchangeOne(ctx, srv, req)
			if err != nil {
				r.logf("DNS 上游 %s 查询失败: %v", srv, err)
			}
			ch <- result{m, err}
		}(srv)
	}

	var lastErr error
	for range servers {
		select {
		case res := <-ch:
			if res.err == nil {
				return res.msg, nil
			}
			lastErr = res.err
		case <-ctx.Done():
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("所有上游 DNS 均失败: %w", lastErr)
}

func (r *Resolver) exchangeOne(ctx context.Context, server string, req *dns.Msg) (*dns.Msg, error) {
	conn, err := r.Dial(ctx, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(r.timeout()))
	}

	co := &dns.Conn{Conn: conn}
	// 以新 ID 发出，避免上游缓存或中间设备按 ID 关联。
	out := req.Copy()
	out.Id = dns.Id()
	if err := co.WriteMsg(out); err != nil {
		return nil, err
	}
	for {
		resp, err := co.ReadMsg()
		if err != nil {
			return nil, err
		}
		if resp.Id == out.Id {
			return resp, nil
		}
		// ID 不匹配说明不是本次查询的应答，继续读。
	}
}

func errorReply(req *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, rcode)
	return m
}

// adapt 把缓存/上游应答调整为与本次请求匹配（ID 与问题段）。
func adapt(src *dns.Msg, req *dns.Msg) *dns.Msg {
	m := src.Copy()
	m.Id = req.Id
	m.Question = req.Question
	m.Response = true
	m.RecursionDesired = req.RecursionDesired
	return m
}

func cacheKey(q dns.Question) string {
	return strings.ToLower(q.Name) + "|" + dns.TypeToString[q.Qtype] + "|" + dns.ClassToString[q.Qclass]
}

// cacheable 判断应答是否值得缓存。
func cacheable(m *dns.Msg) bool {
	if m == nil || m.Truncated {
		return false
	}
	switch m.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
		return true
	}
	return false
}

// ttlOf 取应答中最小 TTL 并做上下限裁剪。
func ttlOf(m *dns.Msg) time.Duration {
	ttl := uint32(0)
	first := true
	for _, rrs := range [][]dns.RR{m.Answer, m.Ns} {
		for _, rr := range rrs {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			t := rr.Header().Ttl
			if first || t < ttl {
				ttl, first = t, false
			}
		}
	}
	if first {
		// 没有任何记录（如空应答 / NXDOMAIN 无 SOA）：按最小 TTL 短暂缓存。
		return minTTL * time.Second
	}
	limit := uint32(maxTTL)
	if m.Rcode == dns.RcodeNameError || len(m.Answer) == 0 {
		limit = maxNegativeTTL
	}
	if ttl > limit {
		ttl = limit
	}
	if ttl < minTTL {
		ttl = minTTL
	}
	return time.Duration(ttl) * time.Second
}

// ServFail 针对一个查询报文构造 SERVFAIL 应答。
//
// 上游彻底不可用时返回它，比干脆不回包要好：客户端会立刻知道失败，
// 而不是反复重试到超时（Windows 解析器的重试会明显拖慢所有程序）。
func ServFail(wire []byte) []byte {
	req := new(dns.Msg)
	if err := req.Unpack(wire); err != nil {
		return nil
	}
	out, err := errorReply(req, dns.RcodeServerFailure).Pack()
	if err != nil {
		return nil
	}
	return out
}
