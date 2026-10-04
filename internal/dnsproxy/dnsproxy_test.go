package dnsproxy

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testDNS 启动一个 TCP DNS 测试服务，返回地址与请求计数器。
func testDNS(t *testing.T, handler func(w dns.ResponseWriter, r *dns.Msg)) (string, *atomic.Int64) {
	t.Helper()
	var count atomic.Int64

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		count.Add(1)
		handler(w, r)
	})
	// 必须等服务真正起来再返回。
	//
	// miekg/dns 的 ShutdownContext 在 started 还是 false 时会直接返回
	// "server not started" 且**不关闭监听器**，随后 ActivateAndServe 会永远
	// 卡在 Accept 上，<-done 也就永远等不到 —— 表现为整个包跑到 10 分钟超时。
	// 用例体内若没有真正发过查询（例如多问题查询那条），就可能撞上这个竞态。
	started := make(chan struct{})
	srv := &dns.Server{
		Listener:          ln,
		Net:               "tcp",
		Handler:           mux,
		NotifyStartedFunc: func() { close(started) },
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.ActivateAndServe()
	}()

	select {
	case <-started:
	case <-time.After(10 * time.Second):
		_ = ln.Close()
		t.Fatal("DNS 测试服务启动超时")
	}

	t.Cleanup(func() {
		_ = srv.Shutdown()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			// 宁可让用例明确失败，也不要挂满 10 分钟再被测试框架打断。
			t.Error("DNS 测试服务未能在 10 秒内停止")
		}
	})
	return ln.Addr().String(), &count
}

// answerA 构造一个固定的 A 应答。
func answerA(ip string, ttl uint32) func(dns.ResponseWriter, *dns.Msg) {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   net.ParseIP(ip),
		})
		_ = w.WriteMsg(m)
	}
}

// directDial 模拟“经代理”的 Dial：测试里直接连本地。
func directDial(ctx context.Context, target string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", target)
}

func query(t *testing.T, r *Resolver, name string, qtype uint16) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	req.Id = 0x4242
	resp, err := r.QueryMsg(context.Background(), req)
	if err != nil {
		t.Fatalf("QueryMsg(%s): %v", name, err)
	}
	if resp.Id != req.Id {
		t.Errorf("应答 ID 未与请求对齐: got %d want %d", resp.Id, req.Id)
	}
	return resp
}

func TestForwardAQuery(t *testing.T) {
	addr, count := testDNS(t, answerA("203.0.113.9", 300))
	r := &Resolver{Dial: directDial, Servers: []string{addr}}

	resp := query(t, r, "shop.example.com", dns.TypeA)
	if len(resp.Answer) != 1 {
		t.Fatalf("期望 1 条应答，实际 %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "203.0.113.9" {
		t.Fatalf("应答内容不对: %v", resp.Answer[0])
	}
	if count.Load() != 1 {
		t.Errorf("上游请求次数 %d，期望 1", count.Load())
	}
}

func TestCacheHitAvoidsUpstream(t *testing.T) {
	addr, count := testDNS(t, answerA("203.0.113.9", 300))
	r := &Resolver{Dial: directDial, Servers: []string{addr}}

	query(t, r, "shop.example.com", dns.TypeA)
	query(t, r, "shop.example.com", dns.TypeA)
	query(t, r, "SHOP.Example.COM", dns.TypeA) // 大小写不敏感
	if got := count.Load(); got != 1 {
		t.Errorf("缓存未生效，上游被请求 %d 次", got)
	}
}

func TestCacheTTLDecrementsAndExpires(t *testing.T) {
	addr, count := testDNS(t, answerA("203.0.113.9", 60))
	r := &Resolver{Dial: directDial, Servers: []string{addr}}
	r.init()

	now := time.Now()
	r.cache.now = func() time.Time { return now }

	first := query(t, r, "a.example.com", dns.TypeA)
	if first.Answer[0].Header().Ttl != 60 {
		t.Fatalf("首次 TTL 应为 60，实际 %d", first.Answer[0].Header().Ttl)
	}

	now = now.Add(20 * time.Second)
	second := query(t, r, "a.example.com", dns.TypeA)
	if ttl := second.Answer[0].Header().Ttl; ttl != 40 {
		t.Errorf("缓存回放 TTL 应递减为 40，实际 %d", ttl)
	}
	if count.Load() != 1 {
		t.Errorf("20 秒内不应回源，实际 %d 次", count.Load())
	}

	now = now.Add(61 * time.Second)
	query(t, r, "a.example.com", dns.TypeA)
	if count.Load() != 2 {
		t.Errorf("过期后应回源，上游请求 %d 次", count.Load())
	}
}

func TestBlockAAAAReturnsEmptyAnswer(t *testing.T) {
	addr, count := testDNS(t, answerA("203.0.113.9", 300))
	r := &Resolver{Dial: directDial, Servers: []string{addr}, BlockAAAA: true}

	resp := query(t, r, "shop.example.com", dns.TypeAAAA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("AAAA 应返回 NOERROR，实际 %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("AAAA 应返回空应答，实际 %d 条", len(resp.Answer))
	}
	if count.Load() != 0 {
		t.Errorf("AAAA 不应回源，实际 %d 次", count.Load())
	}

	// A 记录仍然正常。
	if got := query(t, r, "shop.example.com", dns.TypeA); len(got.Answer) != 1 {
		t.Errorf("A 查询应正常返回，实际 %d 条", len(got.Answer))
	}
}

func TestAAAAPassesThroughWhenNotBlocked(t *testing.T) {
	addr, _ := testDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 30},
			AAAA: net.ParseIP("2001:db8::1"),
		})
		_ = w.WriteMsg(m)
	})
	r := &Resolver{Dial: directDial, Servers: []string{addr}}
	if got := query(t, r, "v6.example.com", dns.TypeAAAA); len(got.Answer) != 1 {
		t.Errorf("未开启过滤时 AAAA 应透传，实际 %d 条", len(got.Answer))
	}
}

func TestFailoverToSecondUpstream(t *testing.T) {
	// 第一个上游指向一个已关闭的端口。
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()

	good, count := testDNS(t, answerA("198.51.100.7", 120))
	var logged atomic.Int64
	r := &Resolver{
		Dial:    directDial,
		Servers: []string{deadAddr, good},
		Logf:    func(string, ...any) { logged.Add(1) },
	}

	resp := query(t, r, "shop.example.com", dns.TypeA)
	if len(resp.Answer) != 1 {
		t.Fatalf("应从第二个上游取得应答，实际 %d 条", len(resp.Answer))
	}
	if count.Load() != 1 {
		t.Errorf("健康上游请求次数 %d", count.Load())
	}
	if logged.Load() == 0 {
		t.Error("失败上游应被记录")
	}
}

func TestAllUpstreamsDown(t *testing.T) {
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := dead.Addr().String()
	dead.Close()

	r := &Resolver{Dial: directDial, Servers: []string{addr}, Timeout: time.Second}
	req := new(dns.Msg)
	req.SetQuestion("a.example.com.", dns.TypeA)
	if _, err := r.QueryMsg(context.Background(), req); err == nil {
		t.Fatal("全部上游不可用时应返回错误")
	}
}

func TestNoUpstreamConfigured(t *testing.T) {
	r := &Resolver{Dial: directDial}
	req := new(dns.Msg)
	req.SetQuestion("a.example.com.", dns.TypeA)
	_, err := r.QueryMsg(context.Background(), req)
	if !errors.Is(err, ErrNoUpstream) {
		t.Fatalf("期望 ErrNoUpstream，实际 %v", err)
	}
}

func TestNXDomainCachedWithNegativeTTL(t *testing.T) {
	addr, count := testDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		m.Ns = append(m.Ns, &dns.SOA{
			Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 86400},
			Ns:      "ns1.example.com.",
			Mbox:    "a.example.com.",
			Minttl:  3600,
			Serial:  1,
			Refresh: 1, Retry: 1, Expire: 1,
		})
		_ = w.WriteMsg(m)
	})
	r := &Resolver{Dial: directDial, Servers: []string{addr}}

	resp := query(t, r, "nope.example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("期望 NXDOMAIN，实际 %s", dns.RcodeToString[resp.Rcode])
	}
	query(t, r, "nope.example.com", dns.TypeA)
	if count.Load() != 1 {
		t.Errorf("NXDOMAIN 应被缓存，上游请求 %d 次", count.Load())
	}
	// 负缓存上限 600 秒。
	if got := ttlOf(resp); got != maxNegativeTTL*time.Second {
		t.Errorf("负缓存 TTL 应裁剪到 %d 秒，实际 %v", maxNegativeTTL, got)
	}
}

func TestTruncatedNotCached(t *testing.T) {
	addr, count := testDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		_ = w.WriteMsg(m)
	})
	r := &Resolver{Dial: directDial, Servers: []string{addr}}
	query(t, r, "t.example.com", dns.TypeA)
	query(t, r, "t.example.com", dns.TypeA)
	if count.Load() != 2 {
		t.Errorf("截断应答不应缓存，上游请求 %d 次", count.Load())
	}
}

func TestMultiQuestionRejected(t *testing.T) {
	addr, count := testDNS(t, answerA("203.0.113.9", 300))
	r := &Resolver{Dial: directDial, Servers: []string{addr}}

	req := new(dns.Msg)
	req.Id = 1
	req.Question = []dns.Question{
		{Name: "a.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "b.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	resp, err := r.QueryMsg(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeFormatError {
		t.Errorf("多问题查询应回 FORMERR，实际 %s", dns.RcodeToString[resp.Rcode])
	}
	if count.Load() != 0 {
		t.Error("多问题查询不应回源")
	}
}

func TestQueryWireFormat(t *testing.T) {
	addr, _ := testDNS(t, answerA("203.0.113.9", 300))
	r := &Resolver{Dial: directDial, Servers: []string{addr}}

	req := new(dns.Msg)
	req.SetQuestion("shop.example.com.", dns.TypeA)
	wire, err := req.Pack()
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.Query(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(out); err != nil {
		t.Fatalf("应答无法解析: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Errorf("期望 1 条应答，实际 %d", len(resp.Answer))
	}

	if _, err := r.Query(context.Background(), []byte{0x01, 0x02}); err == nil {
		t.Error("畸形报文应报错")
	}
}

func TestUpstreamsNormalization(t *testing.T) {
	r := &Resolver{Servers: []string{"8.8.8.8", " 1.1.1.1:5353 ", "2001:4860:4860::8888", "", "   "}}
	got := r.upstreams()
	want := []string{"8.8.8.8:53", "1.1.1.1:5353", "[2001:4860:4860::8888]:53"}
	if len(got) != len(want) {
		t.Fatalf("规范化结果数量不符: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 项: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestFlushClearsCache(t *testing.T) {
	addr, count := testDNS(t, answerA("203.0.113.9", 300))
	r := &Resolver{Dial: directDial, Servers: []string{addr}}
	query(t, r, "shop.example.com", dns.TypeA)
	r.Flush()
	query(t, r, "shop.example.com", dns.TypeA)
	if count.Load() != 2 {
		t.Errorf("Flush 后应回源，上游请求 %d 次", count.Load())
	}
}

func TestCacheLRUEviction(t *testing.T) {
	c := newCache(2)
	m := new(dns.Msg)
	m.SetQuestion("a.", dns.TypeA)
	c.put("k1", m, time.Minute)
	c.put("k2", m, time.Minute)
	c.put("k3", m, time.Minute)
	if c.Len() != 2 {
		t.Fatalf("容量应为 2，实际 %d", c.Len())
	}
	if _, ok := c.get("k1"); ok {
		t.Error("最旧条目应被淘汰")
	}
	if _, ok := c.get("k3"); !ok {
		t.Error("最新条目应保留")
	}
}

func TestCacheDisabled(t *testing.T) {
	addr, count := testDNS(t, answerA("203.0.113.9", 300))
	r := &Resolver{Dial: directDial, Servers: []string{addr}, MaxCacheEntries: -1}
	query(t, r, "shop.example.com", dns.TypeA)
	query(t, r, "shop.example.com", dns.TypeA)
	if count.Load() != 2 {
		t.Errorf("禁用缓存后应每次回源，实际 %d 次", count.Load())
	}
}

func TestServFail(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("a.example.com.", dns.TypeA)
	req.Id = 0x1234
	wire, err := req.Pack()
	if err != nil {
		t.Fatal(err)
	}

	out := ServFail(wire)
	if out == nil {
		t.Fatal("ServFail 返回 nil")
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(out); err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("Rcode = %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
	if resp.Id != 0x1234 || !resp.Response {
		t.Errorf("应答头不正确: id=%#x response=%v", resp.Id, resp.Response)
	}
	if ServFail([]byte{1, 2, 3}) != nil {
		t.Error("畸形输入应返回 nil")
	}
}
