package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/vlqri7qwml/cx/internal/config"
	"github.com/vlqri7qwml/cx/internal/dnsproxy"
	"github.com/vlqri7qwml/cx/internal/netbind"
	"github.com/vlqri7qwml/cx/internal/socks5"
)

// Options 是启动一次隧道所需的全部参数。
type Options struct {
	// TunName 是 Wintun 适配器名称。
	TunName string
	// MTU 为 0 时沿用驱动默认值。
	MTU uint32

	// Node 是要使用的 SOCKS5 节点。
	Node config.Node
	// DNSServers 是上游 DNS（查询经代理以 TCP 发出）。
	DNSServers []string
	// BlockQUIC 为 true 时丢弃 UDP/443。
	BlockQUIC bool
	// BlockAAAA 为 true 时对 AAAA 查询返回空应答（默认关闭 IPv6 时应开启）。
	BlockAAAA bool

	// Monitor 提供绑定物理网卡的 Dialer 与代理域名解析。
	Monitor *netbind.Monitor

	Stats *Stats
	Logf  func(format string, args ...any)
}

// Engine 是一次运行中的隧道。
type Engine struct {
	dev     *tunDevice
	stack   *stack.Stack
	handler *handler
	client  *socks5.Client

	// proxyAddr 是代理服务器被解析后的实际地址。
	proxyAddr string

	closeOnce sync.Once
}

// Start 建立隧道：解析代理地址 → 打开 Wintun → 启动协议栈。
//
// 返回后 TUN 适配器已经存在，调用方应紧接着：
//  1. firewall.PermitTun(e.LUID())  —— 先放行，避免出现短暂不通
//  2. route.Apply(...)              —— 再把流量引过来
func Start(opts Options) (*Engine, error) {
	if opts.Monitor == nil {
		return nil, fmt.Errorf("tunnel: 缺少网卡监视器")
	}
	if opts.Node.Host == "" || opts.Node.Port == 0 {
		return nil, fmt.Errorf("tunnel: 代理节点未配置")
	}

	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	// 代理地址必须在这里就解析成 IP：之后所有到代理的连接都用 IP 直连，
	// 否则 Go 的解析器会走系统 DNS → 进 TUN → 又要先连上代理，形成循环。
	resolveCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	addrs, err := opts.Monitor.ResolveProxyHost(resolveCtx, opts.Node.Host, 8*time.Second)
	cancel()
	if err != nil {
		return nil, err
	}
	proxyAddr := net.JoinHostPort(addrs[0].String(), strconv.Itoa(opts.Node.Port))
	if len(addrs) > 1 {
		logf("代理 %s 解析到 %d 个地址，使用 %s", opts.Node.Host, len(addrs), addrs[0])
	}

	client := &socks5.Client{
		Addr:     proxyAddr,
		Username: opts.Node.Username,
		Password: opts.Node.Password,
		Dial:     opts.Monitor.Dialer(socks5.DefaultTimeout),
		Timeout:  socks5.DefaultTimeout,
	}

	resolver := &dnsproxy.Resolver{
		Dial: func(ctx context.Context, target string) (net.Conn, error) {
			return client.DialContext(ctx, target)
		},
		Servers:   opts.DNSServers,
		BlockAAAA: opts.BlockAAAA,
		Logf:      logf,
	}

	mtu := opts.MTU
	if mtu == 0 {
		mtu = config.DefaultTunMTU
	}
	name := opts.TunName
	if name == "" {
		name = config.DefaultTunName
	}

	dev, err := openTUN(name, mtu)
	if err != nil {
		return nil, err
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	h := &handler{
		client:    client,
		resolver:  resolver,
		blockQUIC: opts.BlockQUIC,
		udpOK:     !opts.Node.NoUDP,
		stats:     opts.Stats,
		logf:      logf,
		ctx:       ctx,
		cancel:    cancelCtx,
	}

	st, err := core.CreateStack(&core.Config{
		LinkEndpoint:     dev,
		TransportHandler: h,
	})
	if err != nil {
		cancelCtx()
		dev.Close()
		return nil, fmt.Errorf("启动用户态协议栈失败: %w", err)
	}

	logf("隧道已启动：适配器 %s (MTU %d)，出口 %s", dev.Name(), dev.MTU(), opts.Node)
	return &Engine{
		dev:       dev,
		stack:     st,
		handler:   h,
		client:    client,
		proxyAddr: proxyAddr,
	}, nil
}

// LUID 返回 Wintun 适配器的接口 LUID。
func (e *Engine) LUID() uint64 { return e.dev.LUID() }

// TunAddr 返回建议配置到 TUN 上的地址与劫持用的 DNS 地址。
func (e *Engine) TunAddr() (netip.Prefix, netip.Addr) {
	return netip.PrefixFrom(netip.MustParseAddr(config.DefaultTunAddr), config.DefaultTunPrefix),
		netip.MustParseAddr(config.DefaultTunDNS)
}

// MTU 返回适配器实际 MTU。
func (e *Engine) MTU() uint32 { return e.dev.MTU() }

// Name 返回适配器名称。
func (e *Engine) Name() string { return e.dev.Name() }

// ProxyAddr 返回代理服务器被解析后的实际地址。
func (e *Engine) ProxyAddr() string { return e.proxyAddr }

// Client 返回用于健康检查与出口探测的 SOCKS5 客户端。
func (e *Engine) Client() *socks5.Client { return e.client }

// Close 关闭协议栈与 TUN 适配器。Wintun 适配器随之从系统中消失，
// 届时流量再也进不来 —— 配合仍然生效的 WFP 阻断规则，整机即断网。
func (e *Engine) Close() {
	e.closeOnce.Do(func() {
		e.handler.cancel()
		e.stack.Close()
		e.dev.Close()
		// 给仍在搬运数据的协程一点时间自行退出（它们都带读写超时）。
		_ = e.handler.wait(3 * time.Second)
	})
}
