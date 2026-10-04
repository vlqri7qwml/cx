package route

import (
	"fmt"
	"net/netip"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Config 描述要施加到 TUN 网卡上的网络配置。
type Config struct {
	LUID winipcfg.LUID
	// Addr 是 TUN 自身地址，例如 172.19.0.1/30。
	Addr netip.Prefix
	// DNS 是下发给系统的 DNS 服务器（指向被协议栈劫持的地址）。
	DNS []netip.Addr
	// MTU 为 0 时沿用驱动默认值。
	MTU uint32
}

// 两条半默认路由：合起来覆盖整个 IPv4 空间，且比 0.0.0.0/0 更具体。
var halfDefaultRoutes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/1"),
	netip.MustParsePrefix("128.0.0.0/1"),
}

// Apply 配置 TUN 的地址、路由、DNS 与接口参数。
func Apply(cfg Config) error {
	if !cfg.Addr.IsValid() || !cfg.Addr.Addr().Is4() {
		return fmt.Errorf("TUN 地址必须是合法的 IPv4 前缀，实际 %v", cfg.Addr)
	}

	if err := cfg.LUID.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{cfg.Addr}); err != nil {
		return fmt.Errorf("设置 TUN 地址 %s 失败: %w", cfg.Addr, err)
	}

	routes := make([]*winipcfg.RouteData, 0, len(halfDefaultRoutes))
	for _, p := range halfDefaultRoutes {
		routes = append(routes, &winipcfg.RouteData{
			Destination: p,
			NextHop:     netip.IPv4Unspecified(), // 直连（on-link）
			Metric:      0,
		})
	}
	if err := cfg.LUID.SetRoutesForFamily(windows.AF_INET, routes); err != nil {
		return fmt.Errorf("设置 TUN 路由失败: %w", err)
	}

	if err := applyInterface(cfg, windows.AF_INET); err != nil {
		return err
	}

	// IPv6：只把接口参数压到最低，不配地址、不加路由。
	// 整机的 IPv6 出网由 WFP 阻断，DNS 侧再过滤掉 AAAA，三者合起来确保不走 v6。
	_ = applyInterface(cfg, windows.AF_INET6)

	if len(cfg.DNS) > 0 {
		if err := cfg.LUID.SetDNS(windows.AF_INET, cfg.DNS, nil); err != nil {
			return fmt.Errorf("设置 TUN DNS 失败: %w", err)
		}
	}

	// 清掉系统解析器缓存，避免沿用代理启用前解析到的地址。
	FlushResolverCache()
	return nil
}

func applyInterface(cfg Config, family winipcfg.AddressFamily) error {
	ipif, err := cfg.LUID.IPInterface(family)
	if err != nil {
		return fmt.Errorf("读取 TUN 接口参数失败: %w", err)
	}
	ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	ipif.DadTransmits = 0
	ipif.ManagedAddressConfigurationSupported = false
	ipif.OtherStatefulConfigurationSupported = false
	// 跃点固定为 0：TUN 的半默认路由本就比默认路由更具体，
	// 固定跃点只是避免 Windows 的自动跃点在网络切换时产生抖动。
	ipif.UseAutomaticMetric = false
	ipif.Metric = 0
	if family == windows.AF_INET && cfg.MTU > 0 {
		ipif.NLMTU = cfg.MTU
	}
	if err := ipif.Set(); err != nil {
		return fmt.Errorf("设置 TUN 接口参数失败: %w", err)
	}
	return nil
}

// Clear 清除 TUN 上的地址、路由与 DNS。
//
// Wintun 适配器本身在设备关闭时就会消失，这里主要是为了在同一次运行中
// 重新连接（切换节点）时不残留旧配置。
func Clear(luid winipcfg.LUID) error {
	var firstErr error
	keep := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		keep(ignoreNotFound(luid.FlushRoutes(family)))
		keep(ignoreNotFound(luid.FlushIPAddresses(family)))
		keep(ignoreNotFound(luid.FlushDNS(family)))
	}
	FlushResolverCache()
	return firstErr
}

// ignoreNotFound 忽略“对象不存在”类错误：适配器已经消失时无需报错。
func ignoreNotFound(err error) error {
	if err == nil {
		return nil
	}
	var errno syscall.Errno
	switch {
	case errorsAs(err, &errno) && (errno == windows.ERROR_NOT_FOUND ||
		errno == windows.ERROR_FILE_NOT_FOUND ||
		errno == windows.ERROR_OBJECT_NOT_FOUND):
		return nil
	}
	return err
}

var (
	modDnsapi                 = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsFlushResolverCache = modDnsapi.NewProc("DnsFlushResolverCache")
)

// FlushResolverCache 清空 Windows DNS 客户端缓存，等价于 ipconfig /flushdns。
func FlushResolverCache() {
	if err := procDnsFlushResolverCache.Find(); err != nil {
		return
	}
	_, _, _ = syscall.SyscallN(procDnsFlushResolverCache.Addr())
}
