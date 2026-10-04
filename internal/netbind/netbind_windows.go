package netbind

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// IP_UNICAST_IF / IPV6_UNICAST_IF（ws2ipdef.h）。
const (
	ipUnicastIF   = 31
	ipv6UnicastIF = 31
)

// Iface 描述一块物理网卡。
type Iface struct {
	LUID  winipcfg.LUID
	Index uint32
	Name  string
	// Metric 为路由跃点与接口跃点之和，用于在多网卡时挑选最优默认出口。
	Metric uint32
}

func (i Iface) String() string {
	if i.Name != "" {
		return fmt.Sprintf("%s (ifIndex=%d)", i.Name, i.Index)
	}
	return fmt.Sprintf("ifIndex=%d", i.Index)
}

// ErrNoDefaultRoute 表示当前没有可用的物理默认路由（网线拔了、Wi-Fi 断了）。
var ErrNoDefaultRoute = errors.New("找不到物理默认网卡：请检查网线或 Wi-Fi 连接")

// Monitor 跟踪物理默认网卡，并在其变化时回调。
type Monitor struct {
	// ExcludeLUID 是自家 TUN 的 LUID，选路时必须排除。
	excludeLUID winipcfg.LUID

	mu      sync.RWMutex
	current Iface
	hasCur  bool

	onChange func(Iface, bool)

	routeCB *winipcfg.RouteChangeCallback
	ifaceCB *winipcfg.InterfaceChangeCallback

	closeOnce sync.Once
}

// NewMonitor 创建监视器并立即做一次探测。onChange 可为 nil。
// excludeLUID 传 0 表示不排除任何接口。
func NewMonitor(excludeLUID winipcfg.LUID, onChange func(iface Iface, ok bool)) (*Monitor, error) {
	m := &Monitor{excludeLUID: excludeLUID, onChange: onChange}
	m.refresh()

	var err error
	m.routeCB, err = winipcfg.RegisterRouteChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibIPforwardRow2) {
		m.refresh()
	})
	if err != nil {
		return nil, fmt.Errorf("注册路由变化回调失败: %w", err)
	}
	m.ifaceCB, err = winipcfg.RegisterInterfaceChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibIPInterfaceRow) {
		m.refresh()
	})
	if err != nil {
		m.routeCB.Unregister()
		return nil, fmt.Errorf("注册接口变化回调失败: %w", err)
	}
	return m, nil
}

// SetExclude 更新需要排除的 TUN LUID（TUN 在 Monitor 之后才创建时使用）。
func (m *Monitor) SetExclude(luid winipcfg.LUID) {
	m.mu.Lock()
	m.excludeLUID = luid
	m.mu.Unlock()
	m.refresh()
}

// Current 返回当前物理默认网卡。
func (m *Monitor) Current() (Iface, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current, m.hasCur
}

// Close 注销回调。
func (m *Monitor) Close() {
	m.closeOnce.Do(func() {
		if m.ifaceCB != nil {
			m.ifaceCB.Unregister()
		}
		if m.routeCB != nil {
			m.routeCB.Unregister()
		}
	})
}

func (m *Monitor) refresh() {
	m.mu.RLock()
	exclude := m.excludeLUID
	m.mu.RUnlock()

	iface, err := defaultInterface(exclude)

	m.mu.Lock()
	prev, hadPrev := m.current, m.hasCur
	if err != nil {
		m.hasCur = false
		m.current = Iface{}
	} else {
		m.hasCur = true
		m.current = iface
	}
	cur, hasCur := m.current, m.hasCur
	m.mu.Unlock()

	changed := hadPrev != hasCur || prev.Index != cur.Index || prev.LUID != cur.LUID
	if changed && m.onChange != nil {
		m.onChange(cur, hasCur)
	}
}

// defaultInterface 在 IPv4 路由表里找出最优的物理默认网卡。
func defaultInterface(exclude winipcfg.LUID) (Iface, error) {
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return Iface{}, fmt.Errorf("读取路由表失败: %w", err)
	}
	ifRows, err := winipcfg.GetIPInterfaceTable(windows.AF_INET)
	if err != nil {
		return Iface{}, fmt.Errorf("读取接口表失败: %w", err)
	}
	ifMetric := make(map[winipcfg.LUID]uint32, len(ifRows))
	connected := make(map[winipcfg.LUID]bool, len(ifRows))
	for _, row := range ifRows {
		ifMetric[row.InterfaceLUID] = row.Metric
		connected[row.InterfaceLUID] = row.Connected
	}

	best := Iface{}
	found := false
	var bestMetric uint32
	for i := range routes {
		r := &routes[i]
		if r.DestinationPrefix.PrefixLength != 0 {
			continue // 只看默认路由
		}
		if r.InterfaceLUID == exclude || r.Loopback {
			continue
		}
		if ok, present := connected[r.InterfaceLUID]; present && !ok {
			continue
		}
		metric := r.Metric + ifMetric[r.InterfaceLUID]
		if found && metric >= bestMetric {
			continue
		}
		best = Iface{LUID: r.InterfaceLUID, Index: r.InterfaceIndex, Metric: metric}
		bestMetric, found = metric, true
	}
	if !found {
		return Iface{}, ErrNoDefaultRoute
	}
	if row, err := best.LUID.Interface(); err == nil {
		best.Name = row.Alias()
	}
	return best, nil
}

// control 在 connect 之前把 socket 绑定到指定接口。
//
// IPv4 的 IP_UNICAST_IF 取网络字节序的接口索引，IPv6 的 IPV6_UNICAST_IF
// 取主机字节序 —— 这是 Windows 的一个历史怪癖，写错会静默地不生效。
func control(index uint32, network string, c syscall.RawConn) error {
	if index == 0 {
		return nil
	}
	var sockErr error
	err := c.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		switch network {
		case "tcp6", "udp6", "ip6":
			sockErr = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, ipv6UnicastIF, int(index))
		default:
			sockErr = windows.SetsockoptInt(h, windows.IPPROTO_IP, ipUnicastIF, int(bits.ReverseBytes32(index)))
		}
	})
	if err != nil {
		return err
	}
	return sockErr
}

// Dialer 返回一个把连接绑定在当前物理默认网卡上的 Dialer。
//
// 每次拨号都会重新读取当前网卡，因此 Wi-Fi/有线切换后无需重建 Dialer。
func (m *Monitor) Dialer(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		iface, ok := m.Current()
		if !ok {
			return nil, ErrNoDefaultRoute
		}
		d := &net.Dialer{
			Timeout: timeout,
			Control: func(network, address string, c syscall.RawConn) error {
				return control(iface.Index, network, c)
			},
		}
		return d.DialContext(ctx, network, addr)
	}
}

// PhysicalDNS 返回物理网卡上配置的 DNS 服务器（排除自家 TUN）。
func PhysicalDNS(exclude winipcfg.LUID) ([]netip.Addr, error) {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC,
		winipcfg.GAAFlagSkipAnycast|winipcfg.GAAFlagSkipMulticast|winipcfg.GAAFlagSkipFriendlyName)
	if err != nil {
		return nil, fmt.Errorf("读取网卡信息失败: %w", err)
	}

	var out []netip.Addr
	seen := make(map[netip.Addr]bool)
	for _, a := range adapters {
		if a.LUID == exclude || a.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		if a.IfType == winipcfg.IfTypeSoftwareLoopback {
			continue
		}
		for dns := a.FirstDNSServerAddress; dns != nil; dns = dns.Next {
			ip := dns.Address.IP()
			if ip == nil {
				continue
			}
			addr, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if !addr.IsValid() || addr.IsUnspecified() || seen[addr] {
				continue
			}
			// 站点本地的 IPv6 DNS（fec0::/10）是历史遗留，跳过。
			if addr.Is6() && addr.As16()[0] == 0xfe && addr.As16()[1]&0xc0 == 0xc0 {
				continue
			}
			seen[addr] = true
			out = append(out, addr)
		}
	}
	return out, nil
}
