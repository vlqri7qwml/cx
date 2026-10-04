package firewall

import (
	"encoding/binary"
	"net/netip"
)

// 断网期间仍然放行的私有网段。
//
// 选择依据：这些地址不可能把流量送出公司网络之外，放行它们不会泄露真实出口 IP，
// 却能让内网打印机、NAS、ERP、域控登录在代理未连接时继续可用。
var (
	privateV4 = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("169.254.0.0/16"), // 链路本地（APIPA）
		netip.MustParsePrefix("224.0.0.0/4"),    // 组播（含 mDNS、SSDP）
		netip.MustParsePrefix("255.255.255.255/32"),
	}
	privateV6 = []netip.Prefix{
		netip.MustParsePrefix("fe80::/10"), // 链路本地
		netip.MustParsePrefix("fc00::/7"),  // 唯一本地地址
		netip.MustParsePrefix("ff00::/8"),  // 组播
	}
)

// prefixToV4 把 IPv4 前缀转成 WFP 的 FWP_V4_ADDR_AND_MASK 所需的两个 uint32。
//
// WFP 的 IPv4 地址一律用主机字节序的 UINT32 表示（而非网络字节序的字节串），
// 这里单独抽成纯函数，便于在任意平台上做单元测试。
func prefixToV4(p netip.Prefix) (addr, mask uint32) {
	a := p.Masked().Addr().As4()
	addr = binary.BigEndian.Uint32(a[:])
	if bits := p.Bits(); bits > 0 {
		mask = ^uint32(0) << (32 - bits)
	}
	return addr, mask
}

// prefixToV6 把 IPv6 前缀转成 FWP_V6_ADDR_AND_MASK 所需的字节串与前缀长度。
// IPv6 地址在 WFP 中保持网络字节序。
func prefixToV6(p netip.Prefix) (addr [16]byte, prefixLen uint8) {
	return p.Masked().Addr().As16(), uint8(p.Bits())
}

// deriveKeyIndex 从派生出的 filterKey 最后一个字节取回序号，仅用于测试与排错。
func deriveKeyIndex(last byte) int { return int(last) }
