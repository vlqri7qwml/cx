package firewall

import (
	"net/netip"
	"testing"
)

func TestPrefixToV4(t *testing.T) {
	cases := []struct {
		prefix   string
		wantAddr uint32
		wantMask uint32
	}{
		// 10.0.0.0/8 -> 0x0A000000, 掩码 0xFF000000
		{"10.0.0.0/8", 0x0A000000, 0xFF000000},
		{"172.16.0.0/12", 0xAC100000, 0xFFF00000},
		{"192.168.0.0/16", 0xC0A80000, 0xFFFF0000},
		{"169.254.0.0/16", 0xA9FE0000, 0xFFFF0000},
		{"224.0.0.0/4", 0xE0000000, 0xF0000000},
		{"255.255.255.255/32", 0xFFFFFFFF, 0xFFFFFFFF},
		{"0.0.0.0/0", 0x00000000, 0x00000000},
		// 未对齐的输入应先被掩码规整
		{"192.168.5.9/16", 0xC0A80000, 0xFFFF0000},
	}
	for _, c := range cases {
		addr, mask := prefixToV4(netip.MustParsePrefix(c.prefix))
		if addr != c.wantAddr || mask != c.wantMask {
			t.Errorf("prefixToV4(%s) = 0x%08X/0x%08X, want 0x%08X/0x%08X",
				c.prefix, addr, mask, c.wantAddr, c.wantMask)
		}
	}
}

func TestPrefixToV6(t *testing.T) {
	addr, bits := prefixToV6(netip.MustParsePrefix("fe80::/10"))
	if bits != 10 {
		t.Errorf("前缀长度 = %d, want 10", bits)
	}
	if addr[0] != 0xfe || addr[1] != 0x80 {
		t.Errorf("fe80::/10 首两字节 = %02x%02x, want fe80", addr[0], addr[1])
	}
	for i := 2; i < 16; i++ {
		if addr[i] != 0 {
			t.Errorf("fe80::/10 第 %d 字节应为 0，实际 %02x", i, addr[i])
		}
	}

	// 未对齐输入应被规整：fe80::1/10 的 ::1 必须被掩掉。
	addr, _ = prefixToV6(netip.MustParsePrefix("fe80::1/10"))
	if addr[15] != 0 {
		t.Errorf("fe80::1/10 规整后末字节应为 0，实际 %02x", addr[15])
	}

	addr, bits = prefixToV6(netip.MustParsePrefix("ff00::/8"))
	if bits != 8 || addr[0] != 0xff {
		t.Errorf("ff00::/8 转换错误: %02x /%d", addr[0], bits)
	}
}

func TestPrivateRangesAreSane(t *testing.T) {
	// 放行列表里绝不能出现任何能把流量送往公网的网段。
	for _, p := range privateV4 {
		if p.Addr().IsGlobalUnicast() && !p.Addr().IsPrivate() && !p.Addr().IsLinkLocalUnicast() {
			t.Errorf("IPv4 放行网段 %s 是公网可路由地址，不应放行", p)
		}
	}
	for _, p := range privateV6 {
		if p.Addr().IsGlobalUnicast() && !p.Addr().IsPrivate() && !p.Addr().IsLinkLocalUnicast() {
			t.Errorf("IPv6 放行网段 %s 是公网可路由地址，不应放行", p)
		}
	}
	if len(privateV4) == 0 || len(privateV6) == 0 {
		t.Fatal("放行网段列表不应为空")
	}
}
