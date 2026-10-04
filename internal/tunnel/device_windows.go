package tunnel

import (
	"fmt"
	"sync"

	"golang.org/x/sys/windows"
	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/iobased"
)

// tunGUID 固定了 Wintun 适配器的 GUID。
//
// 不固定的话，每次创建适配器 Windows 都会认为这是一块“新网卡”，
// 于是在网络连接里留下“网络 2”“网络 3”……越积越多，
// 并且防火墙配置档、跃点等按接口记录的设置也会反复重置。
var tunGUID = windows.GUID{
	Data1: 0x7f1d4c6d,
	Data2: 0x9b32,
	Data3: 0x4de1,
	Data4: [8]byte{0xa4, 0x57, 0x63, 0x78, 0x70, 0x72, 0x6f, 0x78},
}

// Windows 上 Wintun 不需要为报文预留头部。
const tunOffset = 0

// tunDevice 包装 wireguard-go 的 NativeTun，使其既满足 tun2socks 的
// device.Device 接口，又能把 Wintun 的 LUID 暴露出去 ——
// 配置路由与 WFP 放行规则都需要这个 LUID。
type tunDevice struct {
	*iobased.Endpoint

	nt   *wgtun.NativeTun
	name string
	mtu  uint32

	rSizes []int
	rBuffs [][]byte
	wBuffs [][]byte
	rMu    sync.Mutex
	wMu    sync.Mutex
}

var _ device.Device = (*tunDevice)(nil)

// openTUN 创建（或打开）Wintun 适配器。
func openTUN(name string, mtu uint32) (dev *tunDevice, err error) {
	defer func() {
		// wireguard-go 在驱动缺失等情况下会 panic，这里转成普通错误，
		// 以免把整个服务带崩。
		if r := recover(); r != nil {
			err = fmt.Errorf("创建 Wintun 适配器失败: %v（请确认 wintun.dll 与程序在同一目录）", r)
		}
	}()

	wgtun.WintunStaticRequestedGUID = &tunGUID

	d := &tunDevice{
		name:   name,
		mtu:    mtu,
		rSizes: make([]int, 1),
		rBuffs: make([][]byte, 1),
		wBuffs: make([][]byte, 1),
	}

	nt, err := wgtun.CreateTUN(name, int(mtu))
	if err != nil {
		return nil, fmt.Errorf("创建 Wintun 适配器 %q 失败: %w", name, err)
	}
	native, ok := nt.(*wgtun.NativeTun)
	if !ok {
		nt.Close()
		return nil, fmt.Errorf("意外的 TUN 实现类型 %T", nt)
	}
	d.nt = native

	actualMTU, err := native.MTU()
	if err != nil {
		native.Close()
		return nil, fmt.Errorf("读取 TUN MTU 失败: %w", err)
	}
	d.mtu = uint32(actualMTU)

	ep, err := iobased.New(d, d.mtu, tunOffset)
	if err != nil {
		native.Close()
		return nil, fmt.Errorf("创建链路层端点失败: %w", err)
	}
	d.Endpoint = ep
	return d, nil
}

// LUID 返回 Wintun 适配器的接口 LUID。
func (d *tunDevice) LUID() uint64 { return d.nt.LUID() }

// MTU 返回适配器实际 MTU。
func (d *tunDevice) MTU() uint32 { return d.mtu }

func (d *tunDevice) Read(packet []byte) (int, error) {
	d.rMu.Lock()
	defer d.rMu.Unlock()
	d.rBuffs[0] = packet
	if _, err := d.nt.Read(d.rBuffs, d.rSizes, tunOffset); err != nil {
		return 0, err
	}
	return d.rSizes[0], nil
}

func (d *tunDevice) Write(packet []byte) (int, error) {
	d.wMu.Lock()
	defer d.wMu.Unlock()
	d.wBuffs[0] = packet
	return d.nt.Write(d.wBuffs, tunOffset)
}

// Name 返回适配器名称。
func (d *tunDevice) Name() string {
	if name, err := d.nt.Name(); err == nil {
		return name
	}
	return d.name
}

// Type 满足 device.Device 接口。
func (d *tunDevice) Type() string { return "tun" }

// Close 关闭端点与适配器。适配器关闭时 Wintun 会自行移除虚拟网卡。
func (d *tunDevice) Close() {
	if d.Endpoint != nil {
		d.Endpoint.Close()
	}
	_ = d.nt.Close()
}
