package firewall

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// wfpObjectInstaller 在一个 WFP 事务内批量安装对象。
type wfpObjectInstaller func(uintptr) error

// baseObjects 是所有 filter 共用的 provider / sublayer。
type baseObjects struct {
	provider windows.GUID
	filters  windows.GUID
}

// 固定 GUID：固定下来才能在任意一次进程启动（包括重启后、
// 或由 cxproxy.exe unblock 应急命令）中找到并删除上一次留下的持久规则。
var (
	providerGUID = windows.GUID{
		Data1: 0x7f1d4c6a,
		Data2: 0x9b32,
		Data3: 0x4de1,
		Data4: [8]byte{0xa4, 0x57, 0x63, 0x78, 0x70, 0x72, 0x6f, 0x78},
	}
	sublayerGUID = windows.GUID{
		Data1: 0x7f1d4c6b,
		Data2: 0x9b32,
		Data3: 0x4de1,
		Data4: [8]byte{0xa4, 0x57, 0x63, 0x78, 0x70, 0x72, 0x6f, 0x78},
	}
	// filterKeyBase 的最后一个字节用作序号，派生出每条持久 filter 的固定 key。
	filterKeyBase = windows.GUID{
		Data1: 0x7f1d4c6c,
		Data2: 0x9b32,
		Data3: 0x4de1,
		Data4: [8]byte{0xa4, 0x57, 0x63, 0x78, 0x70, 0x72, 0x00},
	}
)

// maxPersistentFilters 既是单次 Enable 能装的规则上限，
// 也是 Disable 清理时扫描的序号范围，必须足够宽裕。
const maxPersistentFilters = 128

// cFWPM_PROVIDER_FLAG_PERSISTENT 对应 FWPM_PROVIDER_FLAG_PERSISTENT。
const cFWPM_PROVIDER_FLAG_PERSISTENT uint32 = 0x00000001

func filterKey(i int) windows.GUID {
	g := filterKeyBase
	g.Data4[7] = byte(i)
	return g
}

// Options 控制断网保护的放行范围。
type Options struct {
	// AllowLAN 为 true 时放行 RFC1918 私有网段、链路本地与组播，
	// 使断网期间内网打印机、NAS、办公系统仍然可用。
	AllowLAN bool
}

var (
	mu sync.Mutex

	// dynSession 持有 TUN 放行规则所在的动态会话；
	// 句柄一关，相关 filter 由 WFP 自动回收。
	dynSession uintptr

	// addState 控制 addFilter 的行为，仅在持有 mu 的事务内被设置。
	addState struct {
		persistent bool
		next       int
	}
)

// addFilter 是 rules_windows.go 中所有 filter 新增的统一入口。
//
// 持久模式下给每条规则打上 PERSISTENT 标志与固定 filterKey；
// 动态模式（TUN 放行）下保持 filterKey 为零，由 WFP 自行分配，
// 这样它们既不会与持久规则撞 key，也会随会话关闭自动消失。
func addFilter(session uintptr, filter *wtFwpmFilter0, sd uintptr, id *uint64) error {
	if addState.persistent {
		if addState.next >= maxPersistentFilters {
			return fmt.Errorf("持久规则数量超过上限 %d", maxPersistentFilters)
		}
		filter.filterKey = filterKey(addState.next)
		filter.flags |= cFWPM_FILTER_FLAG_PERSISTENT
		addState.next++
	} else {
		filter.filterKey = windows.GUID{}
		filter.flags &= ^cFWPM_FILTER_FLAG_PERSISTENT
	}
	return fwpmFilterAdd0(session, filter, sd, id)
}

// openSession 打开一个 WFP 引擎会话。dynamic 为 true 时会话内创建的对象
// 会随句柄关闭而自动删除；为 false 时用于读写持久对象。
func openSession(dynamic bool) (uintptr, error) {
	name, desc := "CXProxy", "CXProxy persistent kill-switch session"
	flags := wtFwpmSessionFlagsValue(0)
	if dynamic {
		desc = "CXProxy dynamic session"
		flags = cFWPM_SESSION_FLAG_DYNAMIC
	}
	displayData, err := createWtFwpmDisplayData0(name, desc)
	if err != nil {
		return 0, wrapErr(err)
	}
	session := wtFwpmSession0{
		displayData:          *displayData,
		flags:                flags,
		txnWaitTimeoutInMSec: windows.INFINITE,
	}
	var handle uintptr
	if err := fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, unsafe.Pointer(&handle)); err != nil {
		return 0, wrapErr(err)
	}
	return handle, nil
}

// registerBaseObjects 以固定 GUID 注册持久化的 provider 与 sublayer。
func registerBaseObjects(session uintptr) (*baseObjects, error) {
	bo := &baseObjects{provider: providerGUID, filters: sublayerGUID}

	{
		displayData, err := createWtFwpmDisplayData0("CXProxy", "CXProxy kill-switch provider")
		if err != nil {
			return nil, wrapErr(err)
		}
		provider := wtFwpmProvider0{
			providerKey: bo.provider,
			displayData: *displayData,
			flags:       cFWPM_PROVIDER_FLAG_PERSISTENT,
		}
		if err := fwpmProviderAdd0(session, &provider, 0); err != nil {
			return nil, wrapErr(err)
		}
	}

	{
		displayData, err := createWtFwpmDisplayData0("CXProxy filters", "Permissive and blocking filters")
		if err != nil {
			return nil, wrapErr(err)
		}
		sublayer := wtFwpmSublayer0{
			subLayerKey: bo.filters,
			displayData: *displayData,
			providerKey: &bo.provider,
			flags:       cFWPM_SUBLAYER_FLAG_PERSISTENT,
			weight:      ^uint16(0),
		}
		if err := fwpmSubLayerAdd0(session, &sublayer, 0); err != nil {
			return nil, wrapErr(err)
		}
	}

	return bo, nil
}

// removeAll 删除本程序留下的全部持久对象。可重复执行。
func removeAll(session uintptr) error {
	for i := 0; i < maxPersistentFilters; i++ {
		key := filterKey(i)
		if err := fwpmFilterDeleteByKey0(session, &key); err != nil && !isNotFound(err) {
			return fmt.Errorf("删除规则 #%d 失败: %w", i, err)
		}
	}
	key := sublayerGUID
	if err := fwpmSubLayerDeleteByKey0(session, &key); err != nil && !isNotFound(err) {
		return fmt.Errorf("删除 sublayer 失败: %w", err)
	}
	key = providerGUID
	if err := fwpmProviderDeleteByKey0(session, &key); err != nil && !isNotFound(err) {
		return fmt.Errorf("删除 provider 失败: %w", err)
	}
	return nil
}

// Enable 安装（或重装）持久化断网保护规则。
//
// 装好之后整机默认无法联网，只有以下流量被放行：
//   - CXProxy 服务自身（按 exe 路径 + 服务 SID）—— 它要连 SOCKS5 代理
//   - 本机回环
//   - DHCPv4 / DHCPv6 / NDP —— 否则连不上网络、拿不到 IP
//   - 可选的局域网（opts.AllowLAN）
//
// 真正让业务流量通行的是 TUN 接口放行规则，由 PermitTun 在协议栈起来后装上。
// 因此代理一旦断开，整机立即回到“只剩上面这几条”的状态。
//
// 整个过程在一个 WFP 事务里完成（先删旧、再装新），不存在中途放行的窗口。
func Enable(opts Options) error {
	mu.Lock()
	defer mu.Unlock()

	session, err := openSession(false)
	if err != nil {
		return err
	}
	defer fwpmEngineClose0(session)

	// 旧的 TUN 动态放行规则必须先撤掉，否则它会引用即将被删除的 sublayer。
	closeDynLocked()

	return runTransaction(session, func(session uintptr) error {
		if err := removeAll(session); err != nil {
			return err
		}

		addState.persistent = true
		addState.next = 0
		defer func() { addState.persistent = false }()

		bo, err := registerBaseObjects(session)
		if err != nil {
			return err
		}
		// 权重从高到低：放行自身 > 回环 > DHCP/NDP > 局域网 > 阻断一切。
		if err := permitSelf(session, bo, 15); err != nil {
			return err
		}
		if err := permitLoopback(session, bo, 13); err != nil {
			return err
		}
		if err := permitDHCPIPv4(session, bo, 12); err != nil {
			return err
		}
		if err := permitDHCPIPv6(session, bo, 12); err != nil {
			return err
		}
		if err := permitNdp(session, bo, 12); err != nil {
			return err
		}
		if opts.AllowLAN {
			if err := permitPrivateNetworks(session, bo, 11); err != nil {
				return err
			}
		}
		return blockAll(session, bo, 0)
	})
}

// PermitTun 放行指定 TUN 接口上的流量，使业务流量可以进入协议栈。
//
// 规则写在动态会话里但挂在持久 sublayer 下：WFP 按 sublayer 分别仲裁，
// 放行必须与 blockAll 同层才有效；而动态会话保证进程一旦退出，
// 这条放行立刻消失，机器自动回落到断网状态。
func PermitTun(luid uint64) error {
	mu.Lock()
	defer mu.Unlock()

	closeDynLocked()

	session, err := openSession(true)
	if err != nil {
		return err
	}
	bo := &baseObjects{provider: providerGUID, filters: sublayerGUID}

	addState.persistent = false
	err = runTransaction(session, func(session uintptr) error {
		return permitTunInterface(session, bo, 14, luid)
	})
	if err != nil {
		fwpmEngineClose0(session)
		return fmt.Errorf("放行 TUN 接口失败: %w", err)
	}
	dynSession = session
	return nil
}

// RevokeTun 撤销 TUN 放行规则，整机立即回到断网状态。
func RevokeTun() {
	mu.Lock()
	defer mu.Unlock()
	closeDynLocked()
}

func closeDynLocked() {
	if dynSession != 0 {
		fwpmEngineClose0(dynSession)
		dynSession = 0
	}
}

// Disable 删除全部断网保护规则，恢复直连。
//
// 这是唯一的恢复途径，对应托盘里校验管理员密码后的「退出」，
// 以及管理员应急命令 cxproxy.exe unblock。
func Disable() error {
	mu.Lock()
	defer mu.Unlock()

	closeDynLocked()

	session, err := openSession(false)
	if err != nil {
		return err
	}
	defer fwpmEngineClose0(session)

	return runTransaction(session, removeAll)
}

// Installed 返回持久化断网保护规则当前是否存在。
func Installed() (bool, error) {
	mu.Lock()
	defer mu.Unlock()

	session, err := openSession(false)
	if err != nil {
		return false, err
	}
	defer fwpmEngineClose0(session)

	key := filterKey(0)
	ok, err := fwpmFilterGetByKey0(session, &key)
	if err != nil {
		return false, fmt.Errorf("查询断网保护状态失败: %w", err)
	}
	return ok, nil
}

// ErrNotElevated 表示当前进程权限不足，无法操作 WFP。
var ErrNotElevated = errors.New("操作 WFP 需要管理员权限")
