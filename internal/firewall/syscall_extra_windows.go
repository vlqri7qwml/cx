package firewall

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fwpuclnt.dll 中用于删除/查询 WFP 对象的函数。
//
// 这些 FwpmXxx 函数把错误码直接作为返回值（DWORD / FWP_E_*），而不是通过
// SetLastError 传递，因此这里手写包装、取返回值本身作为错误，
// 以便可靠地区分“对象不存在”与真正的失败。
var (
	procFwpmFilterDeleteByKey0   = modfwpuclnt.NewProc("FwpmFilterDeleteByKey0")
	procFwpmSubLayerDeleteByKey0 = modfwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmProviderDeleteByKey0 = modfwpuclnt.NewProc("FwpmProviderDeleteByKey0")
	procFwpmFilterGetByKey0      = modfwpuclnt.NewProc("FwpmFilterGetByKey0")
)

// WFP 错误码（winerror.h 中的 FWP_E_*）。
const (
	fwpErrFilterNotFound   syscall.Errno = 0x80320003
	fwpErrProviderNotFound syscall.Errno = 0x80320005
	fwpErrSublayerNotFound syscall.Errno = 0x80320007
	fwpErrNotFound         syscall.Errno = 0x80320008
	fwpErrAlreadyExists    syscall.Errno = 0x80320009
	fwpErrInUse            syscall.Errno = 0x8032000A
)

// isNotFound 判断错误是否属于“对象本来就不存在”，删除时可安全忽略。
func isNotFound(err error) bool {
	return errors.Is(err, fwpErrFilterNotFound) ||
		errors.Is(err, fwpErrProviderNotFound) ||
		errors.Is(err, fwpErrSublayerNotFound) ||
		errors.Is(err, fwpErrNotFound)
}

func fwpStatus(r1 uintptr) error {
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

func fwpmFilterDeleteByKey0(engine uintptr, key *windows.GUID) error {
	r1, _, _ := syscall.SyscallN(procFwpmFilterDeleteByKey0.Addr(), engine, uintptr(unsafe.Pointer(key)))
	return fwpStatus(r1)
}

func fwpmSubLayerDeleteByKey0(engine uintptr, key *windows.GUID) error {
	r1, _, _ := syscall.SyscallN(procFwpmSubLayerDeleteByKey0.Addr(), engine, uintptr(unsafe.Pointer(key)))
	return fwpStatus(r1)
}

func fwpmProviderDeleteByKey0(engine uintptr, key *windows.GUID) error {
	r1, _, _ := syscall.SyscallN(procFwpmProviderDeleteByKey0.Addr(), engine, uintptr(unsafe.Pointer(key)))
	return fwpStatus(r1)
}

// fwpmFilterGetByKey0 只用于判断某条 filter 是否存在；
// 返回的 FWPM_FILTER0 内容我们并不关心，取到后直接释放。
func fwpmFilterGetByKey0(engine uintptr, key *windows.GUID) (exists bool, err error) {
	var out uintptr
	r1, _, _ := syscall.SyscallN(procFwpmFilterGetByKey0.Addr(),
		engine, uintptr(unsafe.Pointer(key)), uintptr(unsafe.Pointer(&out)))
	if err := fwpStatus(r1); err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, err
	}
	if out != 0 {
		fwpmFreeMemory0(unsafe.Pointer(&out))
	}
	return true, nil
}
