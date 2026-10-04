package main

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

// 程序以 GUI 子系统编译（-H windowsgui），否则托盘每次启动都会闪一个黑框。
// 代价是命令行子命令默认没有标准输出，因此这里手动接上控制台。
var (
	modkernel32        = windows.NewLazySystemDLL("kernel32.dll")
	procAttachConsole  = modkernel32.NewProc("AttachConsole")
	procAllocConsole   = modkernel32.NewProc("AllocConsole")
	procGetConsoleWnd  = modkernel32.NewProc("GetConsoleWindow")
	attachParentProces = ^uintptr(0) // ATTACH_PARENT_PROCESS = (DWORD)-1
)

// attachConsole 把标准输出接到调用方的控制台。
//
// 返回的 done 必须在程序结束前调用：从资源管理器直接双击运行时，
// 我们会自己开一个控制台窗口，done 会在退出前等一下，
// 否则窗口一闪而过，用户什么都看不到。
func attachConsole() (done func()) {
	noop := func() {}

	if hasConsole() {
		bindStdHandles()
		return noop
	}

	r1, _, _ := procAttachConsole.Call(attachParentProces)
	if r1 != 0 {
		bindStdHandles()
		return noop
	}

	// 没有父控制台：自己开一个。
	if r1, _, _ := procAllocConsole.Call(); r1 == 0 {
		return noop
	}
	bindStdHandles()
	return func() {
		os.Stdout.WriteString("\n按回车键关闭此窗口…")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
	}
}

func hasConsole() bool {
	r1, _, _ := procGetConsoleWnd.Call()
	return r1 != 0
}

// bindStdHandles 把 os.Stdin/Stdout/Stderr 指向当前控制台。
func bindStdHandles() {
	// 控制台默认是本地代码页，不设成 UTF-8 的话中文会变成乱码。
	_ = windows.SetConsoleOutputCP(65001)

	if h, err := openConsole("CONOUT$", windows.GENERIC_READ|windows.GENERIC_WRITE); err == nil {
		os.Stdout = os.NewFile(uintptr(h), "CONOUT$")
	}
	if h, err := openConsole("CONOUT$", windows.GENERIC_READ|windows.GENERIC_WRITE); err == nil {
		os.Stderr = os.NewFile(uintptr(h), "CONOUT$")
	}
	if h, err := openConsole("CONIN$", windows.GENERIC_READ|windows.GENERIC_WRITE); err == nil {
		os.Stdin = os.NewFile(uintptr(h), "CONIN$")
	}
}

func openConsole(name string, access uint32) (windows.Handle, error) {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(p, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil,
		windows.OPEN_EXISTING, 0, 0)
}
