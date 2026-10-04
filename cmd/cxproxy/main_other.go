//go:build !windows

package main

import (
	"fmt"
	"os"
)

// CXProxy 依赖 Wintun 驱动与 Windows Filtering Platform，只能在 Windows 上运行。
// 这个占位实现让 go build ./... 与 go vet ./... 可以在 Linux/macOS 上照常执行。
func run() {
	fmt.Fprintln(os.Stderr, "CXProxy 仅支持 Windows 10/11 x64。")
	os.Exit(1)
}
