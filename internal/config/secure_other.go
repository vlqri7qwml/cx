//go:build !windows

package config

// 非 Windows 平台（仅用于单元测试）下依赖 0600/0700 文件权限即可。
func secureDir(string) error  { return nil }
func secureFile(string) error { return nil }
