// Command cxproxy 是 CXProxy 的唯一可执行文件，按子命令切换角色：
//
//	cxproxy.exe              由服务控制管理器启动时以服务运行，否则启动托盘
//	cxproxy.exe --tray       启动右下角托盘（随登录自启）
//	cxproxy.exe install      安装服务（开机自启）+ 登记托盘自启动，需管理员
//	cxproxy.exe uninstall    卸载服务并拆除断网保护，需管理员
//	cxproxy.exe run          前台运行，便于排障，需管理员
//	cxproxy.exe unblock      应急：仅拆除断网保护规则，恢复直连，需管理员
//	cxproxy.exe status       打印当前状态
//	cxproxy.exe version      打印版本
package main

func main() { run() }
