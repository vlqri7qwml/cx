// Package tunnel 把 Wintun 网卡上收到的 IP 报文交给用户态协议栈，
// 再按五元组转成到 SOCKS5 代理的 TCP 连接或 UDP 中继。
//
// 数据路径：
//
//	应用程序 → 系统路由(0.0.0.0/1) → Wintun → gVisor netstack
//	  ├─ TCP           → SOCKS5 CONNECT
//	  ├─ UDP :53       → 本地 DNS 解析器 → SOCKS5 上的 DNS-over-TCP
//	  ├─ UDP :443      → 按配置丢弃（迫使浏览器回落 TCP）
//	  └─ 其他 UDP      → SOCKS5 UDP ASSOCIATE（代理不支持时丢弃）
//
// 协议栈与转发逻辑仅在 Windows 下编译；本文件中的统计量是平台无关的。
package tunnel
