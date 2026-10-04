package service

// Version 是产品版本号，构建时可通过 -ldflags "-X ...Version=..." 覆盖。
var Version = "1.0.0"

const (
	// Name 是 Windows 服务名。
	Name = "CXProxy"
	// DisplayName 是服务在 services.msc 里的显示名。
	DisplayName = "CXProxy 代理与断网保护"
	// Description 是服务描述。
	Description = "通过 TUN 虚拟网卡接管整机流量并转发至 SOCKS5 代理；" +
		"代理未连接时阻断整机联网（断网保护），防止真实 IP 泄露。"
)
