module github.com/vlqri7qwml/cx

go 1.25.0

require (
	github.com/Microsoft/go-winio v0.6.2
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794
	github.com/miekg/dns v1.1.68
	github.com/xjasonlyu/tun2socks/v2 v2.6.0
	golang.org/x/crypto v0.50.0
	golang.org/x/sys v0.43.0
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb
	golang.zx2c4.com/wireguard/windows v1.1.1
)

require (
	github.com/google/btree v1.1.3 // indirect
	github.com/lxn/win v0.0.0-20210218163916-a377121e959e // indirect
	golang.org/x/mod v0.34.0 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/time v0.11.0 // indirect
	golang.org/x/tools v0.43.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20250523182742-eede7a881b20 // indirect
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20260420103851-857e549307fe
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20210224134948-620c54ef6199
)
