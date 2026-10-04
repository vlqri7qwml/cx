# CXProxy

Windows 10/11 上的 **TUN 全局代理 + 断网保护（kill switch）** 客户端。

开机自启，用虚拟网卡接管整机流量并转发到公司的 SOCKS5 代理；
**代理没连上时整机就没有网**，只有在右下角托盘里输入管理员密码选择「退出」才恢复直连。

> 用途：公司电商平台要求所有办公终端统一从 Texas 的代理出口访问业务系统，
> 任何情况下都不能用本机真实 IP 直连。本程序由 IT 统一部署在**公司自有设备**上，
> 托盘图标常驻可见，员工随时能看到当前状态、当前节点与出口归属地。

---

## 目录

- [它是怎么工作的](#它是怎么工作的)
- [部署](#部署)
- [日常使用](#日常使用)
- [代理地址支持的写法](#代理地址支持的写法)
- [命令行](#命令行)
- [应急恢复](#应急恢复)
- [常见问题](#常见问题)
- [从源码构建](#从源码构建)
- [项目结构](#项目结构)

---

## 它是怎么工作的

```
开机 ─► CXProxy 服务（LocalSystem，自动启动，异常退出 1 秒后自动拉起）
          │
          ├─ ① 先装 WFP 持久化阻断规则 ──────────── 断网保护的根基
          │     阻断一切出入站，只放行：本程序自身 / 回环 / DHCP / NDP /（可选）局域网
          │
          ├─ ② 创建 Wintun 网卡 172.19.0.1/30，DNS 指向 172.19.0.2
          │     路由 0.0.0.0/1 + 128.0.0.0/1 → TUN（比默认路由更具体，但不替换它）
          │
          ├─ ③ 动态放行 TUN 接口（与阻断规则同一个 sublayer，否则放行不生效）
          │
          ├─ ④ gVisor 用户态协议栈
          │     TCP      → SOCKS5 CONNECT
          │     UDP :53  → 本地解析器 → 经 SOCKS5 的 DNS-over-TCP
          │     UDP :443 → 按配置丢弃（浏览器自动回落 TCP）
          │     其他 UDP → SOCKS5 UDP ASSOCIATE（代理不支持时丢弃）
          │
          └─ ⑤ 命名管道 \\.\pipe\cxproxy ◄──► 托盘（普通用户权限）
```

几个关键设计：

- **阻断规则是持久化的（`FWPM_FILTER_FLAG_PERSISTENT`）。**
  它随 Windows 基础筛选引擎启动即生效，不依赖任何进程活着。
  进程被任务管理器结束、服务被停止、甚至整机重启之后，规则依然在位。
- **本程序到代理的连接绑定在物理网卡上（`IP_UNICAST_IF`）。**
  否则这些连接会被自己的 TUN 吸进去，形成死循环。
- **保留物理网卡的默认路由**，改用两条半默认路由接管流量，上一条才成立。
- **DNS 全部在协议栈内被劫持**，经代理以 TCP 发往上游。
  Windows 的多网卡并发查询会被阻断在物理网卡上，不存在 DNS 泄露。
- **IPv6 整体关闭**：TUN 只配 IPv4，AAAA 查询返回空应答，物理网卡的 IPv6 被 WFP 阻断。
- **托盘没有任何特权**。它改不了配置、也退不出保护，一切都要经服务校验管理员密码。
  配置文件 `config.json` 的 ACL 只给 SYSTEM 与 Administrators，普通用户读不到代理明文密码。

### 各种情况下的行为

| 场景 | 结果 |
|---|---|
| 开机，尚未登录 | 阻断规则已生效；服务自动连接代理 |
| 代理连接失败 / 断开 / 未配置 | **整机无网**（局域网按开关），后台按 5s→60s 退避重试 |
| 任务管理器结束 cxproxy 进程 | 持久规则不随进程消失 → **仍然无网**；约 1 秒后服务被自动拉起 |
| `services.msc` 停止服务 | 保留持久规则 → **仍然无网** |
| 关机 / 重启 | 规则保留，下次开机继续接管 |
| Wi-Fi 与有线切换 | 自动感知并重建隧道 |
| 托盘「退出（恢复网络）」+ 正确管理员密码 | 拆除全部规则 → 恢复直连；**下次开机仍会自动接管** |
| 卸载 | 先拆规则再删服务，卸载后网络一定正常 |

---

## 部署

### 方式一：安装程序（推荐）

1. 以管理员身份运行 `CXProxy-Setup-<版本>.exe`。
2. 安装完成后会自动弹出设置窗口：
   - **先设置管理员密码**（至少 8 位，字母 + 数字/符号）。
     没有密码就无法退出断网保护，这是强制的。
   - 点「批量导入…」，把 SOCKS5 代理按每行一条粘贴进去，确定。
   - 选中要用的节点，点「设为当前」，再点「保存」。
3. 托盘图标变绿即表示已接管流量。右键「检测出口 IP」确认出口在 Texas。

### 方式二：Intune / GPO 静默部署

```bat
CXProxy-Setup-1.0.0.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
```

静默安装后服务已启动、断网保护已生效，但**尚未配置代理**，
因此机器会处于「无网」状态，直到配置下发完成。两种下发方式：

- 让管理员在每台机器上打开托盘设置填写；
- 或由 IT 预先生成 `config.json`，随部署脚本放到
  `C:\ProgramData\CXProxy\config.json`（服务启动时会读取），
  然后 `sc start CXProxy`。

> 预置配置时记得同时写入 `password_hash`（bcrypt），否则员工无法退出保护、
> 但 IT 也无法通过托盘修改配置，只能走 `cxproxy.exe unblock` 应急。

### 方式三：手动

把 `cxproxy.exe` 与 `wintun.dll` 放在同一目录，然后以管理员身份执行：

```bat
cxproxy.exe install
```

---

## 日常使用

托盘图标颜色：

| 颜色 | 含义 |
|---|---|
| 🟢 绿 | 已连接，流量正经代理出网 |
| 🟡 黄 | 正在连接 / 正在退出 |
| 🔴 红 | 断网保护生效中，整机无网 |
| ⚪ 灰 | 服务未运行（点「启动保护」可拉起，无需 UAC） |

右键菜单：状态、出口信息、节点切换、连接/断开、检测出口 IP、设置、打开日志目录、退出。

**设置窗口**里可以：批量导入 / 删除 / 排序节点，测试单个节点的握手延迟，
配置上游 DNS，开关「断网时允许局域网」与「阻止 QUIC」，修改管理员密码。
保存配置需要输入管理员密码。

---

## 代理地址支持的写法

每行一条，行尾可用 `#` 加备注；以 `//` 或 `;` 开头的行会被忽略。

```
socks5://user:pass@1.2.3.4:1080          # 休斯顿-1
socks5h://user:pass@gate.example.com:1080
1.2.3.4:1080:user:pass                   # 常见的「四段式」
user:pass@1.2.3.4:1080
1.2.3.4:1080                             # 无认证
[2001:db8::1]:1080                       # IPv6 字面量要加方括号
```

密码里含 `@` 或 `:` 也能正确解析：

- 带 `@` 的写法以**最后一个** `@` 作为用户信息与地址的分界；
- 四段式只按**前三个** `:` 切分，其余都算密码；
- `socks5://` 形式支持百分号转义（`p%40ss` → `p@ss`）。

---

## 命令行

| 命令 | 说明 |
|---|---|
| `cxproxy.exe`（无参数） | 启动托盘（由 SCM 启动时则以服务运行） |
| `cxproxy.exe --tray` | 启动托盘 |
| `cxproxy.exe install` | 安装服务 + 登记托盘自启动并立即启用保护 **（需管理员）** |
| `cxproxy.exe uninstall` | 先拆保护再卸载服务 **（需管理员）** |
| `cxproxy.exe run` | 前台运行，便于排障 **（需管理员）** |
| `cxproxy.exe unblock` | **应急**：只拆除断网保护规则 **（需管理员）** |
| `cxproxy.exe status` | 打印当前状态、节点列表与流量统计 |
| `cxproxy.exe version` | 打印版本 |

> 程序以 GUI 子系统编译（避免托盘启动时闪黑框），命令行子命令会自动接上调用方的控制台。
> 在 `cmd.exe` 里会出现「提示符先返回、输出随后打印」的现象，属正常。
> 想按顺序看输出可以用 `start /wait cxproxy.exe status`。

---

## 应急恢复

**机器没网、托盘也打不开时**，以管理员身份打开命令提示符：

```bat
cd "C:\Program Files\CXProxy"
cxproxy.exe unblock
```

这会按固定 GUID 删除本程序写入的全部 WFP 规则，网络立刻恢复直连。

如果服务仍在运行，它可能会重新装上规则 —— 彻底停用请执行：

```bat
sc stop CXProxy
cxproxy.exe unblock
```

或者直接卸载（会自动先拆规则）：

```bat
cxproxy.exe uninstall
```

**确认规则是否还在**（不依赖本程序）：

```bat
netsh wfp show filters file=C:\Temp\wfp.xml
findstr /C:"CXProxy" C:\Temp\wfp.xml
```

日志在 `C:\ProgramData\CXProxy\logs\cxproxy.log`（普通用户可读，便于发给 IT）。

---

## 常见问题

**Q：为什么不用系统代理设置 / PAC？**
那只对「愿意读这些设置」的程序有效。TUN 在网络层接管，不挑程序；
再配合 WFP 阻断，才能保证「没有代理就没有网」。

**Q：断网保护期间还能访问内网打印机、NAS 吗？**
默认可以。设置里的「断网时仍允许访问局域网」控制是否放行 RFC1918 私有网段、
链路本地与组播。关掉它安全性更高，但现场支持成本也更高。
放行的网段本身到不了公网，不存在真实 IP 泄露。

**Q：为什么默认要阻止 QUIC？**
大量住宅类 SOCKS5 代理不支持 UDP 中继。放任 UDP/443 的结果是浏览器一直等 QUIC 超时，
体验很差。丢弃后浏览器会立刻回落到 TCP。如果你的代理 UDP 支持良好，可以关掉这一项。

**Q：节点列表里的「UDP」是什么？**
该节点是否尝试 UDP ASSOCIATE。某些代理只支持 TCP，可以在配置里把该节点标记为不走 UDP
（`no_udp`），避免每条 UDP 流都先去申请一次中继再失败。

**Q：切换 Wi-Fi 之后断了一下？**
正常。物理出口网卡变化时需要重新解析代理地址、重新绑定 socket 并重建隧道，
通常 1～3 秒。期间整机无网，不会泄露。

**Q：能不能让员工自己关掉？**
可以，但必须知道管理员密码。托盘的「退出（恢复网络）」会校验密码
（连续 5 次输错锁定 60 秒），通过后拆除全部规则。下次开机仍会自动接管。

**Q：卸载后会不会留下无法上网的残留？**
不会。`uninstall` 的顺序是「先拆断网保护，再删服务」，并且拆除失败会直接报错中止，
不会出现「服务没了但规则还在」的情况。

---

## 从源码构建

需要 Go 1.25+、Windows 10/11 x64、（可选）Inno Setup 6.3+。

```powershell
git clone https://github.com/vlqri7qwml/cx.git
cd cx
powershell -ExecutionPolicy Bypass -File build\build.ps1 -Version 1.0.0
```

脚本会：

1. 从 `https://www.wintun.net` 下载 `wintun-0.14.1.zip` 并校验 SHA256
   （期望值在 `build/wintun.sha256`，可用环境变量 `WINTUN_SHA256` 覆盖）；
2. 用 `build/mkicon` 从代码生成图标（PNG + 多尺寸 ICO，仓库里不存二进制资源）；
3. 用 `go-winres` 把图标、版本信息与清单打进 exe；
4. 编译 `build\dist\cxproxy.exe`；
5. 如果装了 Inno Setup，再打出 `build\dist\CXProxy-Setup-<版本>.exe`。

> **首次构建请核对 Wintun 校验值。** `build/wintun.sha256` 里记录的是 0.14.1 的预期值；
> 请与 wintun.net 下载页公布的 SHA256 比对一致后再发布。校验失败时脚本会打印实际值并中止，
> 绝不会把来历不明的内核驱动打进安装包。

跨平台开发时，Linux/macOS 上也能跑全部单元测试与交叉编译检查：

```sh
go test ./...
GOOS=windows GOARCH=amd64 go build ./...
GOOS=windows GOARCH=amd64 go vet ./...
```

---

## 项目结构

```
cmd/cxproxy/            入口：服务 / 托盘 / install / uninstall / run / unblock / status
internal/config/        配置读写、代理地址解析、bcrypt 密码与失败限速
internal/socks5/        SOCKS5 客户端（CONNECT + UDP ASSOCIATE + RFC1929 认证）
internal/dnsproxy/      经 SOCKS5 的 DNS-over-TCP 解析器、AAAA 过滤、LRU + TTL 缓存
internal/firewall/      WFP 持久化断网保护（改编自 wireguard-windows，MIT）
internal/route/         TUN 地址 / 路由 / DNS / 接口跃点配置
internal/netbind/       物理默认网卡探测、绑定网卡的 Dialer、代理域名直连解析
internal/tunnel/        Wintun + gVisor 协议栈，TCP/UDP/DNS 转发
internal/ipc/           命名管道协议与编解码
internal/service/       服务主循环、状态机、健康检查、安装卸载
internal/ui/            托盘与设置界面（walk）、图标生成
internal/logx/          带体积轮转的日志
internal/checker/       出口 IP 与归属地探测
build/                  图标生成器、winres 配置、清单、构建脚本、Inno Setup 脚本
```

### 第三方组件与许可

| 组件 | 用途 | 许可 |
|---|---|---|
| `golang.zx2c4.com/wireguard/tun` | Wintun 适配器封装 | MIT |
| `golang.zx2c4.com/wireguard/windows` | `winipcfg`、WFP 代码基座、walk fork | MIT |
| `github.com/xjasonlyu/tun2socks/v2` | `core`（协议栈装配）与 `iobased` 链路层端点 | GPL-3.0 |
| `gvisor.dev/gvisor` | 用户态 TCP/IP 协议栈 | Apache-2.0 |
| `github.com/lxn/walk` / `lxn/win` | Windows 界面 | BSD-3-Clause |
| `github.com/Microsoft/go-winio` | 命名管道 | MIT |
| `github.com/miekg/dns` | DNS 报文处理 | BSD-3-Clause |
| Wintun | 虚拟网卡驱动（随安装包分发，不入库） | 见 wintun.net |

> **注意：`tun2socks` 是 GPL-3.0。** 本程序链接了它，因此当前整体按 GPL-3.0 对待，
> 适用于公司内部自用。若将来需要对外分发闭源版本，需要把
> `internal/tunnel` 对 `tun2socks/core` 的依赖替换为直接基于 gVisor（Apache-2.0）的实现
> —— 现有的 `handler`/`device` 已经是自写的，改动面集中在 `engine_windows.go` 里
> 装配协议栈的那几十行。

`internal/firewall/` 下的 `rules_windows.go`、`helpers_windows.go`、`types_windows*.go`、
`zsyscall_windows.go` 改编自 wireguard-windows 的 `tunnel/firewall`（MIT），
版权头与 `LICENSE.wireguard` 均已保留；CXProxy 的改动在文件头部有说明。
