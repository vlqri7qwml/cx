// Package firewall 用 Windows Filtering Platform (WFP) 实现 CXProxy 的断网保护。
//
// 设计要点：
//
//   - 规则是“持久化”的（FWPM_FILTER_FLAG_PERSISTENT）。这意味着规则随 Windows
//     基础筛选引擎 (BFE) 启动即生效，并且在 cxproxy 进程崩溃、被任务管理器结束、
//     服务被停止、甚至整机重启之后依然存在。这正是“代理没开就没有网”的根基：
//     阻断规则不依赖任何进程活着。
//   - 规则全部挂在同一个固定 GUID 的 sublayer 下。WFP 的仲裁是按 sublayer 分别
//     取胜者、任一 sublayer 阻断即阻断，因此放行规则必须与 blockAll 同层，
//     否则放行不会生效。TUN 接口的动态放行规则也因此写入同一个 sublayer。
//   - Enable 在一个 WFP 事务里先删旧规则再装新规则，既可重复执行，
//     又不会在切换过程中出现“短暂放行”的泄露窗口。
//   - Disable 按固定 filterKey 逐条删除，是唯一恢复直连的途径，
//     对应托盘里输入管理员密码后的「退出」，以及应急命令 cxproxy.exe unblock。
//
// 本包仅在 Windows 下有实现；其余平台编译为空包，以便 go build ./... 可跨平台执行。
package firewall
