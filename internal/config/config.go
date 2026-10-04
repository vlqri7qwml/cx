// Package config 负责 CXProxy 的配置持久化与代理地址解析。
//
// 配置文件固定存放于 %ProgramData%\CXProxy\config.json，并通过 DACL 收紧为
// 仅 SYSTEM 与 Administrators 可读写：普通用户只能经由服务的命名管道读取
// 经过脱敏的配置，拿不到代理明文密码。
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// CurrentVersion 为配置结构版本，便于以后迁移。
const CurrentVersion = 1

// 默认 TUN 网段：172.19.0.1/30，网关侧 .1，DNS 劫持地址 .2。
const (
	DefaultTunName    = "CXProxy"
	DefaultTunAddr    = "172.19.0.1"
	DefaultTunPrefix  = 30
	DefaultTunDNS     = "172.19.0.2"
	DefaultTunMTU     = 1420
	DefaultPipeName   = `\\.\pipe\cxproxy`
	DefaultServiceKey = "CXProxy"
)

// Config 是落盘的全部配置。
type Config struct {
	Version int `json:"version"`

	// Nodes 为可选的 SOCKS5 节点列表，Active 指向当前使用的节点。
	Nodes  []Node `json:"nodes"`
	Active int    `json:"active"`

	// AutoConnect 为 true 时服务启动即自动连接 Active 节点。
	AutoConnect bool `json:"auto_connect"`

	// AllowLAN 为 true 时断网保护放行 RFC1918 私有网段（打印机、NAS、内网办公系统）。
	AllowLAN bool `json:"allow_lan"`

	// BlockQUIC 为 true 时丢弃 UDP/443，迫使浏览器回落 TCP，住宅代理下更稳定。
	BlockQUIC bool `json:"block_quic"`

	// DNSServers 为上游 DNS，查询统一经 SOCKS5 以 TCP 发出。
	DNSServers []string `json:"dns_servers"`

	// PasswordHash 为管理员密码的 bcrypt 哈希；为空表示尚未设置。
	PasswordHash string `json:"password_hash"`

	TunName  string `json:"tun_name"`
	LogLevel string `json:"log_level"`
}

// Default 返回带安全默认值的配置。
func Default() *Config {
	return &Config{
		Version:     CurrentVersion,
		Active:      -1,
		AutoConnect: true,
		AllowLAN:    true,
		BlockQUIC:   true,
		DNSServers:  []string{"8.8.8.8", "1.1.1.1"},
		TunName:     DefaultTunName,
		LogLevel:    "info",
	}
}

// ActiveNode 返回当前选中的节点。
func (c *Config) ActiveNode() (Node, bool) {
	if c.Active < 0 || c.Active >= len(c.Nodes) {
		return Node{}, false
	}
	return c.Nodes[c.Active], true
}

// Sanitized 返回可以安全交给普通用户界面的副本：代理密码被替换为掩码，
// 管理员密码哈希被清空。IPC 回传配置时一律走这个方法。
func (c *Config) Sanitized() *Config {
	cp := *c
	cp.PasswordHash = ""
	cp.Nodes = make([]Node, len(c.Nodes))
	copy(cp.Nodes, c.Nodes)
	for i := range cp.Nodes {
		if cp.Nodes[i].Password != "" {
			cp.Nodes[i].Password = MaskedPassword
		}
	}
	cp.DNSServers = append([]string(nil), c.DNSServers...)
	return &cp
}

// MaskedPassword 是脱敏占位符。界面提交配置时若某节点密码仍为该占位符，
// 服务端会保留原密码，避免界面把掩码写回配置。
const MaskedPassword = "\x00__CXPROXY_KEEP__"

// MergeSecrets 把 old 中的真实密码回填到 c 中仍为掩码占位符的节点上。
func (c *Config) MergeSecrets(old *Config) {
	for i := range c.Nodes {
		if c.Nodes[i].Password != MaskedPassword {
			continue
		}
		c.Nodes[i].Password = ""
		for _, o := range old.Nodes {
			if o.Host == c.Nodes[i].Host && o.Port == c.Nodes[i].Port && o.Username == c.Nodes[i].Username {
				c.Nodes[i].Password = o.Password
				break
			}
		}
	}
}

// Normalize 修正越界与空字段，使配置始终可用。
func (c *Config) Normalize() {
	if c.Version == 0 {
		c.Version = CurrentVersion
	}
	if c.TunName == "" {
		c.TunName = DefaultTunName
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if len(c.DNSServers) == 0 {
		c.DNSServers = []string{"8.8.8.8", "1.1.1.1"}
	}
	if len(c.Nodes) == 0 {
		c.Active = -1
		return
	}
	if c.Active < 0 || c.Active >= len(c.Nodes) {
		c.Active = 0
	}
	for i := range c.Nodes {
		if c.Nodes[i].Name == "" {
			c.Nodes[i].Name = c.Nodes[i].Addr()
		}
	}
}

// Validate 校验配置是否可以保存。
func (c *Config) Validate() error {
	for i, n := range c.Nodes {
		if _, err := finish(n); err != nil {
			return fmt.Errorf("第 %d 个节点 %q: %w", i+1, n.Label(), err)
		}
	}
	for _, s := range c.DNSServers {
		if _, _, err := splitHostPort(s + ":53"); err != nil {
			return fmt.Errorf("DNS 服务器 %q 不合法", s)
		}
	}
	return nil
}

// Dir 返回配置目录：%ProgramData%\CXProxy。
func Dir() string {
	if v := os.Getenv("CXPROXY_DIR"); v != "" {
		return v
	}
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "CXProxy")
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "CXProxy")
	}
	return filepath.Join(os.TempDir(), "CXProxy")
}

// Path 返回配置文件完整路径。
func Path() string { return filepath.Join(Dir(), "config.json") }

// LogDir 返回服务日志目录。该目录对普通用户只读，便于员工取日志给 IT。
func LogDir() string { return filepath.Join(Dir(), "logs") }

// ServiceLogPath 返回服务日志文件路径。
func ServiceLogPath() string { return filepath.Join(LogDir(), "cxproxy.log") }

// UserLogPath 返回托盘日志文件路径。
//
// 托盘以普通用户身份运行，写不进 %ProgramData%\CXProxy（那里只有 SYSTEM
// 与管理员可写），因此托盘日志落在用户自己的 LocalAppData 下。
func UserLogPath() string {
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, "CXProxy", "tray.log")
	}
	return filepath.Join(os.TempDir(), "CXProxy", "tray.log")
}

var saveMu sync.Mutex

// Load 读取配置；文件不存在时返回默认配置且 found 为 false。
func Load(path string) (cfg *Config, found bool, err error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), false, nil
	}
	if err != nil {
		return Default(), false, err
	}
	c := Default()
	if err := json.Unmarshal(b, c); err != nil {
		return Default(), true, fmt.Errorf("配置文件解析失败 %s: %w", path, err)
	}
	c.Normalize()
	return c, true, nil
}

// Save 原子写入配置，并收紧目录与文件权限。
func Save(path string, c *Config) error {
	saveMu.Lock()
	defer saveMu.Unlock()

	c.Normalize()
	if err := c.Validate(); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := secureDir(dir); err != nil {
		return fmt.Errorf("设置配置目录权限失败: %w", err)
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := secureFile(tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("设置配置文件权限失败: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
