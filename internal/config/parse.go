package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Node 描述一个 SOCKS5 出口节点。
type Node struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// NoUDP 为 true 时不尝试 UDP ASSOCIATE（部分住宅代理不支持）。
	NoUDP bool `json:"no_udp,omitempty"`
}

// Addr 返回可直接用于 net.Dial 的 host:port。
func (n Node) Addr() string {
	return net.JoinHostPort(n.Host, strconv.Itoa(n.Port))
}

// Label 返回界面上显示的名称。
func (n Node) Label() string {
	if n.Name != "" {
		return n.Name
	}
	return n.Addr()
}

// Equal 用于判断两个节点在网络意义上是否一致（忽略备注名）。
func (n Node) Equal(o Node) bool {
	return n.Host == o.Host && n.Port == o.Port &&
		n.Username == o.Username && n.Password == o.Password && n.NoUDP == o.NoUDP
}

// String 返回 socks5:// 形式，密码以 *** 掩码，可安全写入日志。
func (n Node) String() string {
	if n.Username != "" {
		return fmt.Sprintf("socks5://%s:***@%s", n.Username, n.Addr())
	}
	return "socks5://" + n.Addr()
}

var errEmptyLine = errors.New("空行")

// ParseNode 解析一行代理配置，支持以下写法（可带 #备注）：
//
//	socks5://user:pass@host:port
//	socks5h://user:pass@host:port
//	host:port:user:pass
//	user:pass@host:port
//	host:port
//
// 密码中含有 @ 或 : 也能正确解析：userinfo 以最后一个 @ 为界，
// host:port:user:pass 形式只按前三个 : 切分。
func ParseNode(line string) (Node, error) {
	var n Node

	s := strings.TrimSpace(line)
	if s == "" {
		return n, errEmptyLine
	}
	// 剥离备注。
	if i := strings.IndexByte(s, '#'); i >= 0 {
		n.Name = strings.TrimSpace(s[i+1:])
		s = strings.TrimSpace(s[:i])
	}
	if s == "" {
		return n, errEmptyLine
	}

	// 剥离协议头。
	lower := strings.ToLower(s)
	for _, scheme := range []string{"socks5h://", "socks5://", "socks://", "socks4://"} {
		if strings.HasPrefix(lower, scheme) {
			if scheme == "socks4://" {
				return n, errors.New("不支持 SOCKS4，请使用 SOCKS5")
			}
			// 优先交给 url.Parse，可正确处理百分号转义。
			if u, err := url.Parse(s); err == nil && u.Host != "" {
				host, port, perr := splitHostPort(u.Host)
				if perr != nil {
					return n, perr
				}
				n.Host, n.Port = host, port
				if u.User != nil {
					n.Username = u.User.Username()
					n.Password, _ = u.User.Password()
				}
				return finish(n)
			}
			s = s[len(scheme):]
			lower = strings.ToLower(s)
			break
		}
	}

	if at := strings.LastIndexByte(s, '@'); at >= 0 {
		// user:pass@host:port
		userinfo, hostport := s[:at], s[at+1:]
		user, pass := userinfo, ""
		if i := strings.IndexByte(userinfo, ':'); i >= 0 {
			user, pass = userinfo[:i], userinfo[i+1:]
		}
		host, port, err := splitHostPort(hostport)
		if err != nil {
			return n, err
		}
		n.Host, n.Port, n.Username, n.Password = host, port, user, pass
		return finish(n)
	}

	// host:port:user:pass —— 仅当第二段是合法端口时才这样解释。
	if parts := strings.SplitN(s, ":", 4); len(parts) == 4 {
		if p, err := parsePort(parts[1]); err == nil {
			n.Host, n.Port, n.Username, n.Password = parts[0], p, parts[2], parts[3]
			return finish(n)
		}
	}

	host, port, err := splitHostPort(s)
	if err != nil {
		return n, err
	}
	n.Host, n.Port = host, port
	return finish(n)
}

func finish(n Node) (Node, error) {
	n.Host = strings.TrimSpace(n.Host)
	if n.Host == "" {
		return n, errors.New("缺少代理地址")
	}
	if strings.ContainsAny(n.Host, " \t") {
		return n, fmt.Errorf("代理地址含非法字符: %q", n.Host)
	}
	if n.Port <= 0 || n.Port > 65535 {
		return n, fmt.Errorf("端口不合法: %d", n.Port)
	}
	if n.Username == "" && n.Password != "" {
		return n, errors.New("填写了密码但缺少用户名")
	}
	if n.Name == "" {
		n.Name = n.Addr()
	}
	return n, nil
}

func splitHostPort(s string) (string, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, errors.New("缺少代理地址")
	}
	// IPv6 字面量必须写成 [::1]:1080。
	if strings.HasPrefix(s, "[") {
		h, p, err := net.SplitHostPort(s)
		if err != nil {
			return "", 0, fmt.Errorf("地址格式错误 %q: %w", s, err)
		}
		port, err := parsePort(p)
		if err != nil {
			return "", 0, err
		}
		return h, port, nil
	}
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", 0, fmt.Errorf("缺少端口: %q", s)
	}
	port, err := parsePort(s[i+1:])
	if err != nil {
		return "", 0, err
	}
	return s[:i], port, nil
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("端口不是数字: %q", s)
	}
	if p <= 0 || p > 65535 {
		return 0, fmt.Errorf("端口超出范围: %d", p)
	}
	return p, nil
}

// ParseNodes 批量解析（每行一条），返回解析成功的节点与逐行错误。
// 空行与以 // 、; 开头的注释行会被忽略。
func ParseNodes(text string) ([]Node, []error) {
	var (
		nodes []Node
		errs  []error
	)
	for i, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "//") || strings.HasPrefix(t, ";") {
			continue
		}
		n, err := ParseNode(line)
		if err != nil {
			if !errors.Is(err, errEmptyLine) {
				errs = append(errs, fmt.Errorf("第 %d 行: %w", i+1, err))
			}
			continue
		}
		nodes = append(nodes, n)
	}
	return nodes, errs
}
