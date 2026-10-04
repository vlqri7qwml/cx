package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestParseNode(t *testing.T) {
	cases := []struct {
		in   string
		want Node
	}{
		{"socks5://u1:p1@1.2.3.4:1080", Node{Name: "1.2.3.4:1080", Host: "1.2.3.4", Port: 1080, Username: "u1", Password: "p1"}},
		{"socks5h://u1:p1@proxy.example.com:9050", Node{Name: "proxy.example.com:9050", Host: "proxy.example.com", Port: 9050, Username: "u1", Password: "p1"}},
		{"socks://1.2.3.4:1080", Node{Name: "1.2.3.4:1080", Host: "1.2.3.4", Port: 1080}},
		{"1.2.3.4:1080:user:pass", Node{Name: "1.2.3.4:1080", Host: "1.2.3.4", Port: 1080, Username: "user", Password: "pass"}},
		{"user:pass@1.2.3.4:1080", Node{Name: "1.2.3.4:1080", Host: "1.2.3.4", Port: 1080, Username: "user", Password: "pass"}},
		{"1.2.3.4:1080", Node{Name: "1.2.3.4:1080", Host: "1.2.3.4", Port: 1080}},
		{"  1.2.3.4:1080   # 休斯顿-1 ", Node{Name: "休斯顿-1", Host: "1.2.3.4", Port: 1080}},
		// 密码含 @ ：以最后一个 @ 为分界
		{"user:p@ss@1.2.3.4:1080", Node{Name: "1.2.3.4:1080", Host: "1.2.3.4", Port: 1080, Username: "user", Password: "p@ss"}},
		// 密码含 : ：host:port:user:pass 只按前三个冒号切分
		{"1.2.3.4:1080:user:pa:ss", Node{Name: "1.2.3.4:1080", Host: "1.2.3.4", Port: 1080, Username: "user", Password: "pa:ss"}},
		// 百分号转义由 url.Parse 还原
		{"socks5://user:p%40ss@1.2.3.4:1080", Node{Name: "1.2.3.4:1080", Host: "1.2.3.4", Port: 1080, Username: "user", Password: "p@ss"}},
		// IPv6 字面量
		{"socks5://[2001:db8::1]:1080", Node{Name: "[2001:db8::1]:1080", Host: "2001:db8::1", Port: 1080}},
		{"[2001:db8::1]:1080", Node{Name: "[2001:db8::1]:1080", Host: "2001:db8::1", Port: 1080}},
		// 域名形式的 host:port:user:pass
		{"gate.example.com:7000:abc:123456", Node{Name: "gate.example.com:7000", Host: "gate.example.com", Port: 7000, Username: "abc", Password: "123456"}},
	}
	for _, c := range cases {
		got, err := ParseNode(c.in)
		if err != nil {
			t.Errorf("ParseNode(%q) 返回错误: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseNode(%q)\n got  %+v\n want %+v", c.in, got, c.want)
		}
	}
}

func TestParseNodeErrors(t *testing.T) {
	bad := []string{
		"", "   ", "#只有备注",
		"1.2.3.4",                     // 缺端口
		"1.2.3.4:abc",                 // 端口非数字
		"1.2.3.4:0",                   // 端口越界
		"1.2.3.4:70000",               // 端口越界
		":1080",                       // 缺地址
		"socks4://1.2.3.4:1080",       // 不支持 SOCKS4
		"socks5://:pass@1.2.3.4:1080", // 有密码无用户名
	}
	for _, s := range bad {
		if n, err := ParseNode(s); err == nil {
			t.Errorf("ParseNode(%q) 应当失败，却得到 %+v", s, n)
		}
	}
}

func TestParseNodes(t *testing.T) {
	text := "socks5://a:b@1.1.1.1:1080 # 节点A\r\n" +
		"\n" +
		"// 注释行\n" +
		"; 另一种注释\n" +
		"2.2.2.2:1080:u:p\n" +
		"坏行\n" +
		"3.3.3.3:1080\n"
	nodes, errs := ParseNodes(text)
	if len(nodes) != 3 {
		t.Fatalf("期望解析出 3 个节点，实际 %d: %+v", len(nodes), nodes)
	}
	if nodes[0].Name != "节点A" || nodes[0].Username != "a" {
		t.Errorf("第一个节点解析有误: %+v", nodes[0])
	}
	if len(errs) != 1 {
		t.Errorf("期望 1 条错误，实际 %d: %v", len(errs), errs)
	}
}

func TestNodeStringMasksPassword(t *testing.T) {
	n := Node{Host: "1.2.3.4", Port: 1080, Username: "u", Password: "secret"}
	if got := n.String(); got != "socks5://u:***@1.2.3.4:1080" {
		t.Errorf("密码未脱敏: %s", got)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	c := Default()
	n, err := ParseNode("socks5://u:p@1.2.3.4:1080#休斯顿")
	if err != nil {
		t.Fatal(err)
	}
	c.Nodes = append(c.Nodes, n)
	c.Active = 0
	if err := c.SetPassword("Texas2026!"); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}

	got, found, err := Load(path)
	if err != nil || !found {
		t.Fatalf("Load 失败: found=%v err=%v", found, err)
	}
	if len(got.Nodes) != 1 || !got.Nodes[0].Equal(n) {
		t.Errorf("节点未正确持久化: %+v", got.Nodes)
	}
	if err := got.VerifyPassword("Texas2026!"); err != nil {
		t.Errorf("密码校验失败: %v", err)
	}
	if err := got.VerifyPassword("wrong"); err == nil {
		t.Error("错误密码竟然通过了")
	}
	if !got.AllowLAN || !got.BlockQUIC || !got.AutoConnect {
		t.Errorf("默认开关未保留: %+v", got)
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	c, found, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Error("不存在的文件不应报告 found=true")
	}
	if c.Active != -1 || len(c.DNSServers) != 2 {
		t.Errorf("默认配置不正确: %+v", c)
	}
}

func TestSanitizedAndMergeSecrets(t *testing.T) {
	c := Default()
	c.Nodes = []Node{{Host: "1.2.3.4", Port: 1080, Username: "u", Password: "real"}}
	c.Active = 0
	_ = c.SetPassword("Texas2026!")

	s := c.Sanitized()
	if s.PasswordHash != "" {
		t.Error("Sanitized 未清除管理员密码哈希")
	}
	if s.Nodes[0].Password != MaskedPassword {
		t.Errorf("Sanitized 未掩码代理密码: %q", s.Nodes[0].Password)
	}
	if c.Nodes[0].Password != "real" {
		t.Error("Sanitized 不应修改原配置")
	}

	// 界面把掩码原样提交回来时，服务端必须保留原密码。
	s.MergeSecrets(c)
	if s.Nodes[0].Password != "real" {
		t.Errorf("MergeSecrets 未回填原密码: %q", s.Nodes[0].Password)
	}
}

func TestPasswordStrength(t *testing.T) {
	for _, bad := range []string{"short1", "12345678", "abcdefgh", " Texas2026! "} {
		if err := CheckPasswordStrength(bad); err == nil {
			t.Errorf("弱密码 %q 应被拒绝", bad)
		}
	}
	for _, good := range []string{"Texas2026", "cx-proxy!!", "强密码2026年"} {
		if err := CheckPasswordStrength(good); err != nil {
			t.Errorf("密码 %q 应被接受: %v", good, err)
		}
	}
}

func TestThrottleLocksAfterFiveFailures(t *testing.T) {
	c := Default()
	if err := c.SetPassword("Texas2026!"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	th := NewThrottle()
	th.now = func() time.Time { return now }

	for i := 0; i < 5; i++ {
		if err := th.Verify(c, "wrong"); err == nil {
			t.Fatalf("第 %d 次错误密码竟然通过", i+1)
		}
	}
	// 第 5 次失败后应被锁定，即使密码正确也拒绝。
	if err := th.Verify(c, "Texas2026!"); err == nil {
		t.Fatal("锁定期内正确密码也应被拒绝")
	}
	if ok, d := th.Allow(); ok || d <= 0 {
		t.Fatalf("Allow 应报告锁定中: ok=%v d=%v", ok, d)
	}
	// 锁定期过后恢复。
	now = now.Add(61 * time.Second)
	if err := th.Verify(c, "Texas2026!"); err != nil {
		t.Fatalf("锁定期过后应允许: %v", err)
	}
}

func TestVerifyWithoutPassword(t *testing.T) {
	if err := Default().VerifyPassword("x"); err != ErrNoPassword {
		t.Errorf("未设置密码时应返回 ErrNoPassword，实际 %v", err)
	}
}
