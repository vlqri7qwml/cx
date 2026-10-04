package logx

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrintfWritesFileAndExtra(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cxproxy.log")
	var buf bytes.Buffer

	l, err := New(Options{Path: path, Extra: &buf})
	if err != nil {
		t.Fatal(err)
	}
	l.now = func() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC) }
	l.Printf("连接到 %s", "1.2.3.4:1080")
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if !strings.Contains(got, "连接到 1.2.3.4:1080") {
		t.Errorf("文件内容不含日志正文: %q", got)
	}
	if !strings.HasPrefix(got, "2026-10-04 12:00:00.000 ") {
		t.Errorf("缺少时间戳: %q", got)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Error("未补换行")
	}
	if buf.String() != got {
		t.Errorf("Extra 输出与文件不一致: %q vs %q", buf.String(), got)
	}
}

func TestRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cxproxy.log")

	l, err := New(Options{Path: path, MaxSize: 200, Keep: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	for i := 0; i < 40; i++ {
		l.Printf("第 %02d 行日志内容填充填充填充填充", i)
	}

	for _, name := range []string{"cxproxy.log", "cxproxy.log.1", "cxproxy.log.2"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("期望存在 %s: %v", name, err)
		}
	}
	// 只保留 2 个历史文件。
	if _, err := os.Stat(filepath.Join(dir, "cxproxy.log.3")); err == nil {
		t.Error("cxproxy.log.3 不应存在（Keep=2）")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 400 {
		t.Errorf("当前日志文件未按上限轮转，大小 %d", info.Size())
	}
}

func TestNoPathOnlyExtra(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(Options{Extra: &buf})
	if err != nil {
		t.Fatal(err)
	}
	l.Printf("只写控制台")
	if !strings.Contains(buf.String(), "只写控制台") {
		t.Errorf("Extra 未收到日志: %q", buf.String())
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if l.Path() != "" {
		t.Errorf("Path 应为空，实际 %q", l.Path())
	}
}

func TestNewReturnsUsableLoggerOnError(t *testing.T) {
	// 指向一个不可能创建成功的路径：仍应返回可用实例，只是报错。
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := New(Options{Path: filepath.Join(blocker, "sub", "a.log")})
	if err == nil {
		t.Skip("该平台允许在文件下创建目录，跳过")
	}
	if l == nil {
		t.Fatal("出错时也应返回非 nil 的 Logger")
	}
	l.Printf("不应 panic")
	_ = l.Close()
}
