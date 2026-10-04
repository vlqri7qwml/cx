package ui

import (
	"errors"
	"strings"
	"testing"
)

func TestSplitList(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"8.8.8.8, 1.1.1.1", []string{"8.8.8.8", "1.1.1.1"}},
		{"8.8.8.8;1.1.1.1", []string{"8.8.8.8", "1.1.1.1"}},
		{" 8.8.8.8 \t 1.1.1.1 \n", []string{"8.8.8.8", "1.1.1.1"}},
		// 中文输入法下的全角逗号/分号也要能用
		{"8.8.8.8，1.1.1.1；9.9.9.9", []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"}},
		{"", nil},
		{"   ,, ;; ", nil},
		{"8.8.8.8:53", []string{"8.8.8.8:53"}},
	}
	for _, c := range cases {
		got := splitList(c.in)
		if len(got) != len(c.want) {
			t.Errorf("splitList(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("splitList(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("短文本", 10); got != "短文本" {
		t.Errorf("未超长不应截断，实际 %q", got)
	}
	got := truncate("一二三四五六七八九十", 5)
	if r := []rune(got); len(r) != 5 {
		t.Errorf("截断后应为 5 个字符，实际 %d (%q)", len(r), got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("截断后应以省略号结尾，实际 %q", got)
	}
	// 按 rune 截断，不能把多字节字符切坏。
	if !strings.HasPrefix(got, "一二三四") {
		t.Errorf("截断位置不对: %q", got)
	}
}

func TestJoinErrors(t *testing.T) {
	errs := []error{
		errors.New("第 1 行: 缺少端口"),
		errors.New("第 2 行: 端口不是数字"),
		errors.New("第 3 行: 缺少代理地址"),
	}
	got := joinErrors(errs, 10)
	for _, e := range errs {
		if !strings.Contains(got, e.Error()) {
			t.Errorf("输出缺少 %q: %q", e.Error(), got)
		}
	}
	if strings.HasSuffix(got, "\n") {
		t.Error("末尾不应有多余换行")
	}

	limited := joinErrors(errs, 2)
	if !strings.Contains(limited, "另有 1 行存在问题") {
		t.Errorf("超出上限时应提示剩余条数，实际 %q", limited)
	}
	if strings.Contains(limited, "第 3 行") {
		t.Errorf("超出上限的条目不应显示: %q", limited)
	}

	if got := joinErrors(nil, 5); got != "" {
		t.Errorf("无错误时应返回空串，实际 %q", got)
	}
}
