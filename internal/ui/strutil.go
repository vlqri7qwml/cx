package ui

import (
	"fmt"
	"strings"
)

// splitList 把逗号/分号/空白分隔的列表拆开。
func splitList(s string) []string {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '，' || r == '；'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}

// joinErrors 把逐行错误拼成提示文本，最多显示 max 条。
func joinErrors(errs []error, max int) string {
	var b strings.Builder
	for i, err := range errs {
		if i >= max {
			fmt.Fprintf(&b, "…… 另有 %d 行存在问题", len(errs)-max)
			break
		}
		b.WriteString("• ")
		b.WriteString(err.Error())
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}
