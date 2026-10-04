// Package logx 提供一个带体积轮转的简易日志器。
//
// 服务以 LocalSystem 身份长期运行，日志必须落盘才能排障；
// 同时不能无限增长把客户机磁盘写满，因此按体积轮转并只保留少量历史。
package logx

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// 默认轮转参数。
const (
	DefaultMaxSize = 4 << 20 // 4 MiB
	DefaultKeep    = 3       // 另外保留 3 个历史文件
)

// Logger 是一个并发安全的日志器。
type Logger struct {
	mu      sync.Mutex
	path    string
	file    *os.File
	size    int64
	maxSize int64
	keep    int
	extra   io.Writer // 额外输出（例如控制台）
	now     func() time.Time
}

// Options 控制日志器行为。
type Options struct {
	// Path 为日志文件路径；为空表示只写 Extra。
	Path string
	// MaxSize 为单文件上限，0 取默认值。
	MaxSize int64
	// Keep 为保留的历史文件个数，0 取默认值，负数表示不保留历史。
	Keep int
	// Extra 为额外输出目标，可为 nil。
	Extra io.Writer
}

// New 创建日志器。即便无法写文件（权限不足等）也会返回可用的实例，
// 以免服务因为日志问题起不来。
func New(opts Options) (*Logger, error) {
	l := &Logger{
		path:    opts.Path,
		maxSize: opts.MaxSize,
		keep:    opts.Keep,
		extra:   opts.Extra,
		now:     time.Now,
	}
	if l.maxSize <= 0 {
		l.maxSize = DefaultMaxSize
	}
	if l.keep == 0 {
		l.keep = DefaultKeep
	}
	if l.path == "" {
		return l, nil
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return l, err
	}
	if err := l.open(); err != nil {
		return l, err
	}
	return l, nil
}

func (l *Logger) open() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.file = f
	l.size = info.Size()
	return nil
}

// Printf 写入一行日志（自动补时间戳与换行）。
func (l *Logger) Printf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	l.mu.Lock()
	defer l.mu.Unlock()

	stamp := l.now().Format("2006-01-02 15:04:05.000")
	out := stamp + " " + line
	if len(out) == 0 || out[len(out)-1] != '\n' {
		out += "\n"
	}

	if l.extra != nil {
		_, _ = io.WriteString(l.extra, out)
	}
	if l.file == nil {
		return
	}
	if l.size+int64(len(out)) > l.maxSize {
		l.rotateLocked()
	}
	n, err := io.WriteString(l.file, out)
	if err == nil {
		l.size += int64(n)
	}
}

// rotateLocked 轮转日志文件。调用方必须已持有锁。
func (l *Logger) rotateLocked() {
	_ = l.file.Close()
	l.file = nil

	if l.keep > 0 {
		// cxproxy.log.2 -> cxproxy.log.3，依次后移，最旧的被覆盖。
		oldest := fmt.Sprintf("%s.%d", l.path, l.keep)
		_ = os.Remove(oldest)
		for i := l.keep - 1; i >= 1; i-- {
			_ = os.Rename(fmt.Sprintf("%s.%d", l.path, i), fmt.Sprintf("%s.%d", l.path, i+1))
		}
		_ = os.Rename(l.path, l.path+".1")
	} else {
		_ = os.Remove(l.path)
	}
	// 重新打开；失败则退化为只写 Extra。
	_ = l.open()
}

// Close 关闭底层文件。
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

// Path 返回日志文件路径。
func (l *Logger) Path() string { return l.path }
