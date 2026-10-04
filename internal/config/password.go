package config

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// 密码策略：最短 8 位，且至少包含两类字符，避免 "12345678" 这类口令。
const minPasswordLen = 8

// ErrNoPassword 表示尚未设置管理员密码。
var ErrNoPassword = errors.New("尚未设置管理员密码")

// ErrBadPassword 表示密码错误。
var ErrBadPassword = errors.New("管理员密码错误")

// ErrLocked 表示因连续输错而被临时锁定。
var ErrLocked = errors.New("密码连续输错次数过多，请稍后再试")

// CheckPasswordStrength 校验新密码是否满足最低复杂度要求。
func CheckPasswordStrength(pw string) error {
	if len([]rune(pw)) < minPasswordLen {
		return fmt.Errorf("密码至少需要 %d 位", minPasswordLen)
	}
	if strings.TrimSpace(pw) != pw {
		return errors.New("密码首尾不能有空格")
	}
	var hasLetter, hasDigit, hasOther bool
	for _, r := range pw {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasOther = true
		}
	}
	classes := 0
	for _, ok := range []bool{hasLetter, hasDigit, hasOther} {
		if ok {
			classes++
		}
	}
	if classes < 2 {
		return errors.New("密码需同时包含字母与数字（或符号）")
	}
	return nil
}

// SetPassword 设置管理员密码（写入 bcrypt 哈希）。
func (c *Config) SetPassword(pw string) error {
	if err := CheckPasswordStrength(pw); err != nil {
		return err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	c.PasswordHash = string(h)
	return nil
}

// HasPassword 返回是否已设置管理员密码。
func (c *Config) HasPassword() bool { return c.PasswordHash != "" }

// VerifyPassword 校验密码。未设置密码时返回 ErrNoPassword。
func (c *Config) VerifyPassword(pw string) error {
	if !c.HasPassword() {
		return ErrNoPassword
	}
	if err := bcrypt.CompareHashAndPassword([]byte(c.PasswordHash), []byte(pw)); err != nil {
		return ErrBadPassword
	}
	return nil
}

// Throttle 限制密码尝试频率：连续 MaxFailures 次失败后锁定 LockFor。
// 服务端在处理每个需要密码的 IPC 请求前都会经过它，避免暴力枚举。
type Throttle struct {
	MaxFailures int
	LockFor     time.Duration

	mu       sync.Mutex
	failures int
	until    time.Time
	now      func() time.Time // 便于测试
}

// NewThrottle 返回默认策略：连续 5 次错误锁定 60 秒。
func NewThrottle() *Throttle {
	return &Throttle{MaxFailures: 5, LockFor: 60 * time.Second}
}

func (t *Throttle) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

// Allow 返回当前是否允许尝试，以及剩余锁定时长。
func (t *Throttle) Allow() (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if d := t.until.Sub(t.clock()); d > 0 {
		return false, d
	}
	return true, 0
}

// Verify 在限速保护下校验密码。
func (t *Throttle) Verify(c *Config, pw string) error {
	if ok, d := t.Allow(); !ok {
		return fmt.Errorf("%w（还需等待 %d 秒）", ErrLocked, int(d.Seconds())+1)
	}
	err := c.VerifyPassword(pw)

	t.mu.Lock()
	defer t.mu.Unlock()
	if err != nil {
		t.failures++
		if t.MaxFailures > 0 && t.failures >= t.MaxFailures {
			t.failures = 0
			t.until = t.clock().Add(t.LockFor)
		}
		return err
	}
	t.failures = 0
	t.until = time.Time{}
	return nil
}
