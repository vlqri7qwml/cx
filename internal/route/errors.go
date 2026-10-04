package route

import "errors"

// errorsAs 是 errors.As 的薄封装，便于在 Windows 专属文件里保持简洁。
func errorsAs(err error, target any) bool { return errors.As(err, target) }
