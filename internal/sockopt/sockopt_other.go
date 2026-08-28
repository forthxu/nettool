//go:build !linux && !darwin && !windows

package sockopt

import (
	"fmt"
	"runtime"
)

// apply 兜底：Makefile 里没有这些目标，但保证 GOOS=freebsd 之类仍能编译通过。
// 错误往上抛而不是静默放行——静默意味着用户以为走了指定线路，实际走的是默认网关。
func apply(fd uintptr, network string, o Options) error {
	return fmt.Errorf("本平台（%s）不支持把 socket 绑定到指定出口线路", runtime.GOOS)
}
