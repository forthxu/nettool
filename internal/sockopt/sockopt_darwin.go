//go:build darwin

package sockopt

import (
	"fmt"
	"syscall"
)

// apply 在 macOS 上用 IP_BOUND_IF 把 socket 锁进某块网卡的作用域，效果与
// 路由表里的 -ifscope 一致（见 route/oscmd.go 里对 -ifscope 的说明）。
//
// 能力边界：这只能选网卡，不能选网关。同一块网卡上配了两个网关时，走的仍是
// 该网卡自己那条默认路由——macOS 没有 SO_MARK，也没有 ip rule。上层必须把这个
// 限制如实告诉用户，不能假装和 Linux 对等。Mark 字段在这里被忽略。
func apply(fd uintptr, network string, o Options) error {
	if o.IfIndex == 0 {
		return nil
	}
	level, opt, name := syscall.IPPROTO_IP, syscall.IP_BOUND_IF, "IP_BOUND_IF"
	if isIPv6(network) {
		level, opt, name = syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF, "IPV6_BOUND_IF"
	}
	if err := syscall.SetsockoptInt(int(fd), level, opt, o.IfIndex); err != nil {
		return fmt.Errorf("设置 %s=%d 失败: %w", name, o.IfIndex, err)
	}
	return nil
}
