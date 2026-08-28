//go:build windows

package sockopt

import (
	"fmt"
	"syscall"
)

// 标准库的 syscall 包在 Windows 上没有这两个常量（SO_MARK / IP_BOUND_IF 倒是
// linux/darwin 都有）。ws2ipdef.h 里 IP_UNICAST_IF 与 IPV6_UNICAST_IF 都是 31，
// 属于不会变的内核 ABI 编号；为这两个数把 golang.org/x/sys 提成直接依赖不划算。
const (
	ipUnicastIF   = 31
	ipv6UnicastIF = 31
)

// apply 在 Windows 上用 IP_UNICAST_IF 指定出站网卡。
//
// 能力边界与 macOS 相同：选的是网卡而不是网关，同一块网卡上的两个网关分不开，
// 用的是该网卡配置里的默认网关。Mark 字段在这里被忽略。
func apply(fd uintptr, network string, o Options) error {
	if o.IfIndex == 0 {
		return nil
	}
	h := syscall.Handle(fd)
	if isIPv6(network) {
		// IPV6_UNICAST_IF 收主机字节序，和下面的 v4 不一样
		if err := syscall.SetsockoptInt(h, syscall.IPPROTO_IPV6, ipv6UnicastIF, o.IfIndex); err != nil {
			return fmt.Errorf("设置 IPV6_UNICAST_IF=%d 失败: %w", o.IfIndex, err)
		}
		return nil
	}
	// IP_UNICAST_IF 收网络字节序，传错会得到 WSAENOBUFS 或静默失效
	if err := syscall.SetsockoptInt(h, syscall.IPPROTO_IP, ipUnicastIF, unicastIfValue(o.IfIndex)); err != nil {
		return fmt.Errorf("设置 IP_UNICAST_IF=%d 失败: %w", o.IfIndex, err)
	}
	return nil
}
