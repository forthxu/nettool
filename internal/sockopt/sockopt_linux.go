//go:build linux

package sockopt

import (
	"fmt"
	"math"
	"syscall"
)

// apply 在 Linux 上打 SO_MARK（配合 ip rule 策略路由，能区分同一块网卡上的
// 多个网关）和 SO_BINDTODEVICE（没有 ip rule 时的降级手段，只能按网卡区分）。
func apply(fd uintptr, network string, o Options) error {
	if o.Mark != 0 {
		// SetsockoptInt 收的是 int，32 位路由器（mips/arm）上 int 只有 32 位。
		// 本程序分配的 mark 上限是 0x7F000000，落在范围内；这里兜住外部传进来的
		// 异常值，免得在 mips 上悄悄溢出成负数。
		if o.Mark > math.MaxInt32 {
			return fmt.Errorf("mark 0x%08x 超出本平台可设置的范围", o.Mark)
		}
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(o.Mark)); err != nil {
			return fmt.Errorf("设置 SO_MARK 0x%08x 失败（需要 root 或 CAP_NET_ADMIN）: %w", o.Mark, err)
		}
	}
	if o.IfName != "" {
		if err := syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, o.IfName); err != nil {
			return fmt.Errorf("绑定网卡 %s 失败（需要 root 或 CAP_NET_RAW）: %w", o.IfName, err)
		}
	}
	// IfIndex 在 Linux 上用不着：SO_BINDTODEVICE 认的是网卡名而不是索引
	return nil
}
