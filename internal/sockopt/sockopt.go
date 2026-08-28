// Package sockopt 给出站 socket 打上「走哪条出口线路」的平台相关标记，
// 供 net.Dialer.Control 使用。
//
// 本仓库其余地方一律用 runtime.GOOS 分支做平台适配（见 route/oscmd.go、
// netconfig/nic.go），那套写法对「拼命令行」有效，因为 exec.Command 是跨平台的。
// 这里不行：syscall.SO_MARK 在 darwin 的构建里根本不存在，syscall.IP_BOUND_IF
// 在 linux 的构建里也不存在，它们是编译期标识符而不是运行期取值。所以这个包
// 是全仓库唯一使用 build tag 的地方，不是惯例被随手放弃了。
//
// 各平台的能力并不对等，调用方必须如实告诉用户：
//   - linux：SO_MARK 配合 ip rule 策略路由，能区分同一块网卡上的不同网关
//   - darwin：IP_BOUND_IF 只能选网卡，但配合 Egress 里的源端口段 + PF 的
//     route-to（见 internal/uplink 的 ModePFRouteTo）同样能区分同网卡的两个网关
//   - windows：只能把 socket 绑到某块网卡，同一块网卡上的两个网关分不开
package sockopt

import (
	"fmt"
	"math/bits"
	"strings"
	"syscall"
)

// Options 是要打到一个出站 socket 上的标记。零值表示什么都不做，
// 此时 Control 返回 nil，拨号路径与没有这个包时逐字节一致。
type Options struct {
	Mark    uint32 // linux SO_MARK；0 表示不设
	IfName  string // linux SO_BINDTODEVICE；空表示不设
	IfIndex int    // darwin IP_BOUND_IF / windows IP_UNICAST_IF；0 表示不设
}

func (o Options) Empty() bool {
	return o.Mark == 0 && o.IfName == "" && o.IfIndex == 0
}

// String 供日志与界面展示，说明这个 socket 实际被怎么标记了
func (o Options) String() string {
	if o.Empty() {
		return "默认线路"
	}
	var parts []string
	if o.Mark != 0 {
		parts = append(parts, fmt.Sprintf("mark=0x%08x", o.Mark))
	}
	if o.IfName != "" {
		parts = append(parts, "dev="+o.IfName)
	}
	if o.IfIndex != 0 {
		parts = append(parts, fmt.Sprintf("ifindex=%d", o.IfIndex))
	}
	return strings.Join(parts, " ")
}

// Control 返回可直接赋给 net.Dialer.Control 的函数；Options 为零值时返回 nil。
//
// 这里的错误一定要往上抛，不能吞掉：setsockopt 失败（最常见的是没有
// CAP_NET_ADMIN）意味着这个连接会从默认网关出去，而用户以为它走的是别的线路。
// 宁可拨号失败，也不要静默走错线路。
//
// 标准库在 socket() 之后、bind()/connect() 之前调用 Control（见
// $GOROOT/src/net/sock_posix.go 的 socket()），所以设置在此处一定赶得上。
func Control(o Options) func(network, address string, c syscall.RawConn) error {
	if o.Empty() {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var applyErr error
		if err := c.Control(func(fd uintptr) {
			applyErr = apply(fd, network, o)
		}); err != nil {
			return err
		}
		return applyErr
	}
}

// isIPv6 判断这个 socket 是不是 IPv6。标准库传进 Control 的 network 来自
// fd.ctrlNetwork()，对 tcp/udp/ip 一定带上了 "4" 或 "6" 后缀，不用猜。
func isIPv6(network string) bool {
	return strings.HasSuffix(network, "6")
}

// unicastIfValue 把网卡索引转成 Windows IP_UNICAST_IF 需要的网络字节序表示。
// IPV6_UNICAST_IF 用的却是主机字节序，两者不一样，别混。搞错的话轻则静默失效，
// 重则 connect 时报 WSAENOBUFS。
//
// 放在无 build tag 的文件里是为了能在开发机（macOS）上跑单测。Windows 支持的
// 全部 GOARCH 都是小端，所以整字节反转就等于转网络字节序。
func unicastIfValue(idx int) int {
	return int(bits.ReverseBytes32(uint32(idx)))
}
