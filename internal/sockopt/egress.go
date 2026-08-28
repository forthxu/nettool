package sockopt

// 出站连接的完整"怎么出去"描述，以及按它拨号的辅助类型。
//
// 为什么源端口也是出口的一部分：macOS 没有 fwmark，区分实例只能靠包本身带的
// 信息。源 IP 分不开同一块网卡上的两个网关（它们共用一个源 IP），能分开的只剩
// **源端口**——给每个实例划一段专属端口，再让 PF 按端口段把包 route-to 到指定
// 网关。所以在那条路径上，"绑定段内的某个源端口"和"打 SO_MARK"是同一件事的
// 两种平台实现，都必须在拨号时施加，见 internal/uplink 的 ModePFRouteTo。

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
)

// Egress 是一条出站连接要施加的全部出口约束。零值表示什么都不做，
// 拨号路径与没有这个包时逐字节一致。
type Egress struct {
	// Options 是 setsockopt 层面的绑定（mark / 网卡）
	Options Options
	// SourceIP 是要绑定的本机源地址，空表示由内核挑
	SourceIP string
	// PortStart/PortEnd 是本实例专属的源端口段（闭区间），0 表示不限定，
	// 由内核分配临时端口。设了端口段就必须同时给出 SourceIP——PF 规则是按
	// "源 IP + 源端口段"匹配的，少一半就匹配不上，流量会从默认网关漏出去。
	PortStart int
	PortEnd   int
}

func (e Egress) Empty() bool {
	return e.Options.Empty() && e.SourceIP == "" && e.PortStart == 0
}

// String 供日志与界面展示
func (e Egress) String() string {
	if e.Empty() {
		return "默认线路"
	}
	var parts []string
	if !e.Options.Empty() {
		parts = append(parts, e.Options.String())
	}
	if e.SourceIP != "" {
		parts = append(parts, "src="+e.SourceIP)
	}
	if e.PortStart != 0 {
		parts = append(parts, fmt.Sprintf("sport=%d-%d", e.PortStart, e.PortEnd))
	}
	return strings.Join(parts, " ")
}

// Validate 检查这份出口约束自身是否自洽
func (e Egress) Validate() error {
	if e.SourceIP != "" && net.ParseIP(e.SourceIP) == nil {
		return fmt.Errorf("出口源地址 %q 不是合法的 IP", e.SourceIP)
	}
	if e.PortStart == 0 && e.PortEnd == 0 {
		return nil
	}
	// 下界取 1024：低端口要特权，而且都是知名服务端口，拿来做出站源口只会添乱
	if e.PortStart < 1024 || e.PortEnd < e.PortStart || e.PortEnd > 65535 {
		return fmt.Errorf("出口源端口段 %d-%d 不合法", e.PortStart, e.PortEnd)
	}
	if e.SourceIP == "" {
		return fmt.Errorf("限定了源端口段却没有源地址，PF 规则将匹配不上")
	}
	return nil
}

// maxPortAttempts 是一次拨号在端口段里最多试几个端口。
// 段长 256 时全试一遍的代价（每次一个 bind 系统调用）已经不小，而且端口段被占满
// 说明并发早就异常了，试 64 次还不成就该如实报错，不要在这里空转。
const maxPortAttempts = 64

// Dialer 按 Egress 拨号。它存在的唯一理由是源端口段那条路径：绑定固定源端口
// 会撞上 EADDRINUSE（同一个端口正在被本实例的另一条连接用着），必须在段内换个
// 端口重试，普通的 net.Dialer 做不到这件事。
//
// 没有端口段时它就是 net.Dialer 的一层薄包装，行为完全一致。
type Dialer struct {
	base    net.Dialer
	egress  Egress
	localIP net.IP
	seq     atomic.Uint64
}

// NewDialer 校验出口约束并返回拨号器。base 里的 Timeout/KeepAlive 等会被沿用，
// 但 Control 与 LocalAddr 由本包接管（传进来也会被覆盖）。
func NewDialer(e Egress, base net.Dialer) (*Dialer, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	d := &Dialer{base: base, egress: e}
	if e.SourceIP != "" {
		d.localIP = net.ParseIP(e.SourceIP)
	}
	// Control 里 setsockopt 失败会让拨号直接失败，这是有意的：
	// 宁可连不上，也不要静默从默认网关出去（见 Control 的注释）
	d.base.Control = Control(e.Options)
	d.base.LocalAddr = nil
	return d, nil
}

// DialContext 拨号。限定了源端口段时在段内轮转选口，撞上已被占用的端口就换下一个。
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.egress.PortStart == 0 {
		dialer := d.base
		if d.localIP != nil {
			dialer.LocalAddr = localAddr(network, d.localIP, 0)
		}
		return dialer.DialContext(ctx, network, address)
	}

	size := d.egress.PortEnd - d.egress.PortStart + 1
	attempts := min(maxPortAttempts, size)
	var lastErr error
	for i := 0; i < attempts; i++ {
		// 轮转而不是随机：Math/rand 会让复现问题变难，而顺序推进天然避开刚用过的口
		seq := d.seq.Add(1) - 1
		port := d.egress.PortStart + int(seq%uint64(size))

		dialer := d.base
		dialer.LocalAddr = localAddr(network, d.localIP, port)
		conn, err := dialer.DialContext(ctx, network, address)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if !isPortTaken(err) || ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// localAddr 按协议给出正确的地址类型。UDP 走错类型的话 net.Dialer 会直接报
// mismatched local address type——代理自身的 DNS 查询正是 UDP，别漏。
func localAddr(network string, ip net.IP, port int) net.Addr {
	if ip == nil && port == 0 {
		return nil
	}
	if strings.HasPrefix(network, "udp") {
		return &net.UDPAddr{IP: ip, Port: port}
	}
	return &net.TCPAddr{IP: ip, Port: port}
}

// isPortTaken 判断这次失败是不是"这个源端口不能用"，只有这种情况才值得换口重试。
// 目标不可达之类的错误换多少个源端口都一样，重试只会白白拖长超时。
func isPortTaken(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.EADDRNOTAVAIL)
}
