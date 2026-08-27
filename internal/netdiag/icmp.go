package netdiag

// ICMP 套接字的开、发、收与回包匹配。ping 和 traceroute 共用这一层，
// 区别只在于发之前设不设 TTL、以及怎么解读回来的那个包。

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// protocolICMP 是 IPv4 的 ICMP 协议号，解析回包时要用
const protocolICMP = 1

// payloadMagic 打在负载开头（"lanp"），用来认出"这是本程序发的包"，
// 免得同机器上别的 ping 恰好用了同一个序号时被错认。
const payloadMagic uint32 = 0x6c616e70

// errTimeout 表示这一次探测等到超时也没收到匹配的回包
var errTimeout = errors.New("等待回包超时")

// 回包的三种类型：目标回的 echo reply、中间路由器回的超时、以及不可达
const (
	replyEcho        = "echo"
	replyExceeded    = "exceeded"
	replyUnreachable = "unreachable"
)

type reply struct {
	From   net.IP
	TTL    int // 回包自身的 TTL（拿不到时为 0）
	Kind   string
	Seq    int
	Detail string
}

type icmpConn struct {
	pc         *icmp.PacketConn
	p4         *ipv4.PacketConn
	privileged bool // true = ip4:icmp 原始套接字（需要 root）
	id         int
	closeOnce  sync.Once
}

// openICMP 开一个 ICMP 套接字，可绑定本机源地址。
//
// 有两条路可走：非特权的 ICMP 数据报套接字（macOS 默认可用，Linux 要求当前用户的 gid
// 在 net.ipv4.ping_group_range 内）和需要 root 的原始套接字。ping 优先用前者，
// 好让非 root 也能用；traceroute 优先用后者——非特权套接字在 Linux 上收不到中间
// 路由器回的 Time Exceeded，那样整趟都是超时。
//
// Windows 压根没有非特权 ICMP 套接字，只剩原始套接字这一条路，因此 ping 和
// traceroute 都必须以管理员身份运行。好在设置 TTL（traceroute 要用）在 Windows
// 上是支持的，只有回包的 TTL 读不到（x/net 在这个平台上没实现控制消息），
// 界面上那一列会显示 0。
func openICMP(source net.IP, preferRaw bool) (*icmpConn, error) {
	addr := "0.0.0.0"
	if source != nil {
		addr = source.String()
	}

	networks := []string{"udp4", "ip4:icmp"}
	if preferRaw {
		networks = []string{"ip4:icmp", "udp4"}
	}
	if runtime.GOOS == "windows" {
		// Windows 没有非特权 ICMP 数据报套接字，试也是白试
		networks = []string{"ip4:icmp"}
	}

	var errs []error
	for _, network := range networks {
		pc, err := icmp.ListenPacket(network, addr)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", network, err))
			continue
		}
		c := &icmpConn{
			pc:         pc,
			p4:         pc.IPv4PacketConn(),
			privileged: network != "udp4",
			id:         os.Getpid() & 0xffff,
		}
		if c.p4 != nil {
			// 拿回包的 TTL 是锦上添花，不支持就算了
			_ = c.p4.SetControlMessage(ipv4.FlagTTL, true)
		}
		return c, nil
	}

	return nil, fmt.Errorf("%w（%s）: %v", ErrICMPUnavailable, icmpPrivilegeHint(), errors.Join(errs...))
}

// icmpPrivilegeHint 按平台给一句"该怎么办"，界面上直接显示给用户
func icmpPrivilegeHint() string {
	switch runtime.GOOS {
	case "windows":
		return "Windows 没有非特权 ICMP 套接字，必须以管理员身份运行；另外防火墙要放行 ICMP 入站"
	case "linux":
		return "原始套接字需要 root，非特权套接字需要当前用户的 gid 落在 net.ipv4.ping_group_range 内"
	default:
		return "原始套接字需要 root"
	}
}

func (c *icmpConn) close() {
	c.closeOnce.Do(func() { c.pc.Close() })
}

// dstAddr：非特权套接字要用 UDPAddr，原始套接字要用 IPAddr
func (c *icmpConn) dstAddr(ip net.IP) net.Addr {
	if c.privileged {
		return &net.IPAddr{IP: ip}
	}
	return &net.UDPAddr{IP: ip}
}

func (c *icmpConn) setTTL(ttl int) error {
	if c.p4 == nil {
		return errors.New("当前套接字不支持设置 TTL，无法做 traceroute")
	}
	return c.p4.SetTTL(ttl)
}

// send 发一个 echo request，返回发出去的时刻
func (c *icmpConn) send(dst net.IP, seq, size int) (time.Time, error) {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: c.id, Seq: seq & 0xffff, Data: buildPayload(seq, size)},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return time.Time{}, err
	}

	sentAt := time.Now()
	if _, err := c.pc.WriteTo(b, c.dstAddr(dst)); err != nil {
		return sentAt, err
	}
	return sentAt, nil
}

// await 一直读到收着序号对得上的回包，或者到点了返回 errTimeout。
// 期间读到的别的包（别人的 ping、上一轮迟到的回包）直接丢掉接着等。
func (c *icmpConn) await(seq int, deadline time.Time) (*reply, error) {
	buf := make([]byte, 1500)
	for {
		if err := c.pc.SetReadDeadline(deadline); err != nil {
			return nil, err
		}
		n, ttl, peer, err := c.read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return nil, errTimeout
			}
			return nil, err
		}
		rep, ok := parseReply(buf[:n], peer, ttl)
		if !ok || rep.Seq != seq&0xffff {
			continue
		}
		return rep, nil
	}
}

func (c *icmpConn) read(buf []byte) (int, int, net.Addr, error) {
	if c.p4 != nil {
		n, cm, peer, err := c.p4.ReadFrom(buf)
		ttl := 0
		if cm != nil {
			ttl = cm.TTL
		}
		return n, ttl, peer, err
	}
	n, peer, err := c.pc.ReadFrom(buf)
	return n, 0, peer, err
}

// buildPayload 造负载：前 8 字节是magic+序号，剩下的填可读的填充字符。
// 负载不足 8 字节时只填充，此时全靠 ICMP 头里的序号来匹配。
func buildPayload(seq, size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	if size >= 8 {
		binary.BigEndian.PutUint32(b[0:4], payloadMagic)
		binary.BigEndian.PutUint32(b[4:8], uint32(seq))
	}
	return b
}

// payloadSeq 取回打在负载里的序号；不是本程序发的返回 false
func payloadSeq(b []byte) (int, bool) {
	if len(b) < 8 || binary.BigEndian.Uint32(b[0:4]) != payloadMagic {
		return 0, false
	}
	return int(binary.BigEndian.Uint32(b[4:8])), true
}

// parseReply 解一个收到的 ICMP 包，取出"它对应我们发的哪一个探测"。
//
// echo reply 里负载是原样回来的，可以顺带核对 magic；超时和不可达回的是
// 原包的 IP 头 + 前 8 字节 ICMP 头，只能从里面抠序号。
func parseReply(b []byte, peer net.Addr, ttl int) (*reply, bool) {
	m, err := icmp.ParseMessage(protocolICMP, b)
	if err != nil {
		return nil, false
	}

	r := &reply{From: addrIP(peer), TTL: ttl}
	switch body := m.Body.(type) {
	case *icmp.Echo:
		if m.Type != ipv4.ICMPTypeEchoReply {
			return nil, false
		}
		// 非特权套接字上 ID 会被内核改写，认不得，所以一律按序号匹配
		if seq, ok := payloadSeq(body.Data); ok && seq&0xffff != body.Seq {
			return nil, false // 负载里写的不是这个序号，不是我们的包
		} else if !ok && len(body.Data) >= 8 {
			return nil, false // 够长却没有 magic：别人发的
		}
		r.Kind, r.Seq = replyEcho, body.Seq

	case *icmp.TimeExceeded:
		seq, ok := quotedSeq(body.Data)
		if !ok {
			return nil, false
		}
		r.Kind, r.Seq = replyExceeded, seq

	case *icmp.DstUnreach:
		seq, ok := quotedSeq(body.Data)
		if !ok {
			return nil, false
		}
		r.Kind, r.Seq, r.Detail = replyUnreachable, seq, unreachText(m.Code)

	default:
		return nil, false
	}
	return r, true
}

// quotedSeq 从 ICMP 差错报文引用的原包里抠出 echo request 的序号
func quotedSeq(data []byte) (int, bool) {
	if len(data) < 20 {
		return 0, false
	}
	hdrLen := int(data[0]&0x0f) * 4
	if hdrLen < 20 || len(data) < hdrLen+8 {
		return 0, false
	}
	if data[9] != protocolICMP { // 引用的不是 ICMP 包，与我们无关
		return 0, false
	}
	inner := data[hdrLen:]
	if inner[0] != 8 { // 不是 echo request
		return 0, false
	}
	return int(binary.BigEndian.Uint16(inner[6:8])), true
}

// addrIP 从对端地址里取 IP：原始套接字给的是 IPAddr，非特权套接字给的是 UDPAddr
func addrIP(peer net.Addr) net.IP {
	switch a := peer.(type) {
	case *net.IPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	}
	return nil
}

// unreachText 把常见的不可达代码翻成人话
func unreachText(code int) string {
	switch code {
	case 0:
		return "网络不可达"
	case 1:
		return "主机不可达"
	case 2:
		return "协议不可达"
	case 3:
		return "端口不可达"
	case 4:
		return "需要分片但设置了不分片"
	case 9, 10:
		return "被管理策略禁止"
	case 13:
		return "被过滤（管理禁止）"
	default:
		return fmt.Sprintf("目标不可达 (code %d)", code)
	}
}
