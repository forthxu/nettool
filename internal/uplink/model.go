// Package uplink 管理"出口线路"：一条线路 = 一个网关 + 它所在的网卡，
// 绑定了该线路的 SOCKS5 实例，其出站流量从这个网关走。
//
// 与 internal/route 的分工：route 管的是"哪些**目标**走哪个网关"，下发到 main
// 表，全机生效；本包管的是"哪个**实例**走哪个网关"。两者是正交的，所以拆成
// 两个包、两份台账。
//
// "哪个实例走哪个网关"需要一个能刻在包上、又能被内核用来选路的**选择器**。
// 路由查询本身只看目的地址，所以光靠加路由是做不到的。各平台的选择器不同：
//
//   - linux（ModeFwmark）：选择器是 fwmark。每条线路一个 mark、一张独立路由表、
//     一条 ip rule，出站 socket 打上 SO_MARK 就落进对应的表。
//   - darwin（ModePFRouteTo）：选择器是**源端口段**。每条线路分一段专属源端口，
//     PF 里一条 route-to 规则按"源 IP + 源端口段"把包直接送到指定网关，绕过路由
//     查询。同网卡的两个网关因此也能分开。
//   - darwin 无 PF 时（ModeBoundIF）/ windows（ModeUnicastIF）：只能把 socket
//     绑到某块网卡，选不了网关。
//
// 能力差异是真实存在的，必须如实告诉用户，见 Capability。
package uplink

import (
	"fmt"
	"net"
	"time"
)

// 策略路由用到的三组编号。这些数值的选择依据见下方各常量的注释，
// TestMarkDoesNotCollide 会把这些论证锁死。
const (
	// maxSlots 是能同时存在的出口线路数上限。槽位号决定 mark / 表号 / 优先级，
	// 三者一一对应，槽位耗尽时礼貌拒绝，绝不绕回别人的编号空间。
	maxSlots = 64

	// markMask 只看 mark 的最高字节。既有的 mark 使用者全都挤在低三字节里：
	// mwan3 用 0x3F00（老版本 0xFF00）、SQM/qos-scripts 用最低字节、
	// WireGuard 用单值 0xCA6C、Tailscale 用 0x80000/0xFF0000。最高字节没人占。
	markMask = 0xFF000000
	// markBase 是最高字节的起始值，槽位 0..63 对应 0x40000000..0x7F000000。
	markBase = 0x40

	// tableBase：路由表号从 7000 开始。0/253/254/255 是内核保留的
	// unspec/default/main/local；mwan3 按接口 id 占用 1–250，是 OpenWrt 上最大的
	// 撞车源；netifd 的 ip4table 惯例也是小数字。7000–7063 这一段没人用。
	tableBase = 7000

	// rulePrioBase / rulePrioStride：ip rule 优先级从 300 开始，每条线路占两个。
	// 必须排在 "0: local" 之后（否则本机流量会被抢走），并排在
	// mwan3(1001+)、Tailscale(5210+)、wg-quick(32764)、main(32766) 之前。
	rulePrioBase   = 300
	rulePrioStride = 2
	// rulePrioLimit 是优先级的硬上限（不含）。必须小于 mwan3 的 1001：
	// mwan3 会给"未打标"流量装一条 fwmark 0x0/0x3F00 的规则，而我们的 mark
	// 低 24 位全为 0，是能被它匹配上的——靠优先级排在它前面才不会被截走。
	rulePrioLimit = 1000

	// pfPortBase / pfPortSize：macOS 上每条线路的专属源端口段，槽位 0..63 对应
	// 20000..36383。选这一段的理由：macOS 的临时端口从 net.inet.ip.portrange.first
	// = 49152 起（本机实测），20000 段完全在它之外，不会跟内核抢口；也避开了
	// 1024 以下的特权端口与常见服务端口。
	//
	// 每段 256 个口，就是这条线路能同时保持的出站连接数上限——超了会
	// EADDRINUSE，sockopt.Dialer 会在段内换口重试，段真的占满才报错。
	pfPortBase = 20000
	pfPortSize = 256
)

// 出口生效方式。能力差异是真实存在的，命名上就不要含糊。
const (
	ModeFwmark    = "fwmark"       // Linux 策略路由：可区分同一网卡上的不同网关
	ModeBindDev   = "bindtodevice" // Linux 降级（无 ip rule）：只能按网卡区分
	ModePFRouteTo = "pf_route_to"  // macOS PF route-to：可区分同一网卡上的不同网关
	ModeBoundIF   = "bound_if"     // macOS 降级（无 PF）：只能按网卡区分
	ModeUnicastIF = "unicast_if"   // Windows IP_UNICAST_IF：只能按网卡区分
	ModeNone      = "none"         // 本平台无法绑定出口
)

func slotMark(slot int) uint32 { return uint32(markBase+slot) << 24 }
func slotTable(slot int) int   { return tableBase + slot }
func slotPrio(slot int) int    { return rulePrioBase + rulePrioStride*slot }

// slotPorts 给出槽位对应的源端口段（闭区间），供 macOS 的 PF 模式使用
func slotPorts(slot int) (int, int) {
	start := pfPortBase + slot*pfPortSize
	return start, start + pfPortSize - 1
}

// Uplink 是一条出口线路。
type Uplink struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Gateway   string `json:"gateway"`
	Interface string `json:"interface"`
	// SourceIP 写进路由表项的 src，让内核给走这条线路的连接挑对源地址。
	// 在 macOS/Windows 上它是主力手段之一（那边只能按网卡绑），可留空自动推断。
	SourceIP string `json:"source_ip,omitempty"`

	// 策略路由三件套。分配后就写死不再重算：用户可能已经拿这个 mark 写了
	// 自己的防火墙规则或排障笔记，重算会让那些东西全部失效。
	Slot     int    `json:"slot"`
	Mark     uint32 `json:"mark"`
	Table    int    `json:"table"`
	RulePrio int    `json:"rule_prio"` // 目标优先级被外人占用时会顺延，所以要落盘

	// SourcePortStart/End 是 macOS PF 模式下本线路的专属源端口段，由槽位决定。
	// 同样落盘不重算：用户可能已经拿这个端口段写了自己的 PF 规则或抓包过滤器。
	SourcePortStart int `json:"source_port_start,omitempty"`
	SourcePortEnd   int `json:"source_port_end,omitempty"`

	// PreferMain 决定是否额外装一条 lookup main suppress_prefixlength 0 的规则，
	// 让打标流量仍然遵循 main 表里的具体路由（LAN 直连、以及"路由管理"里下发的
	// proto 210 条目），只有默认路由被本线路接管。默认开启，见 applyLinux。
	PreferMain bool      `json:"prefer_main"`
	Disabled   bool      `json:"disabled,omitempty"`
	CreatedAt  time.Time `json:"created_at"`

	// 以下是运行态，不落盘，每次读取时重新判定
	Applied  bool   `json:"applied"`
	Degraded bool   `json:"degraded,omitempty"` // 本平台分不开，用户坚持创建
	LastErr  string `json:"last_error,omitempty"`
	Mode     string `json:"mode,omitempty"`
}

// MarkSpec 是 ip rule 里 fwmark 参数的写法，例如 0x40000000/0xff000000
func (u Uplink) MarkSpec() string {
	return fmt.Sprintf("0x%x/0x%x", u.Mark, uint32(markMask))
}

// mainPrio / tablePrio 是这条线路实际占用的两个优先级。
// PreferMain 关闭时只用 tablePrio。
func (u Uplink) mainPrio() int  { return u.RulePrio }
func (u Uplink) tablePrio() int { return u.RulePrio + 1 }

// validate 检查一条线路的编号是否落在本包自己的地盘里。
//
// 这是"别把自己锁在机器外面"的最后一道防线：越界的表号可能写进 main/local，
// 越界的优先级可能抢在 0: local 之前把本机流量吞掉。所有下发命令都要先过这里，
// TestBuildRuleCmdsRejectsDangerousInput 覆盖。
func (u Uplink) validate() error {
	if u.Slot < 0 || u.Slot >= maxSlots {
		return fmt.Errorf("槽位 %d 越界（应在 0..%d）", u.Slot, maxSlots-1)
	}
	if u.Mark&^uint32(markMask) != 0 {
		return fmt.Errorf("mark 0x%08x 的低 24 位不为 0，会与 mwan3 等既有标记使用者冲突", u.Mark)
	}
	if u.Mark>>24 < markBase || u.Mark>>24 >= markBase+maxSlots {
		return fmt.Errorf("mark 0x%08x 不在本程序的编号范围内", u.Mark)
	}
	if u.Table < tableBase || u.Table >= tableBase+maxSlots {
		return fmt.Errorf("路由表号 %d 不在本程序的编号范围内（%d..%d）",
			u.Table, tableBase, tableBase+maxSlots-1)
	}
	if u.RulePrio < rulePrioBase || u.tablePrio() >= rulePrioLimit {
		return fmt.Errorf("ip rule 优先级 %d 不在本程序的编号范围内（%d..%d）",
			u.RulePrio, rulePrioBase, rulePrioLimit-1)
	}
	if ip := net.ParseIP(u.Gateway); ip == nil || ip.To4() == nil {
		return fmt.Errorf("网关 %q 不是合法的 IPv4 地址", u.Gateway)
	}
	if u.SourceIP != "" {
		if ip := net.ParseIP(u.SourceIP); ip == nil || ip.To4() == nil {
			return fmt.Errorf("源地址 %q 不是合法的 IPv4 地址", u.SourceIP)
		}
	}
	if u.SourcePortStart != 0 || u.SourcePortEnd != 0 {
		wantStart, wantEnd := slotPorts(u.Slot)
		if u.SourcePortStart != wantStart || u.SourcePortEnd != wantEnd {
			return fmt.Errorf("源端口段 %d-%d 与槽位 %d 不匹配（应为 %d-%d）",
				u.SourcePortStart, u.SourcePortEnd, u.Slot, wantStart, wantEnd)
		}
	}
	return nil
}

// OpError 是单条线路上的失败，批量操作时逐条回报（与 route.OpError 同形）
type OpError struct {
	ID    string `json:"id"`
	Error string `json:"error"`
}

// Check 是一项能力探测结果
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	Remedy string `json:"remedy,omitempty"`
}

// Capability 如实描述本平台此刻能做到什么。界面据此决定说什么话，
// 关键是 PerGatewaySameInterface——只有它为 true 时才能"两网卡三网关"。
type Capability struct {
	Platform string `json:"platform"`
	Mode     string `json:"egress_mode"`
	// PerGatewaySameInterface 为 false 时，同一块网卡上只能有一条出口线路
	PerGatewaySameInterface bool    `json:"per_gateway_same_interface"`
	Root                    bool    `json:"root"`
	Checks                  []Check `json:"checks"`
}
