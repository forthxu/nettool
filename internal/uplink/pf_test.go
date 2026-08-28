package uplink

import (
	"strings"
	"testing"
)

// pfUplink 造一条已经定好模式与端口段的 macOS 线路
func pfUplink(id string, slot int, gateway, iface string) Uplink {
	u := Uplink{
		ID: id, Name: "线路" + id, Gateway: gateway, Interface: iface,
		SourceIP: "192.168.1.5", Slot: slot, Mark: slotMark(slot),
		Table: slotTable(slot), RulePrio: slotPrio(slot),
		Applied: true, Mode: ModePFRouteTo,
	}
	u.SourcePortStart, u.SourcePortEnd = slotPorts(slot)
	return u
}

// TestSlotPortsAreDisjointAndSafe 锁死端口段的选择依据。
//
// 三件事必须同时成立：段与段之间不重叠（否则两条线路的包会互相匹配到对方的
// PF 规则，流量走错网关）、整体落在临时端口段之外（macOS 的
// net.inet.ip.portrange.first = 49152，撞上就会跟内核抢口）、避开特权端口。
func TestSlotPortsAreDisjointAndSafe(t *testing.T) {
	const macOSEphemeralFirst = 49152
	prevEnd := 0
	for slot := 0; slot < maxSlots; slot++ {
		start, end := slotPorts(slot)
		if start < 1024 {
			t.Fatalf("槽位 %d 的端口段 %d-%d 落进了特权端口", slot, start, end)
		}
		if end >= macOSEphemeralFirst {
			t.Fatalf("槽位 %d 的端口段 %d-%d 与 macOS 临时端口段(%d 起)重叠",
				slot, start, end, macOSEphemeralFirst)
		}
		if end < start {
			t.Fatalf("槽位 %d 的端口段 %d-%d 是空的", slot, start, end)
		}
		if slot > 0 && start <= prevEnd {
			t.Fatalf("槽位 %d 的端口段从 %d 起，与上一段（到 %d）重叠", slot, start, prevEnd)
		}
		prevEnd = end
	}
}

// TestRenderPFRulesSeparatesGatewaysOnSameInterface 是这整套 macOS 实现存在的
// 理由：同一块网卡上的两个网关必须被分开。分开靠的是源端口段——两条规则的
// route-to 目标不同、匹配的端口段也不同，网卡则是同一块。
func TestRenderPFRulesSeparatesGatewaysOnSameInterface(t *testing.T) {
	list := []Uplink{
		pfUplink("u1", 0, "192.168.1.1", "en0"),
		pfUplink("u2", 1, "192.168.1.254", "en0"), // 同网卡、另一个网关
	}
	out, err := renderPFRules(list)
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 {
		t.Fatalf("两条线路应当渲染 4 条规则（各 TCP/UDP 一条），实际 %d 条:\n%s", len(lines), out)
	}

	want := []string{
		`pass out quick on en0 route-to (en0 192.168.1.1) inet proto tcp from 192.168.1.5 port 20000:20255 to any flags S/SA keep state user root label "nettool-u1"`,
		`pass out quick on en0 route-to (en0 192.168.1.1) inet proto udp from 192.168.1.5 port 20000:20255 to any keep state user root label "nettool-u1"`,
		`pass out quick on en0 route-to (en0 192.168.1.254) inet proto tcp from 192.168.1.5 port 20256:20511 to any flags S/SA keep state user root label "nettool-u2"`,
		`pass out quick on en0 route-to (en0 192.168.1.254) inet proto udp from 192.168.1.5 port 20256:20511 to any keep state user root label "nettool-u2"`,
	}
	for i, w := range want {
		if lines[i] != w {
			t.Errorf("第 %d 条规则不对\n实际: %s\n期望: %s", i+1, lines[i], w)
		}
	}
}

// TestRenderPFRulesAlwaysCoversUDP 锁死 DNS 泄漏这条：代理自己的域名解析走
// UDP:53，只写 TCP 规则的话查询会从默认网关出去，而数据连接走的是指定线路。
func TestRenderPFRulesAlwaysCoversUDP(t *testing.T) {
	out, err := renderPFRules([]Uplink{pfUplink("u1", 0, "192.168.1.1", "en0")})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if !strings.Contains(out, "proto tcp") || !strings.Contains(out, "proto udp") {
		t.Errorf("TCP 与 UDP 必须各有一条规则，实际:\n%s", out)
	}
}

// TestRenderPFRulesSkipsUnusable 只有真正处于 PF 模式且启用的线路才该被渲染
func TestRenderPFRulesSkipsUnusable(t *testing.T) {
	disabled := pfUplink("u1", 0, "192.168.1.1", "en0")
	disabled.Disabled = true
	boundIF := pfUplink("u2", 1, "192.168.1.254", "en0")
	boundIF.Mode = ModeBoundIF // PF 不可用时的降级模式，没有端口段可匹配
	fwmark := pfUplink("u3", 2, "192.168.2.1", "en1")
	fwmark.Mode = ModeFwmark

	out, err := renderPFRules([]Uplink{disabled, boundIF, fwmark})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("没有可用的 PF 线路时应当渲染出空规则集，实际:\n%s", out)
	}
}

// TestRenderPFRulesRejectsDangerousInput：规则是拼成文本再喂给 pfctl 的，
// 网卡名里混进空格或换行就等于让调用方往规则集里注入任意规则。其余几项拼错的
// 后果是把流量送到错误的地方，同样必须拒绝而不是凑合下发。
func TestRenderPFRulesRejectsDangerousInput(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Uplink)
	}{
		{"网卡名带空格（规则注入）", func(u *Uplink) { u.Interface = "en0 from any to any" }},
		{"网卡名带换行（规则注入）", func(u *Uplink) { u.Interface = "en0\npass out all" }},
		{"网卡名为空", func(u *Uplink) { u.Interface = "" }},
		{"网关不是 IPv4", func(u *Uplink) { u.Gateway = "fe80::1" }},
		{"网关不是 IP", func(u *Uplink) { u.Gateway = "any" }},
		{"缺源地址", func(u *Uplink) { u.SourceIP = "" }},
		{"端口段与槽位不符", func(u *Uplink) { u.SourcePortStart = 1 }},
	}
	for _, c := range cases {
		u := pfUplink("u1", 0, "192.168.1.1", "en0")
		c.mutate(&u)
		out, err := renderPFRules([]Uplink{u})
		if err == nil {
			t.Errorf("%s：应当拒绝，却渲染出了:\n%s", c.name, out)
		}
	}
}

// TestPFConfLoadsAppleAnchor 检查那个让整套方案成立的前提：系统 pf.conf 里
// 必须有一行会求值 com.apple 下子 anchor 的过滤 anchor。只有 scrub/nat/rdr
// 那几个不算——它们管的是别的阶段，带不动 route-to。
func TestPFConfLoadsAppleAnchor(t *testing.T) {
	// macOS 15 自带的 /etc/pf.conf 片段
	stock := `
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
`
	if !pfConfLoadsAppleAnchor(stock) {
		t.Error("系统自带的 pf.conf 应当被认定为可用")
	}

	bad := []struct {
		name string
		conf string
	}{
		{"只有非过滤阶段的 anchor", "scrub-anchor \"com.apple/*\"\nnat-anchor \"com.apple/*\"\n"},
		{"被注释掉了", "# anchor \"com.apple/*\"\n"},
		{"只加载了别人的 anchor", "anchor \"org.example/*\"\n"},
		{"空文件", ""},
	}
	for _, c := range bad {
		if pfConfLoadsAppleAnchor(c.conf) {
			t.Errorf("%s：不该被认定为可用", c.name)
		}
	}
}

func TestParsePFToken(t *testing.T) {
	got, err := parsePFToken("pf enabled\nToken : 12345678901234567890")
	if err != nil {
		t.Fatalf("解析令牌失败: %v", err)
	}
	if got != "12345678901234567890" {
		t.Errorf("令牌解析成 %q", got)
	}

	// 拿不到令牌就绝不能假装拿到了：那样 -X 归还不了，PF 会被一直开着
	if _, err := parsePFToken("pf enabled"); err == nil {
		t.Error("输出里没有令牌时必须报错")
	}
}

// TestPFLabelFitsPFLimit：PF 的 label 上限 63 字节，超了 pfctl 会把整份规则集
// 判为语法错误——一条线路的名字过长不该让所有线路一起失效。
func TestPFLabelFitsPFLimit(t *testing.T) {
	u := pfUplink(strings.Repeat("x", 200), 0, "192.168.1.1", "en0")
	if got := len(pfLabel(u)); got > 63 {
		t.Errorf("label 长度 %d 超过 PF 的 63 字节上限", got)
	}
}
