package uplink

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testUplink 造一条槽位 slot 上的线路，编号按正式规则算，避免测试里写死数字
func testUplink(slot int) Uplink {
	return Uplink{
		ID: "u1", Name: "测试线路", Gateway: "192.168.1.254", Interface: "eth0",
		SourceIP: "192.168.1.5", Slot: slot, Mark: slotMark(slot),
		Table: slotTable(slot), RulePrio: slotPrio(slot), PreferMain: true,
	}
}

// TestMarkDoesNotCollide 把「为什么选这组编号」的论证锁死。
//
// 反向撞车是最容易漏的一条：mwan3 会给「未打标」流量装一条 fwmark 0x0/0x3F00
// 的规则，而我们的 mark 低 24 位全为 0，是能被它匹配上的——唯一的防线是优先级
// 排在它前面。所以这里不只断言 mark 的形状，也断言优先级上限。
func TestMarkDoesNotCollide(t *testing.T) {
	for slot := 0; slot < maxSlots; slot++ {
		mark := slotMark(slot)

		if mark&0x00FFFFFF != 0 {
			t.Errorf("槽位 %d 的 mark 0x%08x 低 24 位不为 0，会闯进 mwan3/SQM/WireGuard 的编号空间", slot, mark)
		}
		// 逐个确认与已知使用者的掩码不相交
		for name, mask := range map[string]uint32{
			"mwan3(0x3F00)":       0x3F00,
			"mwan3 老版(0xFF00)":    0xFF00,
			"SQM/qos(0xFF)":       0xFF,
			"Tailscale(0xFF0000)": 0xFF0000,
		} {
			if mark&mask != 0 {
				t.Errorf("槽位 %d 的 mark 0x%08x 落进了 %s 的掩码", slot, mark, name)
			}
		}
		if mark&uint32(markMask) != mark {
			t.Errorf("槽位 %d 的 mark 0x%08x 超出了本程序的掩码 0x%08x", slot, mark, uint32(markMask))
		}

		table := slotTable(slot)
		if table < 256 {
			t.Errorf("槽位 %d 的表号 %d 落进了内核保留段与 mwan3 的 1..250", slot, table)
		}

		prio := slotPrio(slot)
		if prio <= 0 {
			t.Errorf("槽位 %d 的优先级 %d 必须排在 0: local 之后", slot, prio)
		}
		// +1 是这条线路的第二个优先级，也必须在 mwan3(1001) 之前
		if prio+1 >= 1001 {
			t.Errorf("槽位 %d 的优先级 %d/%d 没有排在 mwan3(1001+) 之前，打标流量会被 mwan3 截走",
				slot, prio, prio+1)
		}
	}

	// 槽位之间不能撞。两个槽位共用一个优先级会让后装的规则挤掉先装的，
	// 表现为"某条线路时灵时不灵"，所以连相邻槽位的第二个优先级也要查。
	seen := map[string]bool{}
	for slot := 0; slot < maxSlots; slot++ {
		for _, key := range []string{
			fmt.Sprintf("mark:%d", slotMark(slot)),
			fmt.Sprintf("table:%d", slotTable(slot)),
			fmt.Sprintf("prio:%d", slotPrio(slot)),
			fmt.Sprintf("prio:%d", slotPrio(slot)+1),
		} {
			if seen[key] {
				t.Errorf("槽位 %d 的编号 %s 与其他槽位重复", slot, key)
			}
			seen[key] = true
		}
	}
}

// 真正下发需要 root，这里只校验命令拼装。拼错的后果是把默认路由写进 main 表，
// 直接改掉整机的默认网关，所以每一个参数都要盯死。
func TestBuildTableRouteCmd(t *testing.T) {
	base := testUplink(0)

	cases := []struct {
		name   string
		mutate func(*Uplink)
		action string
		want   string
	}{
		{
			name: "完整", action: "replace",
			want: "ip route replace default via 192.168.1.254 dev eth0 src 192.168.1.5 table 7000",
		},
		{
			name: "不带源地址", action: "replace",
			mutate: func(u *Uplink) { u.SourceIP = "" },
			want:   "ip route replace default via 192.168.1.254 dev eth0 table 7000",
		},
		{
			name: "不带网卡", action: "replace",
			mutate: func(u *Uplink) { u.Interface = "" },
			want:   "ip route replace default via 192.168.1.254 src 192.168.1.5 table 7000",
		},
		{
			name: "第 3 个槽位", action: "replace",
			mutate: func(u *Uplink) { *u = testUplink(3) },
			want:   "ip route replace default via 192.168.1.254 dev eth0 src 192.168.1.5 table 7003",
		},
		{name: "清空", action: "flush", want: "ip route flush table 7000"},
	}

	for _, c := range cases {
		u := base
		if c.mutate != nil {
			c.mutate(&u)
		}
		got, err := buildTableRouteCmd(u, c.action)
		if err != nil {
			t.Errorf("%s: 意外报错 %v", c.name, err)
			continue
		}
		if joined := strings.Join(got, " "); joined != c.want {
			t.Errorf("%s:\n  实际 %s\n  期望 %s", c.name, joined, c.want)
		}
	}
}

func TestBuildRuleCmds(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Uplink)
		action string
		want   []string
	}{
		{
			name: "默认（带 suppress_prefixlength）", action: "add",
			want: []string{
				"ip rule add priority 300 fwmark 0x40000000/0xff000000 table main suppress_prefixlength 0",
				"ip rule add priority 301 fwmark 0x40000000/0xff000000 table 7000",
			},
		},
		{
			name: "降级后只剩一条", action: "add",
			mutate: func(u *Uplink) { u.PreferMain = false },
			want: []string{
				"ip rule add priority 301 fwmark 0x40000000/0xff000000 table 7000",
			},
		},
		{
			// 删除要带完整选择符，且顺序与添加相反：先撤兜底的表规则，
			// 免得中途失败留下「只查 main 不查本表」的黑洞状态
			name: "删除带完整选择符且倒序", action: "del",
			want: []string{
				"ip rule del priority 301 fwmark 0x40000000/0xff000000 table 7000",
				"ip rule del priority 300 fwmark 0x40000000/0xff000000 table main suppress_prefixlength 0",
			},
		},
		{
			name: "第 5 个槽位", action: "add",
			mutate: func(u *Uplink) { *u = testUplink(5) },
			want: []string{
				"ip rule add priority 310 fwmark 0x45000000/0xff000000 table main suppress_prefixlength 0",
				"ip rule add priority 311 fwmark 0x45000000/0xff000000 table 7005",
			},
		},
		{
			// 优先级被外人占用后顺延，编号仍必须成对
			name: "优先级顺延", action: "add",
			mutate: func(u *Uplink) { u.RulePrio = 400 },
			want: []string{
				"ip rule add priority 400 fwmark 0x40000000/0xff000000 table main suppress_prefixlength 0",
				"ip rule add priority 401 fwmark 0x40000000/0xff000000 table 7000",
			},
		},
	}

	for _, c := range cases {
		u := testUplink(0)
		if c.mutate != nil {
			c.mutate(&u)
		}
		got, err := buildRuleCmds(u, c.action)
		if err != nil {
			t.Errorf("%s: 意外报错 %v", c.name, err)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: 得到 %d 条命令，期望 %d 条: %v", c.name, len(got), len(c.want), got)
			continue
		}
		for i := range got {
			if joined := strings.Join(got[i], " "); joined != c.want[i] {
				t.Errorf("%s 第 %d 条:\n  实际 %s\n  期望 %s", c.name, i+1, joined, c.want[i])
			}
		}
	}
}

// TestBuildCmdsRejectsDangerousInput 锁死「不把自己锁在机器外面」这道防线。
// 越界的表号可能写进 main/local，越界的优先级可能抢在 0: local 之前把本机
// 流量吞掉——这些输入必须在拼命令之前就被拒绝。
func TestBuildCmdsRejectsDangerousInput(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Uplink)
	}{
		{"表号是 main", func(u *Uplink) { u.Table = 254 }},
		{"表号是 local", func(u *Uplink) { u.Table = 255 }},
		{"表号落进 mwan3 的 1..250", func(u *Uplink) { u.Table = 100 }},
		{"表号超出本程序上界", func(u *Uplink) { u.Table = tableBase + maxSlots }},
		{"优先级抢在 local 之前", func(u *Uplink) { u.RulePrio = 0 }},
		{"优先级低于本程序下界", func(u *Uplink) { u.RulePrio = rulePrioBase - 1 }},
		{"优先级越过 mwan3", func(u *Uplink) { u.RulePrio = 1200 }},
		{"优先级的第二条越界", func(u *Uplink) { u.RulePrio = rulePrioLimit - 1 }},
		{"mark 低位不为 0 会撞 mwan3", func(u *Uplink) { u.Mark = 0x40003F00 }},
		{"mark 不在本程序编号段", func(u *Uplink) { u.Mark = 0x01000000 }},
		{"槽位越界", func(u *Uplink) { u.Slot = maxSlots }},
		{"网关为空", func(u *Uplink) { u.Gateway = "" }},
		{"网关不是 IPv4", func(u *Uplink) { u.Gateway = "2001:db8::1" }},
		{"源地址非法", func(u *Uplink) { u.SourceIP = "不是IP" }},
	}

	for _, c := range cases {
		u := testUplink(0)
		c.mutate(&u)
		if _, err := buildRuleCmds(u, "add"); err == nil {
			t.Errorf("%s: buildRuleCmds 应当拒绝", c.name)
		}
		if _, err := buildTableRouteCmd(u, "replace"); err == nil {
			t.Errorf("%s: buildTableRouteCmd 应当拒绝", c.name)
		}
	}
}

// buildRuleFlushCmd 是唯一按优先级盲删的入口，范围校验必须严
func TestBuildRuleFlushCmd(t *testing.T) {
	if _, err := buildRuleFlushCmd(0); err == nil {
		t.Error("优先级 0 是 local 表规则，必须拒绝删除")
	}
	if _, err := buildRuleFlushCmd(32766); err == nil {
		t.Error("优先级 32766 是 main 表规则，必须拒绝删除")
	}
	if _, err := buildRuleFlushCmd(1001); err == nil {
		t.Error("优先级 1001 是 mwan3 的地盘，必须拒绝删除")
	}
	got, err := buildRuleFlushCmd(300)
	if err != nil {
		t.Fatalf("优先级 300 应当允许: %v", err)
	}
	if want := "ip rule del priority 300"; strings.Join(got, " ") != want {
		t.Errorf("实际 %v, 期望 %s", got, want)
	}
}

const iproute2RuleOutput = `0:	from all lookup local
300:	from all fwmark 0x40000000/0xff000000 lookup main suppress_prefixlength 0
301:	from all fwmark 0x40000000/0xff000000 lookup 7000
302:	from all fwmark 0x41000000/0xff000000 lookup main suppress_prefixlength 0
303:	from all fwmark 0x41000000/0xff000000 lookup 7001
32766:	from all lookup main
32767:	from all lookup default`

// mwan3 装的规则长这样，其中 1001 那条匹配的是「未打标」流量——
// 我们的 mark 低位全 0，是会被它匹配上的，所以绝不能把它认成自己的
const mwan3RuleOutput = `0:	from all lookup local
301:	from all fwmark 0x40000000/0xff000000 lookup 7000
1001:	from all fwmark 0x100/0x3f00 lookup 1
1002:	from all fwmark 0x200/0x3f00 lookup 2
2001:	from all fwmark 0x0/0x3f00 blackhole
32766:	from all lookup main`

func TestParseIPRules(t *testing.T) {
	rules, err := parseIPRules(iproute2RuleOutput)
	if err != nil {
		t.Fatalf("解析 iproute2 输出失败: %v", err)
	}
	if len(rules) != 7 {
		t.Fatalf("解析出 %d 条规则，期望 7 条", len(rules))
	}

	// 0: local
	if rules[0].Prio != 0 || rules[0].TableName != "local" || rules[0].Table != tableLocalID {
		t.Errorf("第一条应是 0: local，实际 %+v", rules[0])
	}
	if rules[0].IsOurs() {
		t.Error("local 规则被误认成了本程序的")
	}

	// 300: 带 suppress 的 main 规则
	r := rules[1]
	if r.Prio != 300 || !r.HasMark || r.Mark != 0x40000000 || r.Mask != 0xff000000 {
		t.Errorf("300 那条解析错了: %+v", r)
	}
	if !r.Suppress {
		t.Error("300 那条应当带 suppress_prefixlength")
	}
	if r.Table != tableMainID {
		t.Errorf("300 那条应当 lookup main，实际 %d", r.Table)
	}
	if !r.IsOurs() || r.Slot() != 0 {
		t.Errorf("300 那条应当是本程序槽位 0 的，实际 IsOurs=%v Slot=%d", r.IsOurs(), r.Slot())
	}

	// 303: 槽位 1 的表规则
	if r := rules[4]; !r.IsOurs() || r.Slot() != 1 || r.Table != 7001 || r.Suppress {
		t.Errorf("303 那条解析错了: %+v", r)
	}

	// 32766: main
	if r := rules[5]; r.IsOurs() || r.Table != tableMainID {
		t.Errorf("32766 那条解析错了: %+v", r)
	}
}

// 这条是最关键的隔离测试：别人的规则一条都不能被认领，否则清扫时会把
// mwan3 的规则删掉，直接搞瘫用户的多线负载均衡
func TestParseIPRulesNeverClaimsForeignRules(t *testing.T) {
	rules, err := parseIPRules(mwan3RuleOutput)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	ours := 0
	for _, r := range rules {
		if r.IsOurs() {
			ours++
			if r.Prio != 301 {
				t.Errorf("认领了不属于本程序的规则: %s", r.Raw)
			}
		}
	}
	if ours != 1 {
		t.Errorf("在这份输出里应当只认出 1 条自己的规则，实际 %d 条", ours)
	}

	// mwan3 的 0x0/0x3f00 掩码与我们的不同，绝不能被当成自己的
	for _, r := range rules {
		if r.Prio == 2001 && r.IsOurs() {
			t.Error("mwan3 的 fwmark 0x0/0x3f00 兜底规则被误认成了本程序的")
		}
	}
}

// busybox 未启用 CONFIG_FEATURE_IP_RULE 时打的是 usage，
// 必须干净报错而不是解析出一个空列表——否则「不支持」会被当成「没有规则」
func TestParseIPRulesRejectsUnsupportedOutput(t *testing.T) {
	cases := []string{
		"",
		"ip: unknown command \"rule\"",
		"Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\nwhere OBJECT := { link | addr | route | neigh }",
		"Object \"rule\" is unknown, try \"ip help\".",
	}
	for _, out := range cases {
		if rules, err := parseIPRules(out); err == nil {
			t.Errorf("输出 %q 应当报错，实际解析出 %d 条规则", out, len(rules))
		}
	}
}

func TestParseFwmark(t *testing.T) {
	cases := []struct {
		in         string
		mark, mask uint32
		ok         bool
	}{
		{"0x40000000/0xff000000", 0x40000000, 0xff000000, true},
		{"0x1", 0x1, 0xffffffff, true}, // 不带掩码时内核语义是全 1
		{"0x100/0x3f00", 0x100, 0x3f00, true},
		{"0x0/0x3f00", 0x0, 0x3f00, true},
		{"垃圾", 0, 0, false},
		{"0x1/垃圾", 0, 0, false},
	}
	for _, c := range cases {
		mark, mask, ok := parseFwmark(c.in)
		if ok != c.ok {
			t.Errorf("parseFwmark(%q) ok=%v, 期望 %v", c.in, ok, c.ok)
			continue
		}
		if ok && (mark != c.mark || mask != c.mask) {
			t.Errorf("parseFwmark(%q) = 0x%x/0x%x, 期望 0x%x/0x%x", c.in, mark, mask, c.mark, c.mask)
		}
	}
}

func TestParseRouteGet(t *testing.T) {
	cases := []struct {
		name          string
		out           string
		via, dev, src string
		dest          string
		wantErr       bool
	}{
		{
			name: "经网关",
			out:  "1.1.1.1 via 192.168.1.254 dev eth0 src 192.168.1.5 mark 0x41000000 uid 0 \n    cache ",
			via:  "192.168.1.254", dev: "eth0", src: "192.168.1.5", dest: "1.1.1.1",
		},
		{
			name: "直连（无 via）",
			out:  "192.168.1.9 dev eth0 src 192.168.1.5 uid 0 \n    cache ",
			dev:  "eth0", src: "192.168.1.5", dest: "192.168.1.9",
		},
		{
			name: "本机地址",
			out:  "local 127.0.0.1 dev lo src 127.0.0.1 uid 0 \n    cache <local> ",
			dev:  "lo", src: "127.0.0.1", dest: "127.0.0.1",
		},
		{name: "不可达", out: "unreachable 1.1.1.1 dev lo src 127.0.0.1 uid 0", wantErr: true},
		{name: "空输出", out: "", wantErr: true},
		{name: "无法解析", out: "RTNETLINK answers: Network is unreachable", wantErr: true},
	}

	for _, c := range cases {
		got, err := parseRouteGet(c.out)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: 应当报错，实际 %+v", c.name, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: 意外报错 %v", c.name, err)
			continue
		}
		if got.Via != c.via || got.Dev != c.dev || got.Src != c.src || got.Destination != c.dest {
			t.Errorf("%s:\n  实际 via=%q dev=%q src=%q dest=%q\n  期望 via=%q dev=%q src=%q dest=%q",
				c.name, got.Via, got.Dev, got.Src, got.Destination, c.via, c.dev, c.src, c.dest)
		}
	}
}

func TestAllocateSlot(t *testing.T) {
	m := New()

	// 空台账从 0 开始
	slot, err := m.allocateSlotLocked()
	if err != nil || slot != 0 {
		t.Fatalf("空台账应当分到槽位 0，实际 %d (%v)", slot, err)
	}

	// 已占用的不复用，且挑最小的空闲槽位
	m.uplinks["u1"] = Uplink{ID: "u1", Slot: 0}
	m.uplinks["u2"] = Uplink{ID: "u2", Slot: 2}
	if slot, _ := m.allocateSlotLocked(); slot != 1 {
		t.Errorf("应当分到最小空闲槽位 1，实际 %d", slot)
	}

	// 删除后可以复用
	delete(m.uplinks, "u1")
	if slot, _ := m.allocateSlotLocked(); slot != 0 {
		t.Errorf("槽位 0 释放后应当能复用，实际 %d", slot)
	}

	// 耗尽时礼貌拒绝，绝不绕回别人的编号空间
	full := New()
	for i := 0; i < maxSlots; i++ {
		full.uplinks[fmt.Sprintf("u%d", i)] = Uplink{Slot: i}
	}
	if _, err := full.allocateSlotLocked(); err == nil {
		t.Error("槽位耗尽时应当报错")
	}
}

func TestNextID(t *testing.T) {
	m := New()
	if got := m.nextIDLocked(); got != "u1" {
		t.Errorf("空台账应当给 u1，实际 %s", got)
	}
	m.uplinks["u1"] = Uplink{ID: "u1"}
	m.uplinks["u7"] = Uplink{ID: "u7"}
	if got := m.nextIDLocked(); got != "u8" {
		t.Errorf("应当接在最大编号之后给 u8，实际 %s", got)
	}
}

func TestMarkSpec(t *testing.T) {
	if got := testUplink(0).MarkSpec(); got != "0x40000000/0xff000000" {
		t.Errorf("MarkSpec() = %s", got)
	}
	if got := testUplink(63).MarkSpec(); got != "0x7f000000/0xff000000" {
		t.Errorf("MarkSpec() = %s", got)
	}
}

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "uplinks.json")

	save := New()
	save.path = path
	u := testUplink(2)
	u.ID = "u1"
	save.uplinks[u.ID] = u
	save.order = []string{u.ID}
	save.persistLocked()

	load := New()
	if !load.Load(path) {
		t.Fatal("Load 应当成功")
	}
	got, ok := load.Get("u1")
	if !ok {
		t.Fatal("载入后找不到 u1")
	}
	// 编号是当初分配好写死的，往返之后必须一模一样：用户可能已经拿这些
	// 编号写了自己的防火墙规则
	if got.Slot != u.Slot || got.Mark != u.Mark || got.Table != u.Table || got.RulePrio != u.RulePrio {
		t.Errorf("编号在往返中变了: %+v", got)
	}
	if got.Gateway != u.Gateway || got.Interface != u.Interface || got.SourceIP != u.SourceIP {
		t.Errorf("配置在往返中变了: %+v", got)
	}
	// 运行态不落盘，载入后应当是「未生效」，等 Reconcile 去下发
	if got.Applied {
		t.Error("载入后 Applied 应当是 false，等开机对账重新下发")
	}
}

// 手工改坏的台账不能放进来：越界的表号会被拿去拼下发命令，
// 而那条命令可能把默认路由写进 main 表
func TestLoadSkipsTamperedRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "uplinks.json")
	blob := `{"version":1,"uplinks":[
		{"id":"u1","name":"好的","gateway":"192.168.1.1","interface":"eth0",
		 "slot":0,"mark":1073741824,"table":7000,"rule_prio":300,"prefer_main":true},
		{"id":"u2","name":"表号被改成了 main","gateway":"192.168.2.1","interface":"eth1",
		 "slot":1,"mark":1090519040,"table":254,"rule_prio":302,"prefer_main":true}
	]}`
	if err := os.WriteFile(path, []byte(blob), 0o644); err != nil {
		t.Fatal(err)
	}

	m := New()
	m.Load(path)
	if _, ok := m.Get("u1"); !ok {
		t.Error("合法记录应当被载入")
	}
	if _, ok := m.Get("u2"); ok {
		t.Error("表号被改成 main 的记录必须被拒绝")
	}
}

// 台账损坏时把路径置空，宁可这次不持久化也不能覆盖用户的记录
func TestLoadCorruptFileDoesNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "uplinks.json")
	if err := os.WriteFile(path, []byte("{这不是 JSON"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := New()
	if m.Load(path) {
		t.Error("损坏的文件不应当算载入成功")
	}
	if m.StatePath() != "" {
		t.Error("载入损坏文件后必须把路径置空，避免用空台账覆盖用户数据")
	}
	m.persistLocked() // 不应写出任何东西
	data, _ := os.ReadFile(path)
	if string(data) != "{这不是 JSON" {
		t.Error("原文件被覆盖了")
	}
}

// TestDialOptionsRefusesUnappliedUplink 锁死最坏的失败模式：
// 线路没生效时必须拒绝拨号，而不是悄悄退回默认网关——用户以为流量走了
// 指定线路，实际却从默认出口跑了，这种问题现场几乎查不出来。
func TestDialOptionsRefusesUnappliedUplink(t *testing.T) {
	m := New()

	// 未绑定出口：零值，拨号路径与不用本包时完全一致
	e, err := m.DialOptions("")
	if err != nil || !e.Empty() {
		t.Errorf("空 id 应当返回零值，实际 %+v %v", e, err)
	}

	if _, err := m.DialOptions("不存在"); err == nil {
		t.Error("不存在的线路必须报错")
	}

	u := testUplink(0)
	u.Applied, u.LastErr = false, "ip rule 下发失败"
	m.uplinks[u.ID] = u
	if _, err := m.DialOptions(u.ID); err == nil {
		t.Fatal("未生效的线路必须拒绝，不能退回默认线路")
	} else if !strings.Contains(err.Error(), "ip rule 下发失败") {
		t.Errorf("错误信息里应当带上未生效的原因，实际: %v", err)
	}

	u.Applied, u.Disabled = true, true
	m.uplinks[u.ID] = u
	if _, err := m.DialOptions(u.ID); err == nil {
		t.Error("已停用的线路必须拒绝")
	}

	// fwmark 模式只打标、不绑源地址：同一网卡上的两个网关共享源 IP，
	// 绑源地址分不开它们，还可能绑到目标网关不认的地址上
	u.Disabled, u.Mode = false, ModeFwmark
	m.uplinks[u.ID] = u
	e, err = m.DialOptions(u.ID)
	if err != nil {
		t.Fatalf("已生效的线路不该报错: %v", err)
	}
	if e.Options.Mark != u.Mark {
		t.Errorf("应当打上 mark 0x%08x，实际 0x%08x", u.Mark, e.Options.Mark)
	}
	if e.SourceIP != "" || e.PortStart != 0 {
		t.Errorf("fwmark 模式不应绑定源地址或源端口，实际 %+v", e)
	}

	// 降级模式反过来：没有 mark 可用，只能绑网卡 + 源地址
	u.Mode = ModeBindDev
	m.uplinks[u.ID] = u
	e, err = m.DialOptions(u.ID)
	if err != nil {
		t.Fatalf("降级模式不该报错: %v", err)
	}
	if e.Options.Mark != 0 || e.Options.IfName != u.Interface || e.SourceIP != u.SourceIP {
		t.Errorf("降级模式应当绑网卡+源地址，实际 %+v", e)
	}
	if e.PortStart != 0 {
		t.Errorf("只有 macOS 的 PF 模式才限定源端口，实际 %+v", e)
	}
}

// TestPFDialOptionsCarriesPortRange 锁死 macOS 那条路径上最容易漏的一环：
// PF 规则按"源 IP + 源端口段"匹配，拨号时两样都要带上。少任何一样，包就匹配
// 不到规则、从默认网关静默出去。
func TestPFDialOptionsCarriesPortRange(t *testing.T) {
	m := New()
	u := testUplink(2)
	u.Applied, u.Mode = true, ModePFRouteTo
	u.SourcePortStart, u.SourcePortEnd = slotPorts(u.Slot)
	// 用回环网卡，只为拿到一个真实存在的网卡索引，与出口语义无关
	u.Interface = loopbackName(t)
	m.uplinks[u.ID] = u

	e, err := m.DialOptions(u.ID)
	if err != nil {
		t.Fatalf("PF 模式不该报错: %v", err)
	}
	if e.SourceIP != u.SourceIP {
		t.Errorf("PF 模式必须绑源地址，实际 %q", e.SourceIP)
	}
	wantStart, wantEnd := slotPorts(u.Slot)
	if e.PortStart != wantStart || e.PortEnd != wantEnd {
		t.Errorf("PF 模式的源端口段应为 %d-%d，实际 %d-%d",
			wantStart, wantEnd, e.PortStart, e.PortEnd)
	}
	if err := e.Validate(); err != nil {
		t.Errorf("给出的出口约束自身应当自洽: %v", err)
	}
}

func loopbackName(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("枚举网卡失败: %v", err)
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 {
			return i.Name
		}
	}
	t.Skip("本机没有回环网卡")
	return ""
}
