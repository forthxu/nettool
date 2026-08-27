package netdiag

import (
	"net"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func TestOptionsNormalize(t *testing.T) {
	// 目标必须是能拿去解析的 IP 或域名
	for _, bad := range []string{"", "   ", "http://example.com", "example.com:80", "example", "1.2.3.4/24"} {
		o := Options{Target: bad}
		if err := o.normalize(KindPing); err == nil {
			t.Errorf("normalize(target=%q) = nil, 期望报错", bad)
		}
	}

	// 没填的补默认值
	o := Options{Target: "example.com"}
	if err := o.normalize(KindPing); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if o.Count != defaultCount || o.IntervalMs != defaultInterval || o.TimeoutMs != defaultTimeout || o.Size != defaultSize {
		t.Errorf("ping 默认值不对: %+v", o)
	}

	// 负数的 count 表示"一直 ping 到手动停止"，归一化成 0
	o = Options{Target: "1.1.1.1", Count: -1}
	if err := o.normalize(KindPing); err != nil || o.Count != 0 {
		t.Errorf("count=-1 归一化成 %d (err=%v), 期望 0", o.Count, err)
	}

	// 超出范围的夹回边界
	o = Options{Target: "1.1.1.1", Count: maxCount * 10, IntervalMs: 1, TimeoutMs: maxTimeout * 10, Size: maxSize * 10}
	if err := o.normalize(KindPing); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if o.Count != maxCount || o.IntervalMs != minInterval || o.TimeoutMs != maxTimeout || o.Size != maxSize {
		t.Errorf("越界参数没夹回边界: %+v", o)
	}

	// traceroute 走自己那套字段
	o = Options{Target: "1.1.1.1"}
	if err := o.normalize(KindTrace); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if o.MaxHops != defaultMaxHops || o.Probes != defaultProbes {
		t.Errorf("traceroute 默认值不对: %+v", o)
	}

	if err := (&Options{Target: "1.1.1.1"}).normalize("nope"); err == nil {
		t.Error("未知诊断类型应当报错")
	}
}

func TestPayloadRoundTrip(t *testing.T) {
	b := buildPayload(1234, 56)
	if len(b) != 56 {
		t.Fatalf("负载长度 %d, 期望 56", len(b))
	}
	if seq, ok := payloadSeq(b); !ok || seq != 1234 {
		t.Errorf("payloadSeq = (%d, %v), 期望 (1234, true)", seq, ok)
	}

	// 太短的负载装不下标记，只能靠 ICMP 头里的序号匹配
	if _, ok := payloadSeq(buildPayload(1, 4)); ok {
		t.Error("4 字节负载不应当认出序号")
	}
	// 别人发的包（没有 magic）不认
	if _, ok := payloadSeq(make([]byte, 56)); ok {
		t.Error("没有 magic 的负载不应当认出序号")
	}
}

// echoReplyBytes 造一个目标回的 echo reply
func echoReplyBytes(t *testing.T, seq, size int) []byte {
	t.Helper()
	b, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Body: &icmp.Echo{ID: 1, Seq: seq & 0xffff, Data: buildPayload(seq, size)},
	}).Marshal(nil)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// quotedEcho 造一个 ICMP 差错报文里引用的原包：IP 头 + 前 8 字节 ICMP 头
func quotedEcho(seq int) []byte {
	quoted := make([]byte, 28)
	quoted[0] = 0x45              // IPv4, 头长 20 字节
	quoted[9] = protocolICMP      // 引用的是 ICMP 包
	quoted[20] = 8                // echo request
	quoted[26] = byte(seq >> 8)   // 序号高位
	quoted[27] = byte(seq & 0xff) // 序号低位
	return quoted
}

func errorReplyBytes(t *testing.T, typ ipv4.ICMPType, code, seq int) []byte {
	t.Helper()
	msg := &icmp.Message{Type: typ, Code: code}
	if typ == ipv4.ICMPTypeTimeExceeded {
		msg.Body = &icmp.TimeExceeded{Data: quotedEcho(seq)}
	} else {
		msg.Body = &icmp.DstUnreach{Data: quotedEcho(seq)}
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestParseReply(t *testing.T) {
	peer := &net.UDPAddr{IP: net.ParseIP("10.0.0.1")}

	rep, ok := parseReply(echoReplyBytes(t, 7, 56), peer, 51)
	if !ok || rep.Kind != replyEcho || rep.Seq != 7 || rep.TTL != 51 || rep.From.String() != "10.0.0.1" {
		t.Fatalf("echo reply 解析结果不对: %+v (ok=%v)", rep, ok)
	}

	rep, ok = parseReply(errorReplyBytes(t, ipv4.ICMPTypeTimeExceeded, 0, 9), peer, 64)
	if !ok || rep.Kind != replyExceeded || rep.Seq != 9 {
		t.Fatalf("time exceeded 解析结果不对: %+v (ok=%v)", rep, ok)
	}

	rep, ok = parseReply(errorReplyBytes(t, ipv4.ICMPTypeDestinationUnreachable, 1, 11), peer, 64)
	if !ok || rep.Kind != replyUnreachable || rep.Seq != 11 || rep.Detail != "主机不可达" {
		t.Fatalf("dst unreach 解析结果不对: %+v (ok=%v)", rep, ok)
	}

	// 别的进程发的 ping（负载够长但没有 magic）不能被认成我们的回包
	foreign, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Body: &icmp.Echo{ID: 1, Seq: 7, Data: make([]byte, 56)},
	}).Marshal(nil)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, ok := parseReply(foreign, peer, 64); ok {
		t.Error("别人的 echo reply 不应当被认领")
	}

	// echo request（自己发出去被环回看到）不是回包
	req, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 1, Seq: 7, Data: buildPayload(7, 56)}}).Marshal(nil)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, ok := parseReply(req, peer, 64); ok {
		t.Error("echo request 不应当被当成回包")
	}

	if _, ok := parseReply([]byte{0x01}, peer, 64); ok {
		t.Error("残包不应当解析成功")
	}
}

func TestQuotedSeq(t *testing.T) {
	if seq, ok := quotedSeq(quotedEcho(300)); !ok || seq != 300 {
		t.Errorf("quotedSeq = (%d, %v), 期望 (300, true)", seq, ok)
	}
	// 引用的包不是 ICMP，或者截得太短，都不该认
	notICMP := quotedEcho(1)
	notICMP[9] = 6 // TCP
	if _, ok := quotedSeq(notICMP); ok {
		t.Error("引用 TCP 包的差错报文不应当被认领")
	}
	if _, ok := quotedSeq(quotedEcho(1)[:24]); ok {
		t.Error("截断的引用包不应当解析成功")
	}
}

func summarizeProbes(probes []Probe) Summary {
	var stat pingStat
	for _, p := range probes {
		stat.add(p)
	}
	return stat.summary()
}

func TestPingStatSummary(t *testing.T) {
	s := summarizeProbes(nil)
	if s.Sent != 0 || s.Received != 0 || s.LossPercent != 0 {
		t.Errorf("空结果的汇总不对: %+v", s)
	}

	s = summarizeProbes([]Probe{
		{Status: StatusOK, RTTMs: 10},
		{Status: StatusOK, RTTMs: 20},
		{Status: StatusTimeout},
		{Status: StatusUnreachable, RTTMs: 5},
	})
	if s.Sent != 4 || s.Received != 2 {
		t.Fatalf("收发计数不对: %+v", s)
	}
	if s.LossPercent != 50 {
		t.Errorf("丢包率 = %v, 期望 50", s.LossPercent)
	}
	// 不可达那次带着 RTT，但它不算"收到"，不能进 RTT 统计
	if s.MinMs != 10 || s.MaxMs != 20 || s.AvgMs != 15 || s.StddevMs != 5 {
		t.Errorf("RTT 统计不对: %+v", s)
	}

	// 全丢时不能把最小值算成 0
	s = summarizeProbes([]Probe{{Status: StatusTimeout}, {Status: StatusTimeout}})
	if s.LossPercent != 100 || s.MinMs != 0 || s.AvgMs != 0 {
		t.Errorf("全丢包的汇总不对: %+v", s)
	}
}

// 持续 ping 会把明细截断，汇总必须仍然是整轮的
func TestProbeHistoryCapped(t *testing.T) {
	j := &Job{id: "ping-1", kind: KindPing}
	for i := 1; i <= maxProbeHistory+50; i++ {
		j.addProbe(Probe{Seq: i, Status: StatusOK, RTTMs: 10})
	}

	s := j.Snapshot()
	if len(s.Probes) != maxProbeHistory {
		t.Errorf("留下 %d 条明细, 期望 %d", len(s.Probes), maxProbeHistory)
	}
	if s.Probes[len(s.Probes)-1].Seq != maxProbeHistory+50 {
		t.Error("留下的应当是最近的那些")
	}
	if s.Summary.Sent != maxProbeHistory+50 || s.Summary.Received != maxProbeHistory+50 {
		t.Errorf("汇总不应当被截断影响: %+v", s.Summary)
	}
	if s.Summary.AvgMs != 10 || s.Summary.StddevMs != 0 {
		t.Errorf("RTT 汇总不对: %+v", s.Summary)
	}
}

func TestCollectNodes(t *testing.T) {
	nodes := collectNodes([]Probe{
		{From: "10.0.0.1"},
		{From: ""},
		{From: "10.0.0.1"},
		{From: "10.0.0.2"},
	})
	if len(nodes) != 2 || nodes[0].Address != "10.0.0.1" || nodes[1].Address != "10.0.0.2" {
		t.Errorf("collectNodes = %+v, 期望按出现顺序去重出两个", nodes)
	}
}

func TestJobSnapshotIsolated(t *testing.T) {
	j := &Job{id: "ping-1", kind: KindPing, startedAt: time.Now(), running: true}
	j.addProbe(Probe{Seq: 1, Status: StatusOK, RTTMs: 1})
	j.addHop(Hop{TTL: 1, Probes: []Probe{{Seq: 1}}, Nodes: []Node{{Address: "10.0.0.1"}}})

	s := j.Snapshot()
	s.Probes[0].RTTMs = 999
	s.Hops[0].Nodes[0].Address = "changed"

	again := j.Snapshot()
	if again.Probes[0].RTTMs != 1 || again.Hops[0].Nodes[0].Address != "10.0.0.1" {
		t.Error("Snapshot 应当返回副本，改动不能回写到任务里")
	}
	if again.Summary == nil || again.Summary.Sent != 1 {
		t.Errorf("ping 的快照应当带汇总: %+v", again.Summary)
	}
}

func TestRegistryEvictsOldest(t *testing.T) {
	r := &registry{jobs: map[string]*Job{}, latest: map[string]string{}}
	var first string
	for i := 0; i < maxJobs+3; i++ {
		id := r.nextID(KindPing)
		if i == 0 {
			first = id
		}
		r.add(&Job{id: id, kind: KindPing})
	}
	if len(r.jobs) != maxJobs {
		t.Errorf("保留了 %d 条记录, 期望 %d", len(r.jobs), maxJobs)
	}
	if _, ok := r.jobs[first]; ok {
		t.Error("最旧的记录应当被淘汰")
	}
	if r.jobs[r.latest[KindPing]] == nil {
		t.Error("latest 应当指向仍在的最新任务")
	}
}
