package netdiag

// traceroute：把 TTL 从 1 开始一跳一跳加上去，让沿途的路由器各自回一个
// Time Exceeded，从而把整条路径问出来；收到目标回的 echo reply 就说明到了。

import (
	"context"
	"errors"
	"net"
	"time"
)

func (j *Job) runTraceroute(ctx context.Context, c *icmpConn, dst net.IP) {
	timeout := time.Duration(j.opts.TimeoutMs) * time.Millisecond
	seq := 0
	silent := 0 // 连续多少跳一个回包都没有

	for ttl := 1; ttl <= j.opts.MaxHops; ttl++ {
		if ctx.Err() != nil {
			j.setNote("已手动停止")
			return
		}
		if err := c.setTTL(ttl); err != nil {
			if ctx.Err() == nil {
				j.fail(err)
			}
			return
		}

		hop := Hop{TTL: ttl}
		for p := 0; p < j.opts.Probes; p++ {
			if ctx.Err() != nil {
				j.setNote("已手动停止")
				return
			}
			seq++
			probe, final := j.traceProbe(ctx, c, dst, seq, timeout)
			hop.Probes = append(hop.Probes, probe)
			hop.Final = hop.Final || final
		}

		hop.Nodes = collectNodes(hop.Probes)
		idx := j.addHop(hop)

		// 反查放在这一跳先挂出去之后做：域名慢一点没关系，路径要马上能看到
		if j.opts.ResolveNames && len(hop.Nodes) > 0 {
			j.setHopNodes(idx, resolveNodes(ctx, hop.Nodes))
		}

		if hop.Final {
			j.setNote("已到达目标 %s，共 %d 跳", dst, ttl)
			return
		}

		if len(hop.Nodes) == 0 {
			silent++
			if silent >= maxSilentHops {
				j.setNote("连续 %d 跳没有任何回包，提前结束；中间设备常常不回 ICMP，可加大超时或换个源 IP 再试", silent)
				return
			}
		} else {
			silent = 0
		}
	}

	j.setNote("已达最大跳数 %d，仍未到达目标 %s", j.opts.MaxHops, dst)
}

// traceProbe 发一个探测包，返回这次探测的结果以及"是不是已经到目标了"
func (j *Job) traceProbe(ctx context.Context, c *icmpConn, dst net.IP, seq int, timeout time.Duration) (Probe, bool) {
	probe := Probe{Seq: seq, Time: time.Now()}

	sentAt, err := c.send(dst, seq, j.opts.Size)
	if err != nil {
		if ctx.Err() != nil {
			probe.Status = StatusTimeout
			return probe, false
		}
		probe.Status, probe.Detail = StatusError, err.Error()
		return probe, false
	}

	rep, err := c.await(seq, sentAt.Add(timeout))
	probe.RTTMs = round2(float64(time.Since(sentAt).Microseconds()) / 1000)
	probe.Time = time.Now()

	switch {
	case errors.Is(err, errTimeout):
		probe.Status, probe.RTTMs = StatusTimeout, 0
		return probe, false
	case err != nil:
		probe.RTTMs = 0
		if ctx.Err() != nil {
			probe.Status = StatusTimeout
			return probe, false
		}
		probe.Status, probe.Detail = StatusError, err.Error()
		return probe, false
	}

	probe.From, probe.TTL = ipString(rep.From), rep.TTL
	switch rep.Kind {
	case replyEcho:
		probe.Status = StatusOK
		return probe, true // 目标本人回的，这一跳就是终点
	case replyUnreachable:
		probe.Status, probe.Detail = StatusUnreachable, rep.Detail
		// 目标自己回的"端口/主机不可达"也算走到了，中间设备回的则继续往下探
		return probe, rep.From != nil && rep.From.Equal(dst)
	default:
		probe.Status = StatusOK // Time Exceeded：正常的中间跳
		return probe, false
	}
}

// collectNodes 按出现顺序去重这一跳的响应者（负载均衡时同一跳可能有好几个）
func collectNodes(probes []Probe) []Node {
	var nodes []Node
	seen := map[string]bool{}
	for _, p := range probes {
		if p.From == "" || seen[p.From] {
			continue
		}
		seen[p.From] = true
		nodes = append(nodes, Node{Address: p.From})
	}
	return nodes
}

func resolveNodes(ctx context.Context, nodes []Node) []Node {
	out := make([]Node, len(nodes))
	for i, n := range nodes {
		out[i] = Node{Address: n.Address, Name: lookupName(ctx, n.Address)}
	}
	return out
}
