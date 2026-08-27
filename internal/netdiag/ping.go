package netdiag

// ping：按间隔一包一包发，每包等到回包或超时为止。
// 结果一条条追加进任务里，前端轮询时就能边跑边看。

import (
	"context"
	"errors"
	"net"
	"time"
)

func (j *Job) runPing(ctx context.Context, c *icmpConn, dst net.IP) {
	interval := time.Duration(j.opts.IntervalMs) * time.Millisecond
	timeout := time.Duration(j.opts.TimeoutMs) * time.Millisecond
	hardStop := time.Now().Add(maxPingDuration)

	for seq := 1; j.opts.Count == 0 || seq <= j.opts.Count; seq++ {
		if ctx.Err() != nil {
			j.setNote("已手动停止")
			return
		}
		// count 为 0 是"一直 ping"，页面关掉之后没人来停它，这里兜一个上限
		if j.opts.Count == 0 && time.Now().After(hardStop) {
			j.setNote("持续 ping 已达 %s 上限，自动停止", maxPingDuration)
			return
		}

		sentAt := j.pingOnce(ctx, c, dst, seq, timeout)

		// 从"发出去那一刻"起算间隔，回包快慢不会把节奏带偏
		wait := time.Until(sentAt.Add(interval))
		if wait <= 0 {
			continue
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			j.setNote("已手动停止")
			return
		case <-timer.C:
		}
	}
}

// pingOnce 发一包并记录结果，返回发包时刻
func (j *Job) pingOnce(ctx context.Context, c *icmpConn, dst net.IP, seq int, timeout time.Duration) time.Time {
	sentAt, err := c.send(dst, seq, j.opts.Size)
	if err != nil {
		if ctx.Err() != nil { // 停止时套接字被关掉，不算失败
			return sentAt
		}
		j.addProbe(Probe{Seq: seq, Status: StatusError, Detail: err.Error(), Time: time.Now()})
		return sentAt
	}

	rep, err := c.await(seq, sentAt.Add(timeout))
	rtt := round2(float64(time.Since(sentAt).Microseconds()) / 1000)

	switch {
	case errors.Is(err, errTimeout):
		j.addProbe(Probe{Seq: seq, Status: StatusTimeout, Time: time.Now()})
	case err != nil:
		if ctx.Err() != nil {
			return sentAt
		}
		j.addProbe(Probe{Seq: seq, Status: StatusError, Detail: err.Error(), Time: time.Now()})
	case rep.Kind == replyUnreachable:
		j.addProbe(Probe{
			Seq: seq, From: ipString(rep.From), RTTMs: rtt,
			Status: StatusUnreachable, Detail: rep.Detail, Time: time.Now(),
		})
	case rep.Kind == replyExceeded:
		j.addProbe(Probe{
			Seq: seq, From: ipString(rep.From), RTTMs: rtt,
			Status: StatusError, Detail: "TTL 在途中耗尽", Time: time.Now(),
		})
	default:
		j.addProbe(Probe{
			Seq: seq, From: ipString(rep.From), RTTMs: rtt,
			TTL: rep.TTL, Status: StatusOK, Time: time.Now(),
		})
	}
	return sentAt
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
