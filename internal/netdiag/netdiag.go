// Package netdiag 用 ICMP 做连通性诊断：ping 与 traceroute。
//
// 两者都能绑定本机源 IP —— 在多路由器环境里"从哪块网卡发出去"决定了走哪个上游，
// 也就决定了通不通、走几跳，所以这里和 SOCKS5 的出口绑定一样支持指定源地址。
//
// 每次诊断是一个后台任务：接口起一个任务后立刻返回任务 ID，前端轮询拿增量结果，
// 这样 ping 的每一包、traceroute 的每一跳都能边跑边看，而不是等全部跑完才出结果。
package netdiag

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"nettool/internal/netiface"
	"nettool/internal/netutil"
)

// 两种诊断。前端按 kind 记住最近一次任务，刷新页面后还能接着看。
const (
	KindPing  = "ping"
	KindTrace = "traceroute"
)

// 单次探测的四种结果
const (
	StatusOK          = "ok"
	StatusTimeout     = "timeout"
	StatusUnreachable = "unreachable"
	StatusError       = "error"
)

// 各项参数的默认值与上下限：界面上随便填，这里统一夹到能跑得动的范围内
const (
	defaultCount = 4
	maxCount     = 1000

	defaultInterval = 1000
	minInterval     = 100
	maxInterval     = 10000

	defaultTimeout = 2000
	minTimeout     = 100
	maxTimeout     = 10000

	defaultSize = 56
	maxSize     = 1400

	defaultMaxHops = 30
	maxMaxHops     = 64

	defaultProbes = 3
	maxProbes     = 5

	// 持续 ping（count=0）的兜底上限：页面关掉之后没人来停它
	maxPingDuration = 30 * time.Minute
	// traceroute 连续这么多跳一个回包都没有就提前收工，多半是中间设备把 ICMP 丢了
	maxSilentHops = 5
	// 反查域名不值得等太久
	rdnsTimeout = time.Second
	// 内存里最多留几次诊断记录
	maxJobs = 20
	// 单次 ping 最多留多少条明细：持续 ping 能跑很久，界面只看最近的，
	// 发送/丢包/RTT 的汇总另有计数器，不受这里截断影响
	maxProbeHistory = 500
)

// ErrICMPUnavailable 表示 ICMP 套接字压根打不开（通常是权限问题），
// 与"参数填错了"区分开，接口据此回不同的状态码。
var ErrICMPUnavailable = errors.New("ICMP 套接字不可用")

// Options 是发起一次诊断的全部参数，ping 与 traceroute 共用一个结构，
// 各自只取自己关心的字段。
type Options struct {
	Target       string `json:"target"`
	SourceIP     string `json:"source_ip,omitempty"`
	Count        int    `json:"count"`       // ping 探测次数，0 = 一直探到手动停止
	IntervalMs   int    `json:"interval_ms"` // ping 两次探测的间隔
	TimeoutMs    int    `json:"timeout_ms"`  // 单次探测等回包的上限
	Size         int    `json:"size"`        // ICMP 负载字节数
	MaxHops      int    `json:"max_hops"`    // traceroute 最大跳数
	Probes       int    `json:"probes"`      // traceroute 每跳探测次数
	ResolveNames bool   `json:"resolve_names"`
}

// normalize 校验目标地址并把其余参数夹到合法区间；kind 决定哪些字段要补默认值
func (o *Options) normalize(kind string) error {
	o.Target = strings.TrimSpace(o.Target)
	o.SourceIP = strings.TrimSpace(o.SourceIP)

	if o.Target == "" {
		return errors.New("目标地址不能为空")
	}
	if net.ParseIP(o.Target) == nil && !netutil.IsValidDomain(o.Target) {
		return fmt.Errorf("目标 %q 不是合法的 IP 或域名（不要带协议、端口和路径）", o.Target)
	}

	o.TimeoutMs = clamp(o.TimeoutMs, minTimeout, maxTimeout, defaultTimeout)

	switch kind {
	case KindPing:
		// 传负数表示"一直 ping 到手动停止"，归一化成 0；没填则按默认次数
		switch {
		case o.Count < 0:
			o.Count = 0
		case o.Count == 0:
			o.Count = defaultCount
		case o.Count > maxCount:
			o.Count = maxCount
		}
		o.IntervalMs = clamp(o.IntervalMs, minInterval, maxInterval, defaultInterval)
		o.Size = clamp(o.Size, 0, maxSize, defaultSize)
	case KindTrace:
		o.MaxHops = clamp(o.MaxHops, 1, maxMaxHops, defaultMaxHops)
		o.Probes = clamp(o.Probes, 1, maxProbes, defaultProbes)
		o.Size = clamp(o.Size, 0, maxSize, defaultSize)
	default:
		return fmt.Errorf("未知的诊断类型 %q", kind)
	}
	return nil
}

// clamp 把 0（没填）换成默认值，其余夹到 [min, max]
func clamp(v, min, max, def int) int {
	if v == 0 {
		return def
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// Probe 是一次探测的结果（ping 的一包，或 traceroute 某一跳的一次试探）
type Probe struct {
	Seq    int       `json:"seq"`
	From   string    `json:"from,omitempty"`
	RTTMs  float64   `json:"rtt_ms"`
	TTL    int       `json:"ttl,omitempty"` // 回包自己的 TTL，可推算对端跳数
	Status string    `json:"status"`
	Detail string    `json:"detail,omitempty"`
	Time   time.Time `json:"time"`
}

// Node 是 traceroute 某一跳的一个响应者（同一跳可能因负载均衡出现多个）
type Node struct {
	Address string `json:"address"`
	Name    string `json:"name,omitempty"`
}

// Hop 是 traceroute 的一跳
type Hop struct {
	TTL    int     `json:"ttl"`
	Probes []Probe `json:"probes"`
	Nodes  []Node  `json:"nodes"`
	Final  bool    `json:"final"` // 这一跳就是目标本身
}

// Summary 是 ping 跑完（或跑到一半）时的汇总
type Summary struct {
	Sent        int     `json:"sent"`
	Received    int     `json:"received"`
	LossPercent float64 `json:"loss_percent"`
	MinMs       float64 `json:"min_ms"`
	AvgMs       float64 `json:"avg_ms"`
	MaxMs       float64 `json:"max_ms"`
	StddevMs    float64 `json:"stddev_ms"`
}

// Snapshot 是一次诊断任务对外的完整状态，前端轮询拿到的就是它
type Snapshot struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	Target     string     `json:"target"`
	ResolvedIP string     `json:"resolved_ip,omitempty"`
	SourceIP   string     `json:"source_ip,omitempty"`
	Options    Options    `json:"options"`
	Privileged bool       `json:"privileged"` // true = 原始套接字，false = 非特权 ICMP
	Running    bool       `json:"running"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Error      string     `json:"error,omitempty"`
	Note       string     `json:"note,omitempty"`
	Probes     []Probe    `json:"probes,omitempty"`  // ping
	Hops       []Hop      `json:"hops,omitempty"`    // traceroute
	Summary    *Summary   `json:"summary,omitempty"` // ping
	ServerTime time.Time  `json:"server_time"`
}

// Job 是一次正在跑或已经跑完的诊断
type Job struct {
	mu         sync.Mutex
	id         string
	kind       string
	opts       Options
	resolved   string
	privileged bool
	running    bool
	startedAt  time.Time
	finishedAt time.Time
	err        string
	note       string
	probes     []Probe
	stat       pingStat
	hops       []Hop
	cancel     context.CancelFunc
}

// ID 供接口把任务 ID 回给前端
func (j *Job) ID() string { return j.id }

func (j *Job) setResolved(ip string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.resolved = ip
}

func (j *Job) setNote(format string, args ...interface{}) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.note = fmt.Sprintf(format, args...)
}

func (j *Job) fail(err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.err = err.Error()
}

func (j *Job) finish() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.running = false
	j.finishedAt = time.Now()
}

func (j *Job) addProbe(p Probe) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.stat.add(p)
	j.probes = append(j.probes, p)
	if len(j.probes) > maxProbeHistory {
		j.probes = append([]Probe(nil), j.probes[len(j.probes)-maxProbeHistory:]...)
	}
}

func (j *Job) addHop(h Hop) int {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.hops = append(j.hops, h)
	return len(j.hops) - 1
}

// setHopNodes 用来在反查完域名后回填这一跳的响应者
func (j *Job) setHopNodes(idx int, nodes []Node) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if idx >= 0 && idx < len(j.hops) {
		j.hops[idx].Nodes = nodes
	}
}

func (j *Job) stop() {
	j.mu.Lock()
	cancel := j.cancel
	j.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Snapshot 复制一份当前状态（含汇总），调用方可以随便拿去序列化
func (j *Job) Snapshot() Snapshot {
	j.mu.Lock()
	defer j.mu.Unlock()

	s := Snapshot{
		ID:         j.id,
		Kind:       j.kind,
		Target:     j.opts.Target,
		ResolvedIP: j.resolved,
		SourceIP:   j.opts.SourceIP,
		Options:    j.opts,
		Privileged: j.privileged,
		Running:    j.running,
		StartedAt:  j.startedAt,
		Error:      j.err,
		Note:       j.note,
		ServerTime: time.Now(),
	}
	if !j.finishedAt.IsZero() {
		finished := j.finishedAt
		s.FinishedAt = &finished
	}
	if len(j.probes) > 0 {
		s.Probes = append([]Probe(nil), j.probes...)
	}
	for _, h := range j.hops {
		copied := h
		copied.Probes = append([]Probe(nil), h.Probes...)
		copied.Nodes = append([]Node(nil), h.Nodes...)
		s.Hops = append(s.Hops, copied)
	}
	if j.kind == KindPing {
		sum := j.stat.summary()
		s.Summary = &sum
	}
	return s
}

// pingStat 一边探一边累计，这样明细被截断后汇总仍然是整轮的
type pingStat struct {
	sent, received int
	sum, sumSq     float64
	min, max       float64
}

func (s *pingStat) add(p Probe) {
	s.sent++
	if p.Status != StatusOK {
		return
	}
	if s.received == 0 || p.RTTMs < s.min {
		s.min = p.RTTMs
	}
	if p.RTTMs > s.max {
		s.max = p.RTTMs
	}
	s.received++
	s.sum += p.RTTMs
	s.sumSq += p.RTTMs * p.RTTMs
}

// summary 算丢包率与 RTT 的最小/平均/最大/标准差
func (s pingStat) summary() Summary {
	out := Summary{Sent: s.sent, Received: s.received}
	if s.sent == 0 {
		return out
	}
	out.LossPercent = round2(float64(s.sent-s.received) / float64(s.sent) * 100)
	if s.received == 0 {
		return out
	}

	avg := s.sum / float64(s.received)
	variance := s.sumSq/float64(s.received) - avg*avg
	if variance < 0 { // 浮点误差可能算出个极小的负数
		variance = 0
	}
	out.MinMs, out.MaxMs = round2(s.min), round2(s.max)
	out.AvgMs, out.StddevMs = round2(avg), round2(math.Sqrt(variance))
	return out
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

// registry 存着最近的若干次诊断，并记住每种诊断最新的那个任务，
// 前端刷新页面后可以直接接上（不用自己在 localStorage 里记 ID）。
type registry struct {
	mu     sync.Mutex
	jobs   map[string]*Job
	order  []string
	latest map[string]string
	seq    int
}

var reg = &registry{jobs: map[string]*Job{}, latest: map[string]string{}}

func (r *registry) nextID(kind string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	return fmt.Sprintf("%s-%d", kind, r.seq)
}

func (r *registry) add(j *Job) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.jobs[j.id] = j
	r.order = append(r.order, j.id)
	r.latest[j.kind] = j.id

	// 超出保留条数时淘汰最旧的；万一它还在跑，先停掉，别留个没人看的任务一直发包
	for len(r.order) > maxJobs {
		oldest := r.order[0]
		r.order = r.order[1:]
		if old := r.jobs[oldest]; old != nil {
			old.stop()
		}
		delete(r.jobs, oldest)
	}
}

// stopKind 停掉同类的上一个任务：界面上每种诊断只有一块面板，
// 旧任务留着只会白占一个套接字接着发包。
func (r *registry) stopKind(kind string) {
	r.mu.Lock()
	var running []*Job
	for _, j := range r.jobs {
		if j.kind != kind {
			continue
		}
		j.mu.Lock()
		alive := j.running
		j.mu.Unlock()
		if alive {
			running = append(running, j)
		}
	}
	r.mu.Unlock()

	for _, j := range running {
		j.stop()
	}
}

// Get 按 ID 取任务，取不到返回 nil
func Get(id string) *Job {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	return reg.jobs[id]
}

// Latest 取某种诊断最近的一次任务，没有则返回 nil
func Latest(kind string) *Job {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	return reg.jobs[reg.latest[kind]]
}

// Stop 停掉指定任务，返回是否找到
func Stop(id string) bool {
	j := Get(id)
	if j == nil {
		return false
	}
	j.stop()
	return true
}

// Start 发起一次诊断：参数校验、源 IP 校验、开套接字都在这里同步做完，
// 有问题当场报错；真正的探测在后台跑。
func Start(kind string, opts Options) (*Job, error) {
	if err := opts.normalize(kind); err != nil {
		return nil, err
	}

	var source net.IP
	if opts.SourceIP != "" {
		ip, err := netiface.ValidateOutbound(opts.SourceIP)
		if err != nil {
			return nil, err
		}
		source = ip
	}

	reg.stopKind(kind)

	c, err := openICMP(source, kind == KindTrace)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	j := &Job{
		id:         reg.nextID(kind),
		kind:       kind,
		opts:       opts,
		privileged: c.privileged,
		running:    true,
		startedAt:  time.Now(),
		cancel:     cancel,
	}
	if kind == KindTrace && !c.privileged {
		j.note = "当前用的是非特权 ICMP 套接字，部分系统（尤其 Linux）不会把中间路由器的超时回包投给它，可能整趟都是超时；用 root 运行即可。"
	}
	reg.add(j)

	go func() {
		defer cancel()
		// 停止时让阻塞在读上的探测立刻返回
		go func() {
			<-ctx.Done()
			c.close()
		}()
		defer c.close()
		j.run(ctx, c)
	}()

	return j, nil
}

func (j *Job) run(ctx context.Context, c *icmpConn) {
	defer j.finish()

	ip, err := resolveTarget(ctx, j.opts.Target)
	if err != nil {
		j.fail(err)
		return
	}
	j.setResolved(ip.String())

	switch j.kind {
	case KindPing:
		j.runPing(ctx, c, ip)
	case KindTrace:
		j.runTraceroute(ctx, c, ip)
	}
}

// resolveTarget 把目标解析成一个 IPv4 地址；这里只做诊断，IPv6 暂不支持
func resolveTarget(ctx context.Context, target string) (net.IP, error) {
	if ip := net.ParseIP(target); ip != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("%s 是 IPv6 地址，当前只支持 IPv4 诊断", target)
		}
		return ip4, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", target)
	if err != nil {
		return nil, fmt.Errorf("解析 %s 失败: %v", target, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("解析 %s 没有拿到 IPv4 地址", target)
	}
	return ips[0].To4(), nil
}

// lookupName 反查一个地址的域名，查不到就算了（不影响这一跳的结果）
func lookupName(ctx context.Context, addr string) string {
	ctx, cancel := context.WithTimeout(ctx, rdnsTimeout)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, addr)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
