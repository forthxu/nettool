package cftunnel

// cloudflared 子进程的托管：启停、日志留存、意外退出后的处理。
//
// 隧道与快速隧道共用这一份，区别只在启动参数和 onLine 回调。
//
// 关于自动重启的取舍：cloudflared 自己会扛住网络抖动（断线重连都在它内部，进程
// 不退），所以进程真的退出基本只有两种情况——令牌/参数不对（起来几秒就死，重试
// 多少次都一样），或者被外力杀掉（跑了很久才死，重启是对的）。于是规则定成：
// 只有活过 minHealthyRun 的进程意外退出才自动拉起来，短命的直接停下并把最后
// 几行日志留在界面上，让用户看见真正的原因。

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	logCapacity     = 400 // 每个进程留最近多少行输出
	maxAutoRestarts = 10
	stopGrace       = 8 * time.Second // 先礼后兵：等它自己收摊多久再动手
)

// 这两个是变量而不是常量，只为了测试能把它们调短——否则验证一次自动重启要等一分钟
var (
	minHealthyRun = 60 * time.Second // 活过这么久才算"曾经是好的"
	restartDelay  = 5 * time.Second
)

// LogLine 是一行进程输出。带 Seq 是为了让前端只取新增的部分。
type LogLine struct {
	Seq  int64     `json:"seq"`
	Time time.Time `json:"time"`
	Text string    `json:"text"`
}

// logRing 是固定容量的日志环
type logRing struct {
	mu    sync.Mutex
	lines []LogLine
	seq   int64
}

func (r *logRing) add(text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	r.lines = append(r.lines, LogLine{Seq: r.seq, Time: time.Now(), Text: text})
	if len(r.lines) > logCapacity {
		r.lines = append(r.lines[:0], r.lines[len(r.lines)-logCapacity:]...)
	}
}

// since 返回序号大于 after 的行；after 为 0 表示要全部
func (r *logRing) since(after int64) []LogLine {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]LogLine, 0, len(r.lines))
	for _, l := range r.lines {
		if l.Seq > after {
			out = append(out, l)
		}
	}
	return out
}

// contains 找日志里有没有出现过某句话
func (r *logRing) contains(sub string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.lines {
		if strings.Contains(l.Text, sub) {
			return true
		}
	}
	return false
}

func (r *logRing) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = nil
}

// process 是一个被托管的 cloudflared 进程
type process struct {
	label string // 日志前缀里的名字

	mu        sync.Mutex
	cmd       *exec.Cmd
	gen       int // 代数：Wait 回来时用它认出"这是我这一代的进程吗"
	running   bool
	stopping  bool // 用户主动停的，退出时不要自动重启
	startedAt time.Time
	lastExit  string
	restarts  int

	logs   logRing
	onLine func(string) // 每行输出的钩子，快速隧道靠它抓分配到的域名
	// restartFn 由 Manager 提供：自动重启时用它重新算一遍启动参数
	// （令牌可能已经变了），返回 nil 表示这条已经不该再跑了。
	restartFn func() (bin string, args []string, env []string, ok bool)
}

// Start 拉起进程。已经在跑的话先原地停掉再起，省得用户点两下留下两个连接器。
func (p *process) Start(bin string, args, env []string) error {
	if bin == "" {
		return fmt.Errorf("还没有可用的 cloudflared 程序")
	}
	p.Stop()

	p.mu.Lock()
	defer p.mu.Unlock()
	return p.startLocked(bin, args, env)
}

// startLocked 需持有 p.mu
func (p *process) startLocked(bin string, args, env []string) error {
	cmd := exec.Command(bin, args...)
	// 继承一份干净的环境：令牌走 env 传（见 Manager.runArgs），不进命令行，
	// 免得同机器上别的用户 ps 一下就把隧道拿走了
	cmd.Env = env

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 %s 失败: %v", bin, err)
	}

	p.cmd = cmd
	p.gen++
	p.running = true
	p.stopping = false
	p.startedAt = time.Now()
	p.lastExit = ""
	gen := p.gen
	started := p.startedAt

	go p.pump(stdout)
	go p.pump(stderr)
	go p.wait(cmd, gen, started)

	p.logs.add(fmt.Sprintf("[nettool] 启动 %s %s", bin, strings.Join(args, " ")))
	return nil
}

func (p *process) pump(r io.ReadCloser) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 256*1024) // cloudflared 偶尔打很长的一行
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		p.logs.add(line)
		p.mu.Lock()
		hook := p.onLine
		p.mu.Unlock()
		if hook != nil {
			hook(line)
		}
	}
	r.Close()
}

// wait 收尸并决定要不要再拉一次
func (p *process) wait(cmd *exec.Cmd, gen int, started time.Time) {
	err := cmd.Wait()
	lived := time.Since(started)

	p.mu.Lock()
	if p.gen != gen {
		p.mu.Unlock() // 这一代早被新进程顶替了，什么都别动
		return
	}
	p.running = false
	p.cmd = nil
	if err != nil {
		p.lastExit = fmt.Sprintf("%s 后退出: %v", formatShort(lived), err)
	} else {
		p.lastExit = fmt.Sprintf("%s 后正常退出", formatShort(lived))
	}
	p.logs.add("[nettool] " + p.lastExit)

	// 用户点的停止，或者短命进程（多半是令牌/参数不对），到此为止
	if p.stopping || lived < minHealthyRun || p.restartFn == nil || p.restarts >= maxAutoRestarts {
		if !p.stopping && p.restarts >= maxAutoRestarts {
			p.logs.add(fmt.Sprintf("[nettool] 已自动重启 %d 次仍在退出，不再重试", p.restarts))
		}
		p.mu.Unlock()
		return
	}
	p.restarts++
	n := p.restarts
	fn := p.restartFn
	p.mu.Unlock()

	log.Printf("[CFTunnel] %s 意外退出（已运行 %s），%s 后自动重启（第 %d 次）",
		p.label, formatShort(lived), restartDelay, n)
	time.Sleep(restartDelay)

	// 等待期间用户可能已经点了停止，或者这条隧道被删了、被手动启过了。
	// 先确认还该重启，再去算启动参数——算参数要打扰 Manager，白算没必要。
	if p.abandonedRestart(gen) {
		return
	}
	bin, args, env, ok := fn()

	p.mu.Lock()
	defer p.mu.Unlock()
	if !ok || p.gen != gen || p.running || p.stopping {
		return
	}
	if err := p.startLocked(bin, args, env); err != nil {
		p.lastExit = err.Error()
		p.logs.add("[nettool] 自动重启失败: " + err.Error())
	}
}

// abandonedRestart 判断这次待办的重启是不是已经不作数了
func (p *process) abandonedRestart(gen int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.gen != gen || p.running || p.stopping
}

// Stop 停掉进程：先按平台的办法请它自己收摊，超时再强杀。
// 已经停了的话是空操作。
func (p *process) Stop() {
	p.mu.Lock()
	if !p.running || p.cmd == nil || p.cmd.Process == nil {
		// 没在跑也要立上 stopping：此刻可能正卡在自动重启的等待里，
		// 不拦住的话用户点完停止，几秒后它自己又活过来了。
		// 下次 Start 会把这个标记清掉。
		p.stopping = true
		p.mu.Unlock()
		return
	}
	p.stopping = true
	p.restarts = 0
	proc := p.cmd.Process
	p.mu.Unlock()

	if err := terminate(proc); err != nil {
		p.logs.add("[nettool] 请求退出失败，改为强制结束: " + err.Error())
		proc.Kill()
	}

	// cloudflared 收到信号后要把已有连接优雅关掉，给它一点时间
	deadline := time.Now().Add(stopGrace)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		done := !p.running
		p.mu.Unlock()
		if done {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	p.logs.add(fmt.Sprintf("[nettool] 等了 %s 还没退出，强制结束", stopGrace))
	proc.Kill()
}

// Status 是进程此刻的实况。StartedAt 用指针是为了停着的时候能真的不出现在
// JSON 里——time.Time 的零值配 omitempty 是不生效的，会变成 0001-01-01。
type Status struct {
	Running   bool       `json:"running"`
	StartedAt *time.Time `json:"started_at,omitempty"`
	Uptime    int        `json:"uptime_seconds"`
	LastExit  string     `json:"last_exit,omitempty"`
	Restarts  int        `json:"restarts,omitempty"`
	// NoIngress 表示连接器手里一条规则都没有，正在对所有请求回 503。
	// 见 noIngressMarker。
	NoIngress bool `json:"no_ingress,omitempty"`
}

// noIngressMarker 是 cloudflared 在「连上了但没有任何 ingress 规则」时打的话。
//
// 这个状态从外面完全看不出来：隧道在云端是 healthy 的、连接数也对，只是每个请求
// 都 503。会走到这里通常是连接器在隧道还归本地托管时起来的——那会儿云端不下发
// 配置，本地又没给 --config，于是它手里是空的，之后隧道转成云端托管也不会补发。
// 与其让人对着一个 healthy 的界面查半天，不如把这句话捞出来摆在状态里。
const noIngressMarker = "No ingress rules were defined"

func (p *process) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := Status{Running: p.running, LastExit: p.lastExit, Restarts: p.restarts}
	if p.running {
		at := p.startedAt
		st.StartedAt = &at
		st.Uptime = int(time.Since(at).Seconds())
		st.NoIngress = p.logs.contains(noIngressMarker)
	}
	return st
}

func (p *process) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}

func formatShort(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1f 秒", d.Seconds())
	}
	return d.Round(time.Second).String()
}
