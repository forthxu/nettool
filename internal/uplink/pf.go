package uplink

// macOS 的出口实现：PF 的 route-to。
//
// macOS 没有 fwmark，也没有 ip rule，但 PF 能按包的五元组把流量 route-to 到
// 指定的下一跳。于是"哪个实例走哪个网关"的选择器就落在**源端口**上：每条线路
// 分一段专属源端口（见 slotPorts），拨号时从段内选一个口绑上（sockopt.Dialer），
// PF 里一条规则按"源 IP + 源端口段"把包直接送到该线路的网关。
//
//	pass out quick on en0 route-to (en0 192.168.1.254) inet proto tcp \
//	     from 192.168.1.5 port 20256:20511 to any flags S/SA keep state user root
//
// 这样同一块网卡上的两个网关也能分开——绑源 IP 做不到这件事（两个网关共用同一个
// 源 IP），绑网卡更做不到。
//
// 为什么 anchor 叫 com.apple/nettool：系统自带的 /etc/pf.conf 里有一行
// `anchor "com.apple/*"`，挂在 com.apple 下的子 anchor 会被自动求值，不需要去改
// 用户的 pf.conf。这一点是整套方案成立的前提，probePF 会实际检查它。
//
// 本文件不用 build tag：这里全是拼命令行 + exec，跨平台可编译，与
// route/oscmd.go、netconfig/nic.go 的惯例一致，靠 runtime.GOOS 分支即可。
// 真正需要 build tag 的只有 internal/sockopt（那里是编译期的 syscall 常量）。

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// pfAnchor 挂在 com.apple 下，借系统 pf.conf 里的 anchor "com.apple/*" 生效
	pfAnchor = "com.apple/nettool"
	// pfConfPath 是系统主规则集，probePF 要确认它真的会求值我们的 anchor
	pfConfPath = "/etc/pf.conf"
	// pfTimeout：pfctl 正常都是毫秒级返回，卡住说明有别的东西持着 PF 的锁
	pfTimeout = 8 * time.Second
)

// pfProbe 是 macOS 上一次性的能力探测结果
type pfProbe struct {
	ok   bool
	msg  string
	root bool
}

var probePF = sync.OnceValue(func() pfProbe {
	if runtime.GOOS != "darwin" {
		return pfProbe{}
	}
	p := pfProbe{root: os.Geteuid() == 0}

	if _, err := os.Stat("/sbin/pfctl"); err != nil {
		p.msg = "找不到 /sbin/pfctl，无法下发 PF 规则"
		return p
	}
	// 系统 pf.conf 必须求值 com.apple 下的子 anchor，否则我们写进去的规则
	// 会静默不生效——流量照样从默认网关出去，是最难排查的那种失败。
	conf, err := os.ReadFile(pfConfPath)
	if err != nil {
		p.msg = fmt.Sprintf("读取 %s 失败: %v", pfConfPath, err)
		return p
	}
	if !pfConfLoadsAppleAnchor(string(conf)) {
		p.msg = fmt.Sprintf("%s 里没有 anchor \"com.apple/*\"，本程序写入的 PF 规则不会被求值", pfConfPath)
		return p
	}
	if !p.root {
		p.msg = "pfctl 需要 root 权限"
		return p
	}
	p.ok = true
	return p
})

// pfConfLoadsAppleAnchor 判断主规则集会不会求值 com.apple 下的子 anchor。
// 只认过滤用的 anchor 行——scrub-anchor / nat-anchor / rdr-anchor / dummynet-anchor
// 管的是别的阶段，route-to 是过滤规则，只有裸的 anchor 才带得动它。
func pfConfLoadsAppleAnchor(conf string) bool {
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "anchor" {
			continue
		}
		name := strings.Trim(fields[1], `"`)
		if name == "com.apple/*" || name == "com.apple" || name == "*" {
			return true
		}
	}
	return false
}

// renderPFRules 把线路列表渲染成 anchor 的规则集。纯函数，能在没有 root 的
// 情况下被测试覆盖——这些规则一旦拼错就可能让流量走错网关，必须测。
//
// 每条线路两条规则，TCP 和 UDP 各一条。UDP 那条不是可选的：代理自己的 DNS
// 查询走 UDP:53，漏了它域名解析会从默认网关出去，既泄漏查询、解析结果也可能
// 和数据连接的出口对不上。
func renderPFRules(list []Uplink) (string, error) {
	var rules strings.Builder
	for _, u := range list {
		if u.Disabled || u.Mode != ModePFRouteTo {
			continue
		}
		if err := validatePFUplink(u); err != nil {
			return "", err
		}
		label := pfLabel(u)
		// flags S/SA keep state 只对 TCP 有意义（按 SYN 建状态）；
		// UDP 用 keep state 让回包能自动放行
		fmt.Fprintf(&rules,
			"pass out quick on %s route-to (%s %s) inet proto tcp from %s port %d:%d to any flags S/SA keep state user root label %s\n",
			u.Interface, u.Interface, u.Gateway, u.SourceIP,
			u.SourcePortStart, u.SourcePortEnd, strconv.Quote(label))
		fmt.Fprintf(&rules,
			"pass out quick on %s route-to (%s %s) inet proto udp from %s port %d:%d to any keep state user root label %s\n",
			u.Interface, u.Interface, u.Gateway, u.SourceIP,
			u.SourcePortStart, u.SourcePortEnd, strconv.Quote(label))
	}
	return rules.String(), nil
}

// pfLabel 让 pfctl -s rules 的输出能对上是哪条线路，也是 Verify 的比对依据。
// PF 的 label 上限 63 字节，超了 pfctl 会整份规则集报错。
func pfLabel(u Uplink) string {
	label := "nettool-" + u.ID
	if len(label) > 63 {
		label = label[:63]
	}
	return label
}

// validatePFUplink 检查一条线路能不能安全地渲染成 PF 规则。
// 这里的每一项都是"拼错了会把流量送错地方"，宁可拒绝下发。
func validatePFUplink(u Uplink) error {
	if ip := net.ParseIP(u.Gateway); ip == nil || ip.To4() == nil {
		return fmt.Errorf("线路「%s」的网关 %q 不是合法的 IPv4 地址", u.Name, u.Gateway)
	}
	if ip := net.ParseIP(u.SourceIP); ip == nil || ip.To4() == nil {
		return fmt.Errorf("线路「%s」缺少合法的本机 IPv4 源地址（PF 规则要按源 IP 匹配）", u.Name)
	}
	if err := validPFInterface(u.Interface); err != nil {
		return fmt.Errorf("线路「%s」: %w", u.Name, err)
	}
	wantStart, wantEnd := slotPorts(u.Slot)
	if u.SourcePortStart != wantStart || u.SourcePortEnd != wantEnd {
		return fmt.Errorf("线路「%s」的源端口段 %d-%d 与槽位 %d 不符",
			u.Name, u.SourcePortStart, u.SourcePortEnd, u.Slot)
	}
	return nil
}

// validPFInterface 白名单校验网卡名。名字是直接拼进规则文本再喂给 pfctl 的，
// 混进空格或换行就等于让调用方往规则集里注入任意规则。
func validPFInterface(name string) error {
	if name == "" || len(name) > 32 {
		return fmt.Errorf("网卡名 %q 不合法", name)
	}
	for _, ch := range name {
		ok := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-'
		if !ok {
			return fmt.Errorf("网卡名 %q 含有非法字符", name)
		}
	}
	return nil
}

// pfState 持有 pfctl -E 拿到的引用令牌。
//
// PF 的启用是**引用计数**的：-E 开启并返回一个 token，-X <token> 归还。macOS 上
// 好几个系统组件（比如「互联网共享」）都这么用。必须走这套，直接 pfctl -d 会把
// 别人依赖的 PF 一起关掉。
//
// 令牌要落盘（uplinks.json 的 pf_token）。理由和整个包存在的理由一样：内核不记
// "这个引用是谁拿的"，进程被 SIGKILL 之后令牌就丢了，那个引用再也归还不了，PF
// 会一直开着直到重启。落盘之后下次启动能把它还回去。
var pfState struct {
	mu    sync.Mutex
	token string
	stale string // 上次运行留下的令牌，启动后归还一次
}

// NoteStalePFToken 把台账里读到的旧令牌交给本包，下次启用 PF 时顺手归还。
// 由 Load 调用。
func NoteStalePFToken(token string) {
	pfState.mu.Lock()
	defer pfState.mu.Unlock()
	if pfState.token == "" {
		pfState.stale = strings.TrimSpace(token)
	}
}

// CurrentPFToken 返回此刻持有的引用令牌，供落盘。没有就是空串。
func CurrentPFToken() string {
	pfState.mu.Lock()
	defer pfState.mu.Unlock()
	return pfState.token
}

// releaseStaleTokenLocked 归还上次运行泄漏的引用。需持有 pfState.mu，
// 且必须在拿到新令牌**之后**调用——否则引用计数可能归零、PF 被短暂关掉。
//
// 尽力而为：机器重启过的话这个令牌早就失效了，pfctl 会报错，忽略即可。
func releaseStaleTokenLocked() {
	if pfState.stale == "" || pfState.stale == pfState.token {
		pfState.stale = ""
		return
	}
	if !probePF().root {
		return // 没权限，留着记录，等哪次以 root 运行时再还
	}
	if _, err := runPFCTL("", "-X", pfState.stale); err != nil {
		log.Printf("[Uplink] 归还上次残留的 PF 引用令牌 %s 失败（多半是机器重启过，可忽略）: %v",
			pfState.stale, err)
	} else {
		log.Printf("[Uplink] 已归还上次运行残留的 PF 引用令牌 %s", pfState.stale)
	}
	pfState.stale = ""
}

// syncPF 把当前全部线路渲染成 anchor 的规则集，整份替换。
//
// 为什么是整份替换而不是逐条增删：PF 的 anchor 本来就是以规则集为单位加载的
// （pfctl -a <anchor> -f -），这天然幂等，崩溃残留也会在下一次加载时被冲掉，
// 不需要 Linux 那边"先解析再删再加"的一整套。
//
// 列表里没有任何 PF 模式的线路时，连 PF 的引用一起归还，把系统恢复原状。
func syncPF(list []Uplink) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	rules, err := renderPFRules(list)
	if err != nil {
		return err
	}
	if strings.TrimSpace(rules) == "" {
		return closePF()
	}
	// dry-run 先于能力检查：这个开关就是用来"看看会执行什么"的，
	// 不该因为当前环境下发不了就什么都不打印
	if DryRun {
		log.Printf("[Uplink] (dry-run) 将写入 PF anchor %s:\n%s", pfAnchor, rules)
		return nil
	}
	if p := probePF(); !p.ok {
		return fmt.Errorf("无法下发 PF 出口规则: %s", p.msg)
	}

	pfState.mu.Lock()
	defer pfState.mu.Unlock()

	fresh := false
	if pfState.token == "" {
		out, err := runPFCTL("", "-E")
		if err != nil {
			return fmt.Errorf("启用 PF 失败: %w", err)
		}
		token, err := parsePFToken(out)
		if err != nil {
			return err
		}
		pfState.token, fresh = token, true
		log.Printf("[Uplink] 已启用 PF（引用令牌 %s）", token)
	}
	// 拿到新令牌之后再还旧的，中间不会出现引用计数归零、PF 被关掉的窗口
	releaseStaleTokenLocked()

	if _, err := runPFCTL(rules, "-a", pfAnchor, "-f", "-"); err != nil {
		// 是我们刚开的 PF 就还回去，别因为一次规则语法错误把 PF 一直开着
		if fresh {
			_, _ = runPFCTL("", "-X", pfState.token)
			pfState.token = ""
		}
		return fmt.Errorf("加载 PF 出口规则失败: %w", err)
	}
	return nil
}

// closePF 清空 anchor 并归还 PF 引用。没拿过引用就什么都不做。
func closePF() error {
	if runtime.GOOS != "darwin" || DryRun {
		return nil
	}
	pfState.mu.Lock()
	defer pfState.mu.Unlock()
	// 本次没启用过 PF，但上次运行可能泄漏了一个引用，照样要还
	releaseStaleTokenLocked()
	if pfState.token == "" {
		return nil
	}
	if _, err := runPFCTL("", "-a", pfAnchor, "-F", "rules"); err != nil {
		return fmt.Errorf("清空 PF anchor %s 失败: %w", pfAnchor, err)
	}
	if _, err := runPFCTL("", "-X", pfState.token); err != nil {
		return fmt.Errorf("归还 PF 引用令牌失败: %w", err)
	}
	log.Printf("[Uplink] 已清空 PF anchor %s 并归还引用", pfAnchor)
	pfState.token = ""
	return nil
}

// pfAnchorRules 读回 anchor 里此刻实际生效的规则。
//
// 这是 macOS 上的"决定性验证"：规则可能被别人的 pfctl -F all 冲掉，那之后流量
// 会静默回落到默认网关。读回来比对是唯一能发现这件事的办法。
func pfAnchorRules() ([]string, error) {
	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("本平台没有 PF")
	}
	out, err := runPFCTL("", "-a", pfAnchor, "-s", "rules")
	if err != nil {
		return nil, err
	}
	return splitLines(out), nil
}

// parsePFToken 从 pfctl -E 的输出里取引用令牌。
// 典型输出：pf enabled\nToken : 12345678901234567890
func parsePFToken(out string) (string, error) {
	fields := strings.Fields(out)
	for i, f := range fields {
		if !strings.EqualFold(strings.TrimSuffix(f, ":"), "token") {
			continue
		}
		for j := i + 1; j < len(fields); j++ {
			if v := strings.TrimSpace(strings.TrimPrefix(fields[j], ":")); v != "" {
				return v, nil
			}
		}
	}
	return "", fmt.Errorf("pfctl 已启用，但输出里没有引用令牌: %s", strings.TrimSpace(out))
}

// runPFCTL 执行 pfctl，stdin 非空时喂给它。带超时：pfctl 会去抢 /dev/pf 的锁，
// 别人不放手时它会一直等，卡在这里会让整个 Apply 流程挂死。
func runPFCTL(stdin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pfTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/sbin/pfctl", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	text := strings.TrimSpace(buf.String())
	if ctx.Err() != nil {
		return text, fmt.Errorf("pfctl %s 超时", strings.Join(args, " "))
	}
	if err != nil {
		if text == "" {
			text = err.Error()
		}
		return text, fmt.Errorf("pfctl %s: %s", strings.Join(args, " "), text)
	}
	return text, nil
}
