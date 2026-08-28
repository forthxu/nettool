package uplink

import (
	"fmt"
	"log"
	"net"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nettool/internal/netiface"
	"nettool/internal/sockopt"
)

// Manager 持有出口线路台账
type Manager struct {
	mu      sync.Mutex
	path    string
	order   []string // 稳定的展示顺序
	uplinks map[string]Uplink
}

func New() *Manager {
	return &Manager{uplinks: make(map[string]Uplink)}
}

// Default 是本进程唯一的出口线路台账
var Default = New()

// Spec 是新建/修改一条线路时的入参
type Spec struct {
	Name      string `json:"name"`
	Gateway   string `json:"gateway"`
	Interface string `json:"interface,omitempty"`
	SourceIP  string `json:"source_ip,omitempty"`
	// PreferMain 留空表示用默认值 true，见 Uplink.PreferMain
	PreferMain *bool `json:"prefer_main,omitempty"`
	// Force 用于在"本平台只能按网卡区分"时，仍然坚持在同一块网卡上建第二条线路。
	// 这种线路会被标成 Degraded，界面上常驻警告。
	Force bool `json:"force,omitempty"`
}

// List 返回全部线路，按创建顺序
func (m *Manager) List() []Uplink {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := make([]Uplink, 0, len(m.uplinks))
	for _, id := range m.order {
		if u, ok := m.uplinks[id]; ok {
			list = append(list, u)
		}
	}
	return list
}

func (m *Manager) Get(id string) (Uplink, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.uplinks[id]
	return u, ok
}

// Capability 汇报本机此刻的出口能力，rp_filter 按台账里实际用到的网卡检查
func (m *Manager) Capability() Capability {
	m.mu.Lock()
	seen := make(map[string]bool, len(m.uplinks))
	ifaces := make([]string, 0, len(m.uplinks))
	for _, u := range m.uplinks {
		if u.Interface != "" && !seen[u.Interface] {
			seen[u.Interface] = true
			ifaces = append(ifaces, u.Interface)
		}
	}
	m.mu.Unlock()
	sort.Strings(ifaces)
	return Capabilities(ifaces)
}

// Add 新建一条出口线路。下发失败时仍然记进台账（带上错误），
// 这样用户能在界面上看到它、改完再点「重新下发」，而不是凭空消失。
func (m *Manager) Add(spec Spec) (Uplink, error) {
	u, err := m.prepare("", spec)
	if err != nil {
		return Uplink{}, err
	}

	applied, applyErr := applyUplink(u)
	m.mu.Lock()
	m.uplinks[applied.ID] = applied
	m.order = append(m.order, applied.ID)
	m.persistLocked()
	m.mu.Unlock()

	if pfErr := m.refreshPF(); pfErr != nil && applyErr == nil {
		applyErr = pfErr
		applied, _ = m.Get(applied.ID)
	}
	if applyErr != nil {
		log.Printf("[Uplink] 新建线路「%s」(%s via %s) 下发失败: %v",
			applied.Name, applied.Interface, applied.Gateway, applyErr)
		return applied, applyErr
	}
	log.Printf("[Uplink] 已下发线路「%s」: 网关 %s，网卡 %s，mark %s，表 %d，优先级 %d",
		applied.Name, applied.Gateway, netutilOrDash(applied.Interface),
		applied.MarkSpec(), applied.Table, applied.RulePrio)
	return applied, nil
}

// Update 修改一条线路：先按旧配置从内核撤下，再按新配置装回去。
// 槽位/mark/表号保持不变——用户可能已经拿这些编号写了自己的防火墙规则。
func (m *Manager) Update(id string, spec Spec) (Uplink, error) {
	m.mu.Lock()
	old, ok := m.uplinks[id]
	m.mu.Unlock()
	if !ok {
		return Uplink{}, fmt.Errorf("出口线路 %s 不存在", id)
	}

	next, err := m.prepare(id, spec)
	if err != nil {
		return Uplink{}, err
	}
	next.Slot, next.Mark, next.Table = old.Slot, old.Mark, old.Table
	next.RulePrio, next.CreatedAt = old.RulePrio, old.CreatedAt
	next.SourcePortStart, next.SourcePortEnd = old.SourcePortStart, old.SourcePortEnd

	if err := unapplyUplink(old); err != nil {
		log.Printf("[Uplink] 撤下线路「%s」的旧配置时出错（继续按新配置下发）: %v", old.Name, err)
	}
	applied, applyErr := applyUplink(next)

	m.mu.Lock()
	m.uplinks[id] = applied
	m.persistLocked()
	m.mu.Unlock()

	if pfErr := m.refreshPF(); pfErr != nil && applyErr == nil {
		applyErr = pfErr
		applied, _ = m.Get(id)
	}
	return applied, applyErr
}

// Delete 删除一条线路，同时把它的规则和路由表从内核撤干净
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	u, ok := m.uplinks[id]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("出口线路 %s 不存在", id)
	}

	unapplyErr := unapplyUplink(u)

	m.mu.Lock()
	delete(m.uplinks, id)
	for i, x := range m.order {
		if x == id {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	m.persistLocked()
	m.mu.Unlock()

	// macOS 上"撤下"就是在新的规则集里不再渲染它，所以删完才重新加载
	if err := m.refreshPF(); err != nil && unapplyErr == nil {
		unapplyErr = err
	}

	if unapplyErr != nil {
		return fmt.Errorf("台账已删除，但从内核撤下时出错: %w", unapplyErr)
	}
	log.Printf("[Uplink] 已删除线路「%s」并清空路由表 %d", u.Name, u.Table)
	return nil
}

// Apply 重新下发一条线路
func (m *Manager) Apply(id string) (Uplink, error) {
	m.mu.Lock()
	u, ok := m.uplinks[id]
	m.mu.Unlock()
	if !ok {
		return Uplink{}, fmt.Errorf("出口线路 %s 不存在", id)
	}

	applied, err := applyUplink(u)
	m.mu.Lock()
	m.uplinks[id] = applied
	m.persistLocked()
	m.mu.Unlock()

	if pfErr := m.refreshPF(); pfErr != nil && err == nil {
		err = pfErr
		applied, _ = m.Get(id)
	}
	return applied, err
}

// refreshPF 在台账变动后重新加载 macOS 的 PF 规则集。
//
// PF 的 anchor 是整份规则集一起加载的，所以任何一条线路的增删改都得把全部线路
// 重新渲染一遍。这也让它天然幂等：崩溃残留会在下一次加载时被整份冲掉，不需要
// Linux 那边"先解析再删再加"的一套。
//
// 加载失败时把所有 PF 模式的线路标成未生效。规则没装上，绑定它们的实例就必须
// 拒绝启动——PF 匹配不上的流量会从默认网关静默出去，那是最糟的失败方式。
func (m *Manager) refreshPF() error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	err := syncPF(m.List())
	if err != nil {
		log.Printf("[Uplink] 加载 PF 出口规则失败: %v，相关线路已标记为未生效", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		for id, u := range m.uplinks {
			if u.Mode == ModePFRouteTo && u.Applied {
				u.Applied, u.LastErr = false, err.Error()
				m.uplinks[id] = u
			}
		}
	}
	// 成功时也要落盘：PF 的引用令牌可能刚拿到或刚归还，那个值必须存下来，
	// 否则进程被 SIGKILL 之后就再也还不回去了
	m.persistLocked()
	return err
}

// Reconcile 是开机对账：先清扫台账里已经没有的残留规则与路由表
// （崩溃、台账被删都会留下这种孤儿），再把台账里的线路逐条下发。
func (m *Manager) Reconcile() (applied int, failed []OpError) {
	m.mu.Lock()
	known := make(map[int]bool, len(m.uplinks))
	targets := make([]Uplink, 0, len(m.uplinks))
	for _, id := range m.order {
		u, ok := m.uplinks[id]
		if !ok {
			continue
		}
		known[u.Slot] = true
		if !u.Disabled {
			targets = append(targets, u)
		}
	}
	m.mu.Unlock()

	if removed, err := sweepOrphans(known); err != nil {
		log.Printf("[Uplink] 清扫残留规则时出错: %v", err)
	} else if removed > 0 {
		log.Printf("[Uplink] 已清扫 %d 条残留规则", removed)
	}

	var ok []string // 逐条下发成功的，macOS 上还要看整份 PF 规则集加不加得上
	for _, u := range targets {
		result, err := applyUplink(u)
		m.mu.Lock()
		m.uplinks[u.ID] = result
		m.mu.Unlock()
		if err != nil {
			failed = append(failed, OpError{ID: u.ID, Error: err.Error()})
			log.Printf("[Uplink] 线路「%s」下发失败: %v", u.Name, err)
			continue
		}
		applied++
		ok = append(ok, u.ID)
	}

	// macOS 的规则要等所有线路都定好模式与端口段之后整份加载一次。
	// 加载失败会把这些线路重新标成未生效，对账结果要跟着改口，不然日志说"已生效"
	// 而界面显示"未生效"，用户不知道该信哪个。
	if err := m.refreshPF(); err != nil {
		for _, id := range ok {
			if cur, exists := m.Get(id); exists && !cur.Applied {
				failed = append(failed, OpError{ID: id, Error: cur.LastErr})
				applied--
			}
		}
	}

	if len(targets) > 0 {
		log.Printf("[Uplink] 开机对账完成：%d 条线路已生效，%d 条失败", applied, len(failed))
	}

	m.mu.Lock()
	m.persistLocked()
	m.mu.Unlock()
	return applied, failed
}

// Cleanup 把本程序装过的所有规则与路由表从内核清干净，供卸载时使用。
// 台账本身不动——用户可能只是想临时恢复系统原状。
func (m *Manager) Cleanup() error {
	for _, u := range m.List() {
		if err := unapplyUplink(u); err != nil {
			log.Printf("[Uplink] 撤下线路「%s」失败: %v", u.Name, err)
		}
	}
	// macOS：清空 anchor 并归还 PF 引用，把系统恢复原状。
	// 归还之后要落盘，否则下次启动还会拿着一个已经还掉的令牌去还一次。
	if err := closePF(); err != nil {
		log.Printf("[Uplink] 清理 PF 规则失败: %v", err)
	}
	m.mu.Lock()
	m.persistLocked()
	m.mu.Unlock()

	removed, err := sweepOrphans(nil)
	if err != nil {
		return err
	}
	log.Printf("[Uplink] 已清理完毕，另清扫了 %d 条残留规则", removed)
	return nil
}

// verifyTarget 是 route-check 默认探测的目标。挑一个公网地址即可——
// 这条命令只查路由表，不发任何流量。
const verifyTarget = "1.1.1.1"

// Verify 用 ip route get ... mark 查内核实际会把这条线路的流量送到哪里。
//
// 这是唯一能证明"同一网段的两个网关真的被分开了"的确定性检查：不需要联网，
// 也不发一个字节。公网 IP 探测在两个网关同属一个 ISP 时是分不出差别的。
func (m *Manager) Verify(id, target string) (RouteGetResult, error) {
	u, ok := m.Get(id)
	if !ok {
		return RouteGetResult{}, fmt.Errorf("出口线路 %s 不存在", id)
	}
	switch m.Capability().Mode {
	case ModeFwmark:
	case ModePFRouteTo:
		return verifyPF(u)
	default:
		return RouteGetResult{}, fmt.Errorf("本机的出口方式是 %s，只能按网卡绑定，"+
			"没有可查的内核状态；请改用实例的「出口 IP」探测来验证", u.Mode)
	}
	if target == "" {
		target = verifyTarget
	}
	if net.ParseIP(target) == nil {
		return RouteGetResult{}, fmt.Errorf("探测目标 %q 不是合法的 IP 地址", target)
	}

	out, err := execIP([]string{"ip", "route", "get", target, "mark", fmt.Sprintf("0x%x", u.Mark)})
	if err != nil {
		return RouteGetResult{}, err
	}
	res, err := parseRouteGet(out)
	if err != nil {
		return res, err
	}
	// 把内核的实际选择与线路配置比一遍，不一致就直说
	if res.Via != "" && res.Via != u.Gateway {
		return res, fmt.Errorf("内核把打了本线路标记的流量送往 %s，而线路配置的网关是 %s",
			res.Via, u.Gateway)
	}
	if u.Interface != "" && res.Dev != "" && res.Dev != u.Interface {
		return res, fmt.Errorf("内核把流量送出网卡 %s，而线路配置的网卡是 %s", res.Dev, u.Interface)
	}
	return res, nil
}

// verifyPF 是 macOS 上的确定性验证：把 anchor 里此刻真正生效的规则读回来，
// 确认这条线路的规则还在、而且指向的仍是配置里那个网关。
//
// 为什么必须读回来：别人一句 pfctl -F all 就能把我们的规则冲掉，之后流量会静默
// 回落到默认网关，从外部完全看不出来。公网 IP 探测在两个网关同属一个 ISP 时
// 也分不出差别，只能作为旁证。
func verifyPF(u Uplink) (RouteGetResult, error) {
	res := RouteGetResult{
		Destination: "PF anchor " + pfAnchor,
		Via:         u.Gateway, Dev: u.Interface, Src: u.SourceIP,
	}
	rules, err := pfAnchorRules()
	if err != nil {
		return res, fmt.Errorf("读取 PF 规则失败: %w", err)
	}

	label := pfLabel(u)
	var mine []string
	for _, line := range rules {
		if strings.Contains(line, label) {
			mine = append(mine, line)
		}
	}
	res.Raw = strings.Join(mine, "\n")
	if len(mine) == 0 {
		return res, fmt.Errorf("PF anchor %s 里没有线路「%s」的规则，"+
			"它可能被别的程序冲掉了（pfctl -F all 会做这件事）；请点「重新下发」",
			pfAnchor, u.Name)
	}
	// 只对上 label 还不够：规则可能是旧配置留下的，网关早就改了
	portSpec := fmt.Sprintf("%d:%d", u.SourcePortStart, u.SourcePortEnd)
	for _, line := range mine {
		if !strings.Contains(line, u.Gateway) {
			return res, fmt.Errorf("PF 里这条线路的规则指向的不是网关 %s，"+
				"内核里是旧配置，请点「重新下发」", u.Gateway)
		}
		if !strings.Contains(line, portSpec) {
			return res, fmt.Errorf("PF 里这条线路的规则源端口段不是 %s，"+
				"内核里是旧配置，请点「重新下发」", portSpec)
		}
	}
	// TCP 和 UDP 各一条，少一条说明 DNS 查询会从默认网关漏出去
	if len(mine) < 2 {
		return res, fmt.Errorf("PF 里只找到 %d 条规则（应为 TCP、UDP 各一条），"+
			"代理自身的 DNS 查询可能从默认网关漏出去，请点「重新下发」", len(mine))
	}
	return res, nil
}

// EnsureForSourceIP 找出（或新建）一条从指定本机 IP 出去的线路，返回线路 id。
//
// 只给一处用：代理配置从旧的「绑定出口 IP」迁移到出口线路。旧配置里那个 IP 表达的
// 意图就是"走这块网卡的网关"，把它翻译成一条线路，升级后出口才不会静默改变。
//
// 返回的 id 可能非空而 err 也非空——线路建好了但下发失败（比如没有 root）。
// 这时调用方仍应绑定它：绑一条"未生效"的线路会让实例拒绝启动并报出原因，
// 好过让实例悄悄从默认网关出去。
func (m *Manager) EnsureForSourceIP(sourceIP, name string) (string, error) {
	ip := strings.TrimSpace(sourceIP)
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("%q 不是合法的 IP 地址", sourceIP)
	}

	existing := m.List()
	for _, u := range existing {
		if u.SourceIP == ip {
			return u.ID, nil // 已经有一条从这个地址出去的线路
		}
	}

	// 从本机网卡里查出这个地址挂在哪块网卡、对应哪个网关
	var gateway, iface string
	for _, info := range netiface.List() {
		if info.IP == ip {
			gateway, iface = info.Gateway, info.Name
			break
		}
	}
	if iface == "" {
		return "", fmt.Errorf("本机没有 IP 为 %s 的网卡", ip)
	}
	if gateway == "" {
		return "", fmt.Errorf("网卡 %s 上的 %s 查不到对应网关", iface, ip)
	}
	for _, u := range existing {
		if u.Gateway == gateway {
			return u.ID, nil // 这个网关已经有线路了，直接复用
		}
	}

	// Force：本平台只能按网卡区分时，同一块网卡上可能已经有线路了。
	// 迁移是为了保住原有行为，不该被这条限制挡住。
	u, err := m.Add(Spec{Name: name, Gateway: gateway, Interface: iface, SourceIP: ip, Force: true})
	return u.ID, err
}

// KernelDump 原样返回内核里的策略路由现状，供界面排查用：
// 规则到底装上没有、有没有被别人挤掉、表里是不是空的。对标 route.SystemRoutes。
func (m *Manager) KernelDump() map[string]interface{} {
	dump := map[string]interface{}{"platform": runtime.GOOS}
	if runtime.GOOS == "darwin" {
		dump["note"] = "macOS 用 PF 的 route-to 按源端口段选网关，以下是 anchor " +
			pfAnchor + " 里此刻生效的规则"
		if rules, err := pfAnchorRules(); err != nil {
			dump["rules_error"] = err.Error()
		} else if len(rules) == 0 {
			dump["rules"] = []string{"（anchor 是空的——没有任何线路的规则装上）"}
		} else {
			dump["rules"] = rules
		}
		return dump
	}
	if runtime.GOOS != "linux" {
		dump["note"] = "本平台没有策略路由，出口是在 socket 上绑网卡实现的"
		return dump
	}

	if out, err := execIP([]string{"ip", "rule", "show"}); err != nil {
		dump["rules_error"] = err.Error()
	} else {
		dump["rules"] = splitLines(out)
	}

	tables := make(map[string][]string)
	for _, u := range m.List() {
		key := strconv.Itoa(u.Table)
		out, err := execIP([]string{"ip", "route", "show", "table", key})
		if err != nil {
			tables[key] = []string{"读取失败: " + err.Error()}
			continue
		}
		if lines := splitLines(out); len(lines) > 0 {
			tables[key] = lines
		} else {
			tables[key] = []string{"（空表——这条线路的默认路由没装上）"}
		}
	}
	dump["tables"] = tables
	return dump
}

func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// DialOptions 给绑定了某条线路的实例提供拨号时要施加的出口约束。
// id 为空表示走系统默认线路，此时返回零值，拨号路径与不绑出口时完全一致。
func (m *Manager) DialOptions(id string) (sockopt.Egress, error) {
	if id == "" {
		return sockopt.Egress{}, nil
	}
	u, ok := m.Get(id)
	if !ok {
		return sockopt.Egress{}, fmt.Errorf("出口线路 %s 不存在", id)
	}
	if u.Disabled {
		return sockopt.Egress{}, fmt.Errorf("出口线路「%s」已停用", u.Name)
	}
	// 没生效就拒绝，不能退回默认线路：用户以为走的是这条线路，
	// 悄悄从默认网关出去是最糟糕的失败方式。
	if !u.Applied {
		detail := u.LastErr
		if detail == "" {
			detail = "尚未下发"
		}
		return sockopt.Egress{}, fmt.Errorf("出口线路「%s」当前未生效: %s", u.Name, detail)
	}

	switch u.Mode {
	case ModeFwmark:
		// 只打 mark，不绑源地址：同一块网卡上的两个网关共享同一个源 IP，
		// 绑源地址既分不开它们，还可能绑到目标网关不认的地址上。
		// 源地址交给路由表项里的 src 让内核挑，见 buildTableRouteCmd。
		return sockopt.Egress{Options: sockopt.Options{Mark: u.Mark}}, nil
	case ModeBindDev:
		return sockopt.Egress{
			Options: sockopt.Options{IfName: u.Interface}, SourceIP: u.SourceIP,
		}, nil
	case ModePFRouteTo:
		// 源端口段就是这条线路的选择器：PF 里那条 route-to 规则按
		// "源 IP + 源端口段"匹配，两者缺一不可，见 renderPFRules。
		// IP_BOUND_IF 是额外的一层，保证内核选路阶段就落在这块网卡上。
		idx, err := ifIndex(u.Interface)
		if err != nil {
			return sockopt.Egress{}, err
		}
		return sockopt.Egress{
			Options:   sockopt.Options{IfIndex: idx},
			SourceIP:  u.SourceIP,
			PortStart: u.SourcePortStart,
			PortEnd:   u.SourcePortEnd,
		}, nil
	case ModeBoundIF, ModeUnicastIF:
		idx, err := ifIndex(u.Interface)
		if err != nil {
			return sockopt.Egress{}, err
		}
		return sockopt.Egress{
			Options: sockopt.Options{IfIndex: idx}, SourceIP: u.SourceIP,
		}, nil
	default:
		return sockopt.Egress{}, fmt.Errorf("出口线路「%s」的生效方式未知（%s）", u.Name, u.Mode)
	}
}

func ifIndex(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("找不到网卡 %s: %w", name, err)
	}
	return iface.Index, nil
}

// prepare 校验并补全一份 Spec，生成待下发的 Uplink。id 为空表示新建。
func (m *Manager) prepare(id string, spec Spec) (Uplink, error) {
	gateway := strings.TrimSpace(spec.Gateway)
	if ip := net.ParseIP(gateway); ip == nil || ip.To4() == nil {
		return Uplink{}, fmt.Errorf("网关 %q 不是合法的 IPv4 地址", spec.Gateway)
	}
	name := strings.TrimSpace(spec.Name)
	if name == "" {
		name = gateway
	}

	iface, srcIP, err := resolveEgress(gateway, strings.TrimSpace(spec.Interface), strings.TrimSpace(spec.SourceIP))
	if err != nil {
		return Uplink{}, err
	}

	c := m.Capability()
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, other := range m.uplinks {
		if other.ID == id {
			continue
		}
		if other.Gateway == gateway {
			return Uplink{}, fmt.Errorf("网关 %s 已经被线路「%s」使用", gateway, other.Name)
		}
		// 只能按网卡区分的平台上，同一块网卡的第二条线路是分不开的。
		// 不默默接受一个做不到的配置，除非用户显式 force。
		if !c.PerGatewaySameInterface && other.Interface == iface && !spec.Force {
			return Uplink{}, fmt.Errorf(
				"网卡 %s 上已有线路「%s」。本平台（%s）只能按网卡区分出口，"+
					"同一块网卡上的两个网关无法分开；确实要建请显式选择「强制创建」",
				iface, other.Name, c.Platform)
		}
	}

	u := Uplink{
		ID: id, Name: name, Gateway: gateway, Interface: iface, SourceIP: srcIP,
		PreferMain: spec.PreferMain == nil || *spec.PreferMain,
		Degraded:   !c.PerGatewaySameInterface,
	}
	if id == "" {
		slot, err := m.allocateSlotLocked()
		if err != nil {
			return Uplink{}, err
		}
		u.ID = m.nextIDLocked()
		u.Slot, u.Mark, u.Table, u.RulePrio = slot, slotMark(slot), slotTable(slot), slotPrio(slot)
		u.SourcePortStart, u.SourcePortEnd = slotPorts(slot)
		u.CreatedAt = time.Now()
	}
	return u, nil
}

// allocateSlotLocked 挑一个最小的空闲槽位。需持有 m.mu。
func (m *Manager) allocateSlotLocked() (int, error) {
	used := make(map[int]bool, len(m.uplinks))
	for _, u := range m.uplinks {
		used[u.Slot] = true
	}
	for slot := 0; slot < maxSlots; slot++ {
		if !used[slot] {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("出口线路数量已达上限 %d 条", maxSlots)
}

// nextIDLocked 生成不与现有记录冲突的 ID。需持有 m.mu。
func (m *Manager) nextIDLocked() string {
	maxN := 0
	for id := range m.uplinks {
		if n, err := strconv.Atoi(strings.TrimPrefix(id, "u")); err == nil && n > maxN {
			maxN = n
		}
	}
	return "u" + strconv.Itoa(maxN+1)
}

// resolveEgress 补全网关所在的网卡与源地址。
//
// 优先选"系统就是把这个网关配给这块网卡的"那一块（最可靠），否则退而求其次选
// 网段能覆盖该网关的。这与 route.scopeInterface 判断作用域网卡的思路一致。
func resolveEgress(gateway, iface, srcIP string) (string, string, error) {
	gw := net.ParseIP(gateway)
	list := netiface.List()

	var best, fallback netiface.Info
	for _, info := range list {
		if info.Loopback {
			continue
		}
		if iface != "" && info.Name != iface {
			continue
		}
		if info.Gateway == gateway && best.Name == "" {
			best = info
		}
		if fallback.Name == "" {
			if _, ipNet, err := net.ParseCIDR(info.CIDR); err == nil && ipNet.Contains(gw) {
				fallback = info
			}
		}
	}
	pick := best
	if pick.Name == "" {
		pick = fallback
	}

	if iface == "" {
		if pick.Name == "" {
			return "", "", fmt.Errorf("找不到能到达网关 %s 的网卡，请手动指定网卡", gateway)
		}
		iface = pick.Name
	}
	if srcIP == "" {
		if pick.Name == "" {
			// 指定了网卡但网段覆盖不到网关（点对点链路等），源地址就由内核自己挑
			return iface, "", nil
		}
		srcIP = pick.IP
	} else if _, err := netiface.ValidateOutbound(srcIP); err != nil {
		return "", "", err
	}
	return iface, srcIP, nil
}

// netutilOrDash 只用于日志，避免为一个短横线去 import netutil
func netutilOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
