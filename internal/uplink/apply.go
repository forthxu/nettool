package uplink

// 把一条出口线路下发到内核 / 从内核撤下。
//
// 下发顺序是有讲究的：先把默认路由写进本线路的专属表，再装 ip rule。反过来的话，
// 规则一装上，打了标的流量就会去查一张还是空的表，那一瞬间的连接会直接失败。
// 撤销时反过来，先撤规则再清表。

import (
	"fmt"
	"log"
	"net"
	"runtime"
	"strings"
)

// maxRuleSweep 是清扫同一条线路残留规则的次数上限。
// procd 的 respawn 会把崩溃的进程反复拉起（deploy/nettool.init），而 ip rule add
// 并不幂等，没有这个上限的话，解析出错时这里会变成死循环。
const maxRuleSweep = 16

// applyUplink 把一条线路下发到内核，返回更新后的副本
// （RulePrio 可能因为目标优先级被外人占用而顺延，PreferMain 可能被降级）。
func applyUplink(u Uplink) (Uplink, error) {
	if err := u.validate(); err != nil {
		u.Applied, u.LastErr = false, err.Error()
		return u, err
	}
	var err error
	switch runtime.GOOS {
	case "linux":
		u, err = applyLinux(u)
	case "darwin":
		u, err = applyDarwin(u)
	default:
		u, err = applyForeign(u)
	}
	if err != nil {
		u.Applied, u.LastErr = false, err.Error()
		return u, err
	}
	u.Applied, u.LastErr = true, ""
	return u, nil
}

func applyLinux(u Uplink) (Uplink, error) {
	c := Capabilities(nil)
	switch c.Mode {
	case ModeNone:
		return u, fmt.Errorf("当前无法下发策略路由：未以 root 运行")
	case ModeBindDev:
		// 没有可用的 ip rule，内核里没什么可装的：只能靠 SO_BINDTODEVICE
		// 把 socket 绑到网卡上，走的是该网卡自己的默认路由。
		if u.Interface == "" {
			return u, fmt.Errorf("当前 ip 命令不支持策略路由，只能按网卡绑定，但这条线路没有指定网卡")
		}
		u.Mode, u.Degraded = ModeBindDev, true
		return u, nil
	}
	u.Mode, u.Degraded = ModeFwmark, false

	// 1) 先把默认路由写进本线路的专属表
	cmd, err := buildTableRouteCmd(u, "replace")
	if err != nil {
		return u, err
	}
	if _, err := execIP(cmd); err != nil {
		return u, fmt.Errorf("写入路由表 %d 失败: %w", u.Table, err)
	}

	// 2) 清掉这条线路已有的规则：崩溃残留、或是重复 Apply。
	// ip rule add 不幂等，不先清就会静默堆叠。
	if err := removeOurRules(u); err != nil {
		return u, err
	}

	// 3) 挑优先级。目标优先级上坐着别人的规则时顺延，绝不盲删别人的东西。
	prio, err := pickPrio(u)
	if err != nil {
		return u, err
	}
	u.RulePrio = prio

	// 4) 装规则
	return installRules(u)
}

// applyDarwin 处理 macOS。真正的规则下发是整份 anchor 一起加载的（syncPF），
// 由 Manager 在台账变动之后调用；这里只负责把这一条线路校验好、把模式与端口段
// 定下来，让它能被渲染进那份规则集。
func applyDarwin(u Uplink) (Uplink, error) {
	if err := checkInterfaceUp(u.Interface); err != nil {
		return u, err
	}
	c := Capabilities(nil)
	if c.Mode != ModePFRouteTo {
		// PF 不可用，退回 IP_BOUND_IF 的按网卡绑定
		u.Mode, u.Degraded = ModeBoundIF, true
		u.SourcePortStart, u.SourcePortEnd = 0, 0
		return u, nil
	}
	if u.SourceIP == "" {
		// PF 规则按"源 IP + 源端口段"匹配，缺了源 IP 就匹配不上，
		// 流量会静默从默认网关出去——这正是最该拦住的失败方式
		return u, fmt.Errorf("PF 精确出口必须知道本机源地址，请为这条线路指定源 IP")
	}
	u.Mode, u.Degraded = ModePFRouteTo, false
	u.SourcePortStart, u.SourcePortEnd = slotPorts(u.Slot)
	return u, validatePFUplink(u)
}

// applyForeign 处理 Windows 等只能按网卡绑定的平台：内核里没有东西要下发，
// 出口是在 socket 上用 IP_UNICAST_IF 绑网卡实现的，所以这里只做校验，
// 并把"只能按网卡区分"这个事实记下来。
func applyForeign(u Uplink) (Uplink, error) {
	c := Capabilities(nil)
	if c.Mode == ModeNone {
		return u, fmt.Errorf("本平台（%s）不支持绑定出口线路", runtime.GOOS)
	}
	if err := checkInterfaceUp(u.Interface); err != nil {
		return u, err
	}
	u.Mode, u.Degraded = c.Mode, true
	return u, nil
}

func checkInterfaceUp(name string) error {
	if name == "" {
		return fmt.Errorf("本平台的出口要绑到具体网卡上，这条线路必须指定网卡")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("找不到网卡 %s: %w", name, err)
	}
	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("网卡 %s 当前未启用", name)
	}
	return nil
}

// unapplyUplink 把一条线路从内核撤下。撤规则在前、清表在后。
//
// macOS 不走这里：PF 的 anchor 是整份规则集一起加载的，撤一条线路的办法就是
// 在新的规则集里不再渲染它，由 Manager 调 syncPF 完成，见 Manager.refreshPF。
func unapplyUplink(u Uplink) error {
	if runtime.GOOS != "linux" || u.Mode == ModeBindDev {
		return nil // 非 Linux 与降级模式都没往内核里写东西
	}
	if err := removeOurRules(u); err != nil {
		return err
	}
	cmd, err := buildTableRouteCmd(u, "flush")
	if err != nil {
		return err
	}
	if _, err := execIP(cmd); err != nil {
		return fmt.Errorf("清空路由表 %d 失败: %w", u.Table, err)
	}
	return nil
}

// currentRules 读一次 ip rule show
func currentRules() ([]KernelRule, error) {
	out, err := execIP([]string{"ip", "rule", "show"})
	if err != nil {
		return nil, fmt.Errorf("读取 ip rule 失败: %w", err)
	}
	return parseIPRules(out)
}

// removeOurRules 删掉内核里所有属于这条线路（同一个 mark）的规则，不管它们坐在
// 哪个优先级上——用户可能手工挪过。只删 IsOurs() 且 mark 相符的，别人的不碰。
func removeOurRules(u Uplink) error {
	if DryRun {
		log.Printf("[Uplink] (dry-run) 将清除 mark %s 的既有 ip rule", u.MarkSpec())
		return nil
	}
	for i := 0; i < maxRuleSweep; i++ {
		rules, err := currentRules()
		if err != nil {
			return err
		}
		target := -1
		for _, r := range rules {
			if r.IsOurs() && r.Mark == u.Mark {
				target = r.Prio
				break
			}
		}
		if target < 0 {
			return nil
		}
		cmd, err := buildRuleFlushCmd(target)
		if err != nil {
			// 我们的规则跑到了编号范围外，说明有人手工改过；
			// 宁可报错让用户去看，也不要在范围外乱删
			return fmt.Errorf("本程序的规则出现在异常优先级 %d 上，请手动检查后再试: %w", target, err)
		}
		if _, err := execIP(cmd); err != nil && !isRuleMissingError(err) {
			return fmt.Errorf("删除优先级 %d 上的旧规则失败: %w", target, err)
		}
	}
	return fmt.Errorf("清理 mark %s 的旧规则超过 %d 次仍未清空，已放弃", u.MarkSpec(), maxRuleSweep)
}

// pickPrio 给这条线路挑一对空闲的优先级。默认是槽位对应的那一对，
// 被别人占了就往后顺延（步长 2），顺延后的值要落盘——下次删除时得按实际值删。
func pickPrio(u Uplink) (int, error) {
	want := slotPrio(u.Slot)
	if DryRun {
		return want, nil
	}
	rules, err := currentRules()
	if err != nil {
		return 0, err
	}
	taken := make(map[int]bool, len(rules))
	for _, r := range rules {
		// 自己的规则刚被 removeOurRules 清掉了，这里剩下的都算别人的
		if !r.IsOurs() || r.Mark != u.Mark {
			taken[r.Prio] = true
		}
	}
	for p := want; p+1 < rulePrioLimit; p += rulePrioStride {
		if !taken[p] && !taken[p+1] {
			if p != want {
				log.Printf("[Uplink] 优先级 %d 已被其他规则占用，线路「%s」顺延到 %d", want, u.Name, p)
			}
			return p, nil
		}
	}
	return 0, fmt.Errorf("%d..%d 之间已没有空闲的 ip rule 优先级", rulePrioBase, rulePrioLimit-1)
}

// installRules 装规则，并在 ip 不认 suppress_prefixlength 时降级重试。
//
// 降级的后果必须说清楚：没有 suppress_prefixlength，打标流量就完全不查 main 表，
// 「路由管理」里下发的目标路由对绑了出口的实例全部失效。这个状态会被记进
// Capability，界面和启动日志都要说出来（照 route/oscmd.go 里 proto 参数的降级写法）。
func installRules(u Uplink) (Uplink, error) {
	for attempt := 0; attempt < 2; attempt++ {
		cmds, err := buildRuleCmds(u, "add")
		if err != nil {
			return u, err
		}
		var failed error
		for _, c := range cmds {
			if _, err := execIP(c); err != nil && !isRuleExistsError(err) {
				failed = err
				break
			}
		}
		if failed == nil {
			if u.PreferMain {
				noteSuppressSupport(true)
			}
			return u, nil
		}
		if !u.PreferMain {
			return u, fmt.Errorf("下发 ip rule 失败: %w", failed)
		}
		log.Printf("[Uplink] ip 似乎不支持 suppress_prefixlength（%v），线路「%s」降级为不遵循 main 表的目标路由",
			strings.TrimSpace(failed.Error()), u.Name)
		noteSuppressSupport(false)
		u.PreferMain = false
		// 可能已经装上了半条，先清干净再按新形式重试
		if err := removeOurRules(u); err != nil {
			return u, err
		}
	}
	return u, fmt.Errorf("下发 ip rule 失败")
}

// sweepOrphans 清扫内核里属于本程序、但台账里已经没有对应线路的规则与路由表。
// 崩溃（SIGKILL 拦不住）、台账被删、降级重启都会留下这种孤儿，开机对账是唯一
// 可靠的清理时机——所以退出时不做清理，见 README。
func sweepOrphans(known map[int]bool) (int, error) {
	if runtime.GOOS != "linux" || DryRun {
		return 0, nil
	}
	if c := Capabilities(nil); c.Mode != ModeFwmark {
		return 0, nil
	}

	removed := 0
	for i := 0; i < maxRuleSweep*maxSlots; i++ {
		rules, err := currentRules()
		if err != nil {
			return removed, err
		}
		target, slot := -1, -1
		for _, r := range rules {
			if s := r.Slot(); s >= 0 && !known[s] {
				target, slot = r.Prio, s
				break
			}
		}
		if target < 0 {
			break
		}
		cmd, err := buildRuleFlushCmd(target)
		if err != nil {
			return removed, err
		}
		log.Printf("[Uplink] 清扫残留规则: 优先级 %d（槽位 %d，台账中已无对应线路）", target, slot)
		if _, err := execIP(cmd); err != nil && !isRuleMissingError(err) {
			return removed, fmt.Errorf("清扫优先级 %d 的残留规则失败: %w", target, err)
		}
		removed++
	}

	// 规则没了，孤儿表里的路由也一并清掉，免得下次这个槽位被复用时读到旧内容
	for slot := 0; slot < maxSlots; slot++ {
		if known[slot] {
			continue
		}
		out, err := execIP([]string{"ip", "route", "show", "table", fmt.Sprint(slotTable(slot))})
		if err != nil || strings.TrimSpace(out) == "" {
			continue
		}
		log.Printf("[Uplink] 清扫残留路由表 %d", slotTable(slot))
		if _, err := execIP([]string{"ip", "route", "flush", "table", fmt.Sprint(slotTable(slot))}); err != nil {
			log.Printf("[Uplink] 清空残留路由表 %d 失败: %v", slotTable(slot), err)
		}
	}
	return removed, nil
}
