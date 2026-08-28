package uplink

// 能力探测：本平台、本机、此刻究竟能不能做到"同一块网卡上的两个网关分开走"。
//
// 这里的每一句话都会原样呈现给用户，所以宁可说"做不到"，也不要含糊。最坏的
// 失败模式是用户以为流量走了指定线路，实际还在默认网关上——那种情况排查起来
// 极其痛苦，必须在这里就拦住。

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// kernelProbe 是需要 fork 进程的那部分探测，只做一次。
// rp_filter 这种读 /proc 就能拿到的不在这里，每次现读，免得报陈旧信息。
type kernelProbe struct {
	ipRuleOK  bool
	ipRuleMsg string
	tableOK   bool
	tableMsg  string
}

var probeKernel = sync.OnceValue(func() kernelProbe {
	if runtime.GOOS != "linux" {
		return kernelProbe{}
	}
	var p kernelProbe

	// 1) ip rule 子命令是否存在。busybox 未启用 CONFIG_FEATURE_IP_RULE 时
	// 会打一段 usage，parseIPRules 解析不出任何规则行，正好用来判定。
	out, err := execIP([]string{"ip", "rule", "show"})
	switch {
	case err != nil:
		p.ipRuleMsg = fmt.Sprintf("执行 ip rule show 失败: %v", err)
	default:
		if _, perr := parseIPRules(out); perr != nil {
			p.ipRuleMsg = perr.Error()
		} else {
			p.ipRuleOK = true
		}
	}

	// 2) ip route 的 table 参数是否真的生效。这一步不能只看退出码：
	// 精简版的 ip 会把 table 参数**静默忽略**，于是 show table 7000 返回的其实是
	// main 表的内容。真那样的话，我们下发的默认路由会被写进 main 表——直接把
	// 整机的默认网关换掉，是本功能最危险的失败模式，必须在这里就查出来。
	probeTable := strconv.Itoa(tableBase + maxSlots) // 借用一个我们永不使用的表号
	tableOut, terr := execIP([]string{"ip", "route", "show", "table", probeTable})
	mainOut, merr := execIP([]string{"ip", "route", "show"})
	switch {
	case terr != nil:
		p.tableMsg = fmt.Sprintf("执行 ip route show table %s 失败: %v", probeTable, terr)
	case merr == nil && strings.TrimSpace(mainOut) != "" &&
		strings.TrimSpace(tableOut) == strings.TrimSpace(mainOut):
		p.tableMsg = "ip 命令似乎忽略了 table 参数（查询空表返回的却是 main 表内容），" +
			"继续使用会把默认路由写进 main 表、改掉整机的默认网关"
	default:
		p.tableOK = true
	}
	return p
})

// suppressState 记录 suppress_prefixlength 是否可用。它在首次 Apply 时惰性发现
// （下发失败就退回不带该参数的单规则形式），不做投机性的 add/del 探测。
var suppressState struct {
	mu     sync.Mutex
	probed bool
	ok     bool
}

func noteSuppressSupport(ok bool) {
	suppressState.mu.Lock()
	defer suppressState.mu.Unlock()
	suppressState.probed, suppressState.ok = true, ok
}

func suppressSupported() (probed, ok bool) {
	suppressState.mu.Lock()
	defer suppressState.mu.Unlock()
	return suppressState.probed, suppressState.ok
}

// isRoot 判断有没有下发策略路由的权限。Windows 上 Geteuid 返回 -1，
// 判断不了就当有权限，另外用一条 check 提醒需要管理员身份运行。
func isRoot() bool {
	uid := os.Geteuid()
	return uid == 0 || uid == -1
}

// Capabilities 汇总本机此刻的出口能力。interfaces 是当前配置里用到的网卡，
// 用来针对性地检查 rp_filter；传空则只检查全局值。
func Capabilities(interfaces []string) Capability {
	c := Capability{Platform: runtime.GOOS, Root: isRoot()}

	switch runtime.GOOS {
	case "linux":
		p := probeKernel()
		c.Checks = append(c.Checks, Check{
			Name: "ip rule（策略路由）", OK: p.ipRuleOK, Detail: p.ipRuleMsg,
			Remedy: remedyIf(!p.ipRuleOK, "OpenWrt 上执行 opkg update && opkg install ip-full"),
		})
		c.Checks = append(c.Checks, Check{
			Name: "ip route 多路由表", OK: p.tableOK, Detail: p.tableMsg,
			Remedy: remedyIf(!p.tableOK, "OpenWrt 上执行 opkg update && opkg install ip-full"),
		})

		switch {
		case !c.Root:
			c.Mode = ModeNone
		case p.ipRuleOK && p.tableOK:
			c.Mode = ModeFwmark
		default:
			c.Mode = ModeBindDev
		}

		if probed, ok := suppressSupported(); probed && !ok {
			c.Checks = append(c.Checks, Check{
				Name: "suppress_prefixlength", OK: false,
				Detail: "当前 ip 命令不支持该参数。绑定了出口线路的实例将不再遵循" +
					"「路由管理」里下发的目标路由，只有出口线路的默认网关生效",
				Remedy: "OpenWrt 上执行 opkg update && opkg install ip-full",
			})
		}
		c.Checks = append(c.Checks, rpFilterChecks(interfaces)...)

	case "darwin":
		// PF 的 route-to 能按源端口段把包送到指定网关，所以 macOS 也能区分
		// 同一块网卡上的两个网关。PF 不可用时退回 IP_BOUND_IF 的按网卡绑定。
		p := probePF()
		c.Checks = append(c.Checks, Check{
			Name: "PF route-to（精确出口）", OK: p.ok, Detail: p.msg,
			Remedy: remedyIf(!p.ok && !p.root, "以 root 运行（sudo）"),
		})
		if p.ok {
			c.Mode = ModePFRouteTo
		} else {
			c.Mode = ModeBoundIF
		}
	case "windows":
		c.Mode = ModeUnicastIF
		c.Checks = append(c.Checks, Check{
			Name: "管理员权限", OK: true,
			Detail: "Windows 上无法自动判断权限。绑定网卡本身不需要管理员，" +
				"但修改网卡与路由配置需要，请以管理员身份运行",
		})
	default:
		c.Mode = ModeNone
	}

	c.PerGatewaySameInterface = c.Mode == ModeFwmark || c.Mode == ModePFRouteTo

	// 只有 Linux 需要 root 才能绑出口：它要下发 ip rule、还要 SO_MARK
	// （CAP_NET_ADMIN）。macOS 的 IP_BOUND_IF 和 Windows 的 IP_UNICAST_IF 都是
	// 普通权限就能设的，在那两个平台上报 root 警告是误导——macOS 上没有 root
	// 只是用不了 PF 的精确出口，那件事由上面的 PF check 单独说。
	if runtime.GOOS == "linux" && !c.Root {
		c.Checks = append(c.Checks, Check{
			Name: "root 权限", OK: false,
			Detail: "当前不是以 root 运行，无法下发策略路由，也无法给 socket 打标。" +
				"绑定了出口线路的实例会拒绝启动，而不是悄悄从默认网关出去",
			Remedy: "以 root 运行，或给二进制加上 CAP_NET_ADMIN 与 CAP_NET_RAW",
		})
	}
	if c.Mode != ModeNone {
		c.Checks = append(c.Checks, sameInterfaceCheck(c.Mode))
	}
	return c
}

// sameInterfaceCheck 就是界面上那句最关键的话：这台机器此刻能不能把同一块网卡上
// 的两个网关分开。不能的时候要说清楚补救办法，而不是笼统地"本平台不支持"。
func sameInterfaceCheck(mode string) Check {
	switch mode {
	case ModeFwmark:
		return Check{Name: "同网卡多网关", OK: true,
			Detail: "fwmark 策略路由：每条线路一个标记、一张路由表，同一块网卡上的两个网关也能分开"}
	case ModePFRouteTo:
		return Check{Name: "同网卡多网关", OK: true,
			Detail: "PF route-to：每条线路一段专属源端口，同一块网卡上的两个网关也能分开"}
	case ModeBoundIF:
		return Check{Name: "同网卡多网关", OK: false,
			Detail: "PF 不可用，当前只能把出站流量绑到指定网卡，区分不了同一块网卡上的两个网关",
			Remedy: "以 root 运行（sudo）即可启用 PF 精确出口"}
	default:
		return Check{Name: "同网卡多网关", OK: false,
			Detail: "本平台只能把出站流量绑到指定网卡，无法区分同一块网卡上的" +
				"两个网关。需要这个能力请在 Linux / OpenWrt 或 macOS 上运行"}
	}
}

func remedyIf(cond bool, remedy string) string {
	if cond {
		return remedy
	}
	return ""
}

// rpFilterChecks 检查反向路径过滤。严格模式(1) 的反查会忽略 fwmark 规则，
// 跨网卡场景下回包可能被丢弃。同网段双网关一般不受影响（回包本来就从源 IP
// 所在的网卡进来），所以只在真的严格时才报，不要过度告警。
//
// 只读不改：静默改用户的 sysctl 是不能接受的，把确切的命令告诉用户就行。
// 另外提醒一句：src_valid_mark=1 解决的是发包方向，对回包方向没用。
func rpFilterChecks(interfaces []string) []Check {
	all, ok := readRPFilter("all")
	if !ok {
		return nil
	}
	var strict []string
	for _, iface := range interfaces {
		if iface == "" {
			continue
		}
		v, ok := readRPFilter(iface)
		if !ok {
			v = 0
		}
		// 内核取的是 all 与网卡各自设置的较大值
		if max(all, v) == 1 {
			strict = append(strict, iface)
		}
	}
	if all == 1 && len(interfaces) == 0 {
		strict = append(strict, "all")
	}
	if len(strict) == 0 {
		return []Check{{Name: "rp_filter", OK: true}}
	}
	return []Check{{
		Name: "rp_filter", OK: false,
		Detail: fmt.Sprintf("网卡 %s 处于严格模式(1)，跨网卡的出口线路回包可能被内核丢弃"+
			"（同网段双网关一般不受影响）", strings.Join(strict, "、")),
		Remedy: "sysctl -w net.ipv4.conf.all.rp_filter=2（宽松模式）。" +
			"注意 src_valid_mark=1 管的是发包方向，对回包没有帮助",
	}}
}

func readRPFilter(iface string) (int, bool) {
	data, err := os.ReadFile("/proc/sys/net/ipv4/conf/" + iface + "/rp_filter")
	if err != nil {
		return 0, false
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, false
	}
	return v, true
}
