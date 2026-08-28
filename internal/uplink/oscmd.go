package uplink

// 与操作系统打交道的部分：拼 ip rule / ip route 命令、执行、判断错误类型。
// 与 route/oscmd.go 一样，命令拼装单独拆成纯函数——真正执行需要 root，
// 只有拆开才能被测试覆盖，而这些命令一旦拼错就可能把机器的网络搞瘫。

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
)

// DryRun 打开后只打印将要执行的命令而不真的下发，供 -uplink-dry-run 使用
var DryRun bool

// buildTableRouteCmd 拼"往本线路专属路由表里写默认路由"的命令。
//
// 用 replace 而不是 add：replace 天生幂等，反复执行不会报 File exists，
// 也就不需要先查再写。表号已由 validate 限死在本包的地盘里。
func buildTableRouteCmd(u Uplink, action string) ([]string, error) {
	if err := u.validate(); err != nil {
		return nil, err
	}
	switch action {
	case "replace":
		args := []string{"ip", "route", "replace", "default", "via", u.Gateway}
		if u.Interface != "" {
			args = append(args, "dev", u.Interface)
		}
		// src 让内核给走这条线路的连接挑对源地址。同一块网卡上的两个网关共享
		// 同一个源 IP，靠 src 是分不开的（分得开的是 mark），但写上它能避免
		// 内核在多地址网卡上挑到一个该网关不认的源地址。
		if u.SourceIP != "" {
			args = append(args, "src", u.SourceIP)
		}
		return append(args, "table", strconv.Itoa(u.Table)), nil
	case "flush":
		return []string{"ip", "route", "flush", "table", strconv.Itoa(u.Table)}, nil
	default:
		return nil, fmt.Errorf("未知的路由表操作 %q", action)
	}
}

// buildRuleCmds 拼一条线路的 ip rule 命令，按下发顺序返回。
//
// PreferMain 打开时是两条规则：
//
//	ip rule add priority 300 fwmark M/0xff000000 table main suppress_prefixlength 0
//	ip rule add priority 301 fwmark M/0xff000000 table 7000
//
// 第一条是关键。我们的规则排在 main(32766) 前面，打了标的包本来就不会去查
// main 表——"路由管理"里下发的 proto 210 目标路由、LAN 直连路由会统统失效。
// suppress_prefixlength 0 让 main 表的查询忽略前缀长度为 0 的条目（即默认路由），
// 但保留所有更具体的条目，于是只有"其余一切"才落到本线路的表里。
//
// 删除时带上完整选择符而不是只按优先级删：万一那个优先级上坐着别人的规则，
// 盲删会把人家的规则删掉。
func buildRuleCmds(u Uplink, action string) ([][]string, error) {
	if err := u.validate(); err != nil {
		return nil, err
	}
	verb := "add"
	if action != "add" {
		verb = "del"
	}

	selector := func(prio int, table string, suppress bool) []string {
		args := []string{"ip", "rule", verb, "priority", strconv.Itoa(prio),
			"fwmark", u.MarkSpec(), "table", table}
		if suppress {
			args = append(args, "suppress_prefixlength", "0")
		}
		return args
	}

	var cmds [][]string
	if u.PreferMain {
		cmds = append(cmds, selector(u.mainPrio(), "main", true))
	}
	cmds = append(cmds, selector(u.tablePrio(), strconv.Itoa(u.Table), false))

	// 删除时按倒序撤，先撤兜底的表规则再撤 main 规则，中途失败也不会留下
	// "只查 main 不查本表"这种把流量闷死的中间态
	if verb == "del" {
		for i, j := 0, len(cmds)-1; i < j; i, j = i+1, j-1 {
			cmds[i], cmds[j] = cmds[j], cmds[i]
		}
	}
	return cmds, nil
}

// buildRuleFlushCmd 拼"按优先级删掉某条规则"的命令，只用于清扫崩溃残留的孤儿规则。
// 调用方必须已经用 parseIPRules 确认过该优先级上坐的确实是本程序的规则。
func buildRuleFlushCmd(prio int) ([]string, error) {
	if prio < rulePrioBase || prio >= rulePrioLimit {
		return nil, fmt.Errorf("优先级 %d 不在本程序的编号范围内（%d..%d），拒绝删除",
			prio, rulePrioBase, rulePrioLimit-1)
	}
	return []string{"ip", "rule", "del", "priority", strconv.Itoa(prio)}, nil
}

var (
	errRuleExists  = errors.New("规则已存在于内核中")
	errRuleMissing = errors.New("规则不在内核中")
)

// isRuleMissingError 判断"内核里本来就没有这条规则"。
// iproute2 的文案是 RTNETLINK answers: No such file or directory。
func isRuleMissingError(err error) bool {
	if errors.Is(err, errRuleMissing) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such file or directory") ||
		strings.Contains(msg, "no such process") ||
		strings.Contains(msg, "cannot find")
}

func isRuleExistsError(err error) bool {
	if errors.Is(err, errRuleExists) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "file exists")
}

// execIP 执行一条拼好的命令。DryRun 打开时只打印不执行。
func execIP(argv []string) (string, error) {
	if len(argv) == 0 {
		return "", errors.New("空命令")
	}
	if DryRun {
		log.Printf("[Uplink] (dry-run) %s", strings.Join(argv, " "))
		return "", nil
	}
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("%s: %v (output: %s)", strings.Join(argv, " "), err, text)
	}
	return text, nil
}
