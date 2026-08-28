package uplink

// 读内核里的策略路由现状。解析全部拆成纯函数，因为执行需要 root，
// 而这些输出的格式差异（iproute2 / ip-tiny / busybox）恰恰是最需要测试的地方。

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// 内核保留的表名。用户自定义的表名来自 /etc/iproute2/rt_tables，
// 我们不去读那个文件——解析不出数字就保留名字，调用方只关心是不是自己的表。
const (
	tableLocalID   = 255
	tableMainID    = 254
	tableDefaultID = 253
)

// KernelRule 是 ip rule show 里的一行
type KernelRule struct {
	Prio      int
	HasMark   bool
	Mark      uint32
	Mask      uint32
	Table     int    // 解析不出数字时为 -1
	TableName string // 原样保留，例如 main / 7000 / 某个自定义名
	Suppress  bool   // 带 suppress_prefixlength
	Raw       string
}

// IsOurs 判断这条规则是不是本程序装的：掩码必须正好是我们的掩码，
// 且 mark 落在我们的编号段里。别人的规则一律不碰。
func (r KernelRule) IsOurs() bool {
	if !r.HasMark || r.Mask != uint32(markMask) {
		return false
	}
	top := r.Mark >> 24
	return r.Mark&^uint32(markMask) == 0 && top >= markBase && top < markBase+maxSlots
}

// Slot 反推这条规则属于哪个槽位，非本程序的规则返回 -1
func (r KernelRule) Slot() int {
	if !r.IsOurs() {
		return -1
	}
	return int(r.Mark>>24) - markBase
}

// parseIPRules 解析 ip rule show 的输出。
//
// iproute2 / ip-tiny 的格式一致：
//
//	0:	from all lookup local
//	300:	from all fwmark 0x40000000/0xff000000 lookup main suppress_prefixlength 0
//	301:	from all fwmark 0x40000000/0xff000000 lookup 7000
//	1001:	from 192.168.1.5 lookup 1
//	32766:	from all lookup main
//
// busybox 未启用 CONFIG_FEATURE_IP_RULE 时会打一段 usage 出来——那种输出里
// 一行都解析不出来，返回错误而不是一个空列表，免得上层把"没规则"和"不支持"搞混。
func parseIPRules(out string) ([]KernelRule, error) {
	var rules []KernelRule
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		colon := strings.Index(line, ":")
		if colon <= 0 {
			continue
		}
		prio, err := strconv.Atoi(strings.TrimSpace(line[:colon]))
		if err != nil {
			continue
		}

		r := KernelRule{Prio: prio, Table: -1, Raw: line}
		fields := strings.Fields(line[colon+1:])
		for i := 0; i < len(fields); i++ {
			switch fields[i] {
			case "fwmark":
				if i+1 >= len(fields) {
					continue
				}
				mark, mask, ok := parseFwmark(fields[i+1])
				if ok {
					r.HasMark, r.Mark, r.Mask = true, mark, mask
				}
				i++
			case "lookup", "table":
				if i+1 >= len(fields) {
					continue
				}
				r.TableName = fields[i+1]
				r.Table = tableNameToID(fields[i+1])
				i++
			case "suppress_prefixlength":
				r.Suppress = true
			}
		}
		rules = append(rules, r)
	}

	if len(rules) == 0 {
		return nil, fmt.Errorf("ip rule 输出中没有可解析的规则行，很可能是当前 ip 命令不支持 rule 子命令：%s",
			firstLine(out))
	}
	return rules, nil
}

// parseFwmark 解析 "0x40000000/0xff000000" 或 "0x40000000"。
// 不带掩码时内核语义是全 1 掩码。
func parseFwmark(s string) (mark, mask uint32, ok bool) {
	value, maskStr, hasMask := strings.Cut(s, "/")
	m, err := strconv.ParseUint(value, 0, 32)
	if err != nil {
		return 0, 0, false
	}
	mask = 0xFFFFFFFF
	if hasMask {
		mm, err := strconv.ParseUint(maskStr, 0, 32)
		if err != nil {
			return 0, 0, false
		}
		mask = uint32(mm)
	}
	return uint32(m), mask, true
}

func tableNameToID(name string) int {
	switch name {
	case "local":
		return tableLocalID
	case "main":
		return tableMainID
	case "default":
		return tableDefaultID
	}
	if n, err := strconv.Atoi(name); err == nil {
		return n
	}
	return -1
}

// RouteGetResult 是 ip route get 的解析结果
type RouteGetResult struct {
	Destination string `json:"destination"`
	Via         string `json:"via,omitempty"` // 直连目标时为空
	Dev         string `json:"dev,omitempty"`
	Src         string `json:"src,omitempty"`
	Raw         string `json:"raw"`
}

// parseRouteGet 解析 ip route get 的输出，例如：
//
//	1.1.1.1 via 192.168.1.254 dev eth0 src 192.168.1.5 mark 0x41000000 uid 0
//	    cache
//
// 首行开头也可能是 unreachable / local / broadcast 这类类型词。
func parseRouteGet(out string) (RouteGetResult, error) {
	line := firstLine(out)
	if line == "" {
		return RouteGetResult{}, fmt.Errorf("ip route get 没有输出")
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return RouteGetResult{}, fmt.Errorf("ip route get 输出无法解析: %s", line)
	}
	if fields[0] == "unreachable" || fields[0] == "prohibit" || fields[0] == "blackhole" {
		return RouteGetResult{Raw: line}, fmt.Errorf("目标不可达（%s），这条线路的网关可能没配好: %s", fields[0], line)
	}

	res := RouteGetResult{Raw: line}
	for i := 0; i < len(fields); i++ {
		if i+1 >= len(fields) {
			break
		}
		switch fields[i] {
		case "via":
			res.Via = fields[i+1]
			i++
		case "dev":
			res.Dev = fields[i+1]
			i++
		case "src":
			res.Src = fields[i+1]
			i++
		}
	}
	// 目标是第一个能解析成 IP 的字段（首字段可能是 local 之类的类型词）
	for _, f := range fields {
		if net.ParseIP(f) != nil {
			res.Destination = f
			break
		}
	}
	if res.Dev == "" && res.Via == "" {
		return res, fmt.Errorf("ip route get 输出里既没有 via 也没有 dev: %s", line)
	}
	return res, nil
}

func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}
