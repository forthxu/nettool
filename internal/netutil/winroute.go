package netutil

// Windows `route print -4` 的解析。放在 netutil 是因为路由对账（internal/route）
// 和网关探测（internal/netiface）都要用，而后者不能反过来依赖前者。
//
// 关键点是**不能认表头**：Windows 的命令输出跟着系统语言走，中文版打印的是
// "网络目标"、"在链路上"，德文版的 "Auf Verbindung" 甚至会被切成两个词。
// 所以这里只认数据行的形状——四列点分 IPv4 加一列数字，认不出来的行一律跳过。

import (
	"net"
	"strconv"
	"strings"
)

// WinRoute 是活动路由表里的一行
type WinRoute struct {
	Destination string // 归一化后的 CIDR
	Gateway     string // 空串表示直连（On-link），不是本程序关心的形态
	InterfaceIP string // 出口网卡在本机的地址，Windows 用它而不是网卡名标识接口
	Metric      int
}

// ParseWindowsRoutePrint 解析 route print -4 的活动路由表：
//
//	网络目标            网络掩码          网关           接口       跃点数
//	      0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.10     25
//	  192.168.2.0    255.255.255.0    192.168.1.254   192.168.1.10      1
//	    224.0.0.0        240.0.0.0          On-link    192.168.1.10    281
//
// "永久路由" 一段只有四列（少了接口），第四列落在数字上，形状对不上，自然被跳过；
// IPv6 一段的头两列是接口序号与跃点数，同理。
func ParseWindowsRoutePrint(out string) []WinRoute {
	var list []WinRoute

	for _, raw := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.ReplaceAll(raw, "\r", ""))
		if len(fields) < 5 {
			continue
		}

		dest := parseIPv4(fields[0])
		mask := parseIPv4(fields[1])
		ifaceIP := parseIPv4(fields[3])
		if dest == nil || mask == nil || ifaceIP == nil {
			continue
		}
		ipNet := &net.IPNet{IP: dest.Mask(net.IPMask(mask)), Mask: net.IPMask(mask)}
		if _, bits := ipNet.Mask.Size(); bits != 32 {
			continue // Size 在非连续掩码上返回 0,0：不是正常的路由行
		}

		entry := WinRoute{Destination: ipNet.String(), InterfaceIP: ifaceIP.String()}
		// 网关那一列在直连路由上是 "On-link" 之类的本地化文案，解析不出 IP 就当直连
		if gw := parseIPv4(fields[2]); gw != nil {
			entry.Gateway = gw.String()
		}
		entry.Metric, _ = strconv.Atoi(fields[4])

		list = append(list, entry)
	}

	return list
}

// WindowsDefaultGatewaysByIP 从活动路由表里挑出各出口地址的默认网关，
// 得到 本机 IPv4 -> 默认网关 的映射。同一个地址有多条默认路由时取跃点数最小的。
func WindowsDefaultGatewaysByIP(out string) map[string]string {
	result := make(map[string]string)
	best := make(map[string]int)

	for _, r := range ParseWindowsRoutePrint(out) {
		if r.Destination != "0.0.0.0/0" || r.Gateway == "" || r.InterfaceIP == "" {
			continue
		}
		if cur, ok := best[r.InterfaceIP]; ok && cur <= r.Metric {
			continue
		}
		result[r.InterfaceIP] = r.Gateway
		best[r.InterfaceIP] = r.Metric
	}

	return result
}

func parseIPv4(token string) net.IP {
	ip := net.ParseIP(token)
	if ip == nil {
		return nil
	}
	return ip.To4()
}
