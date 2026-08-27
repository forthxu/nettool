package route

// 内核路由表解析，用于和台账对账：内核里有没有这条、是不是本程序加的。

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"

	"nettool/internal/netutil"
)

// KernelRoute 是从系统路由表里解析出来的一条记录。
// 字段没有 json tag：界面读的就是 Destination/Gateway 这两个名字。
type KernelRoute struct {
	Destination string // 归一化后的 CIDR
	Gateway     string
	Ours        bool // Linux 上带本程序 proto 标记
}

// KernelTable 读取当前内核路由表
func KernelTable() ([]KernelRoute, error) {
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("ip", "route", "show").CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("%v (%s)", err, strings.TrimSpace(string(out)))
		}
		return parseLinuxRoutes(string(out)), nil
	case "darwin":
		out, err := exec.Command("netstat", "-nrf", "inet").CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("%v (%s)", err, strings.TrimSpace(string(out)))
		}
		return parseDarwinRoutes(string(out)), nil
	case "windows":
		out, err := exec.Command("route", "print", "-4").CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("%v (%s)", err, strings.TrimSpace(string(out)))
		}
		return parseWindowsRoutes(string(out)), nil
	default:
		return nil, fmt.Errorf("%s 暂不支持路由对账", runtime.GOOS)
	}
}

// KernelHasRoute 判断某条"目标 + 网关"是否已在内核里
func KernelHasRoute(table []KernelRoute, dest, gateway string) bool {
	for _, r := range table {
		if r.Destination == dest && r.Gateway == gateway {
			return true
		}
	}
	return false
}

// parseLinuxRoutes 解析 ip route show：
//
//	104.20.23.154 via 192.168.1.1 dev eth0 proto 210
//	192.168.2.0/24 via 192.168.1.254 dev eth0
func parseLinuxRoutes(out string) []KernelRoute {
	var result []KernelRoute
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] == "default" {
			continue
		}
		dest, ok := normalizeKernelDest(fields[0])
		if !ok {
			continue
		}
		entry := KernelRoute{Destination: dest}
		for i := 1; i < len(fields)-1; i++ {
			switch fields[i] {
			case "via":
				entry.Gateway = fields[i+1]
			case "proto":
				entry.Ours = fields[i+1] == linuxRouteProto
			}
		}
		if entry.Gateway == "" {
			continue // 直连路由，不是本程序下发的形态
		}
		result = append(result, entry)
	}
	return result
}

// parseDarwinRoutes 解析 netstat -nrf inet：
//
//	Destination        Gateway            Flags     Netif
//	192.168.2          192.168.1.254      UGSc      en0
//	104.20.23.154      192.168.10.249     UGHS      en0
func parseDarwinRoutes(out string) []KernelRoute {
	var result []KernelRoute
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] == "default" || fields[0] == "Destination" {
			continue
		}
		dest, ok := normalizeKernelDest(fields[0])
		if !ok {
			continue
		}
		if net.ParseIP(fields[1]) == nil {
			continue // link#16 / MAC 之类的直连表项
		}
		result = append(result, KernelRoute{Destination: dest, Gateway: fields[1]})
	}
	return result
}

// parseWindowsRoutes 解析 route print -4 的活动路由表。
//
// Windows 没有 Linux 的 proto 标记那样的地方给我们打记号，所以 Ours 恒为 false，
// 孤儿路由检测在这个平台上用不了；台账对账（这条还在不在内核里）不受影响。
func parseWindowsRoutes(out string) []KernelRoute {
	var result []KernelRoute
	for _, r := range netutil.ParseWindowsRoutePrint(out) {
		if r.Gateway == "" {
			continue // 直连（On-link），不是本程序下发的形态
		}
		if r.Destination == "0.0.0.0/0" {
			continue // 默认路由，与其他平台保持一致地跳过
		}
		result = append(result, KernelRoute{Destination: r.Destination, Gateway: r.Gateway})
	}
	return result
}

// normalizeKernelDest 把路由表里的目标写法统一成 CIDR。
// BSD/macOS 会省略掩码与末尾的 0：192.168.2 表示 192.168.2.0/24，
// 172.20.0/23 表示 172.20.0.0/23，裸 IP 表示 /32。
func normalizeKernelDest(token string) (string, bool) {
	addr, mask := token, ""
	if i := strings.Index(token, "/"); i >= 0 {
		addr, mask = token[:i], token[i+1:]
	}

	octets := strings.Split(addr, ".")
	if len(octets) == 0 || len(octets) > 4 || strings.Contains(addr, ":") {
		return "", false
	}
	implied := len(octets) * 8
	for len(octets) < 4 {
		octets = append(octets, "0")
	}
	full := strings.Join(octets, ".")
	if net.ParseIP(full) == nil {
		return "", false
	}
	if mask == "" {
		mask = fmt.Sprintf("%d", implied)
		if implied == 32 {
			mask = "32"
		}
	}

	_, ipNet, err := net.ParseCIDR(full + "/" + mask)
	if err != nil {
		return "", false
	}
	return ipNet.String(), true
}
