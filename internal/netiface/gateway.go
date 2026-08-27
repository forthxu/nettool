package netiface

// 网关探测。查询按 IP 地址而不是按网卡进行：一块网卡上可能挂着分属不同上游路由器的
// 多个地址（macOS 的多个网络服务、Linux 的 source-based policy routing），
// 绑到哪个地址就从哪个网关出去。

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
)

// resolveGateways 就地填好每条记录的 Gateway 字段
func resolveGateways(list []Info) {
	byIP := gatewaysByIP(list)
	byIface := defaultGatewaysByInterface()

	for i := range list {
		if gw := byIP[list[i].IP]; gw != "" {
			list[i].Gateway = gw
			continue
		}
		list[i].Gateway = byIface[list[i].Name]
	}
}

// gatewaysByIP 得到 本机 IPv4 -> 该地址实际出口网关 的映射。
// 尽力而为：拿不到就返回空 map，由按网卡的默认路由兜底。
func gatewaysByIP(list []Info) map[string]string {
	switch runtime.GOOS {
	case "darwin":
		return darwinServiceGateways()
	case "linux":
		return linuxSourceGateways(list)
	}
	return map[string]string{}
}

// darwinServiceGateways 读每个网络服务的 IPv4 配置 (scutil)，得到 地址 -> Router 的映射。
// macOS 允许同一块网卡上配置多个网络服务，各自拥有独立的路由器地址，
// 而内核路由表里只有优先级最高的那条默认路由。
func darwinServiceGateways() map[string]string {
	result := make(map[string]string)

	listCmd := exec.Command("scutil")
	listCmd.Stdin = strings.NewReader("list State:/Network/Service/[^/]+/IPv4\n")
	listOut, err := listCmd.Output()
	if err != nil {
		return result
	}

	var showCmds strings.Builder
	for _, line := range strings.Split(string(listOut), "\n") {
		//   subKey [0] = State:/Network/Service/<UUID>/IPv4
		idx := strings.Index(line, "State:/Network/Service/")
		if idx < 0 {
			continue
		}
		fmt.Fprintf(&showCmds, "show %s\n", strings.TrimSpace(line[idx:]))
	}
	if showCmds.Len() == 0 {
		return result
	}

	showCmd := exec.Command("scutil")
	showCmd.Stdin = strings.NewReader(showCmds.String())
	showOut, err := showCmd.Output()
	if err != nil {
		return result
	}

	// 每个 show 输出一个 <dictionary> { ... }，其中 Addresses 是地址数组、
	// Router 是该服务的网关；AdditionalRoutes 等嵌套结构靠括号深度跳过。
	var (
		depth     int
		container = map[int]string{}
		addrs     []string
		router    string
	)
	flushBlock := func() {
		if router != "" {
			for _, a := range addrs {
				if _, exists := result[a]; !exists {
					result[a] = router
				}
			}
		}
		addrs = nil
		router = ""
	}

	for _, raw := range strings.Split(string(showOut), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasSuffix(line, "{"):
			name := ""
			if i := strings.Index(line, ":"); i >= 0 {
				name = strings.TrimSpace(line[:i])
			}
			depth++
			container[depth] = name
		case line == "}":
			if depth == 1 {
				flushBlock()
			}
			delete(container, depth)
			depth--
		case depth == 1 && strings.HasPrefix(line, "Router :"):
			gw := strings.TrimSpace(strings.TrimPrefix(line, "Router :"))
			if net.ParseIP(gw) != nil {
				router = gw
			}
		case depth == 2 && container[2] == "Addresses":
			if i := strings.Index(line, ":"); i >= 0 {
				ip := strings.TrimSpace(line[i+1:])
				if net.ParseIP(ip) != nil {
					addrs = append(addrs, ip)
				}
			}
		}
	}
	flushBlock()

	return result
}

// linuxSourceGateways 直接问内核："从这个本机地址发出去的流量走哪个网关"，
// 这样 ip rule / 多路由表 的策略路由也能正确反映。
func linuxSourceGateways(list []Info) map[string]string {
	result := make(map[string]string)

	for _, iface := range list {
		if iface.Loopback {
			continue
		}
		// 仅查询路由表，不产生任何流量
		out, err := exec.Command("ip", "-4", "route", "get", "1.1.1.1", "from", iface.IP).Output()
		if err != nil {
			continue
		}
		// 1.1.1.1 from 192.168.1.5 via 192.168.1.1 dev eth0 ...
		fields := strings.Fields(string(out))
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "via" {
				if net.ParseIP(fields[i+1]) != nil {
					result[iface.IP] = fields[i+1]
				}
				break
			}
		}
	}

	return result
}

// defaultGatewaysByInterface 从系统路由表得到 网卡名 -> 默认网关 的映射，
// 在按地址查不到网关时兜底。不支持的平台返回空 map。
func defaultGatewaysByInterface() map[string]string {
	result := make(map[string]string)

	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("ip", "route", "show", "default").CombinedOutput()
		if err != nil {
			return result
		}
		// default via 192.168.1.1 dev eth0 proto dhcp metric 100
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			var via, dev string
			for i := 0; i < len(fields)-1; i++ {
				switch fields[i] {
				case "via":
					via = fields[i+1]
				case "dev":
					dev = fields[i+1]
				}
			}
			if via != "" && dev != "" {
				if _, exists := result[dev]; !exists {
					result[dev] = via
				}
			}
		}
	case "darwin":
		out, err := exec.Command("netstat", "-nrf", "inet").CombinedOutput()
		if err != nil {
			return result
		}
		// default            192.168.1.1        UGScg             en0
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[0] != "default" {
				continue
			}
			gw := fields[1]
			dev := fields[len(fields)-1]
			if net.ParseIP(gw) == nil {
				continue
			}
			if _, exists := result[dev]; !exists {
				result[dev] = gw
			}
		}
	}

	return result
}
