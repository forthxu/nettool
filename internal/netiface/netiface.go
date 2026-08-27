// Package netiface 枚举本机网卡上可用的 IPv4 地址，并尽力找出每个地址实际走的网关。
// SOCKS5 的出口绑定、路由的作用域判断都依赖这里的结果。
package netiface

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
)

// Info 是一个可用的本机 IPv4 地址（同一块网卡有多个地址时会出现多条）
type Info struct {
	Name     string `json:"name"`
	IP       string `json:"ip"`
	CIDR     string `json:"cidr"`
	MAC      string `json:"mac,omitempty"`
	Gateway  string `json:"gateway,omitempty"`
	Loopback bool   `json:"loopback"`
}

// List 返回本机所有已 UP 的 IPv4 地址，供 Web 界面挑选 SOCKS5 出口
func List() []Info {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("[Interfaces] Failed to list interfaces: %v", err)
		return []Info{}
	}

	list := make([]Info, 0, len(ifaces))

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil {
				continue // only IPv4 can be bound as outbound here
			}
			ones, _ := ipNet.Mask.Size()
			list = append(list, Info{
				Name:     iface.Name,
				IP:       ip4.String(),
				CIDR:     fmt.Sprintf("%s/%d", ip4.String(), ones),
				MAC:      iface.HardwareAddr.String(),
				Loopback: iface.Flags&net.FlagLoopback != 0,
			})
		}
	}

	resolveGateways(list)

	// Physical/usable NICs first, loopback last.
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Loopback != list[j].Loopback {
			return !list[i].Loopback
		}
		if (list[i].Gateway != "") != (list[j].Gateway != "") {
			return list[i].Gateway != ""
		}
		return list[i].Name < list[j].Name
	})

	return list
}

// ValidateOutbound 确认要绑定的出口地址真的配在本机某块网卡上——
// 绑一个不存在的地址，要到拨号那一刻才会以一个看不懂的错误失败。
func ValidateOutbound(outboundIP string) (net.IP, error) {
	ip := net.ParseIP(outboundIP)
	if ip == nil {
		return nil, fmt.Errorf("出口 IP %q 不是合法的 IP 地址", outboundIP)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("出口 IP %s 不是 IPv4 地址，暂不支持绑定 IPv6 出口", outboundIP)
	}

	list := List()
	for _, iface := range list {
		if iface.IP == ip4.String() {
			return ip4, nil
		}
	}

	available := make([]string, 0, len(list))
	for _, iface := range list {
		available = append(available, fmt.Sprintf("%s(%s)", iface.IP, iface.Name))
	}
	if len(available) == 0 {
		return nil, fmt.Errorf("出口 IP %s 不属于本机任何网卡（未检测到可用的本机 IPv4 网卡）", outboundIP)
	}
	return nil, fmt.Errorf("出口 IP %s 不属于本机任何网卡，可用的本机 IP: %s", outboundIP, strings.Join(available, ", "))
}
