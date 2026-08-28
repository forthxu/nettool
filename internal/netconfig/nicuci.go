package netconfig

// OpenWrt / UCI 后端。
//
// Makefile 里本来就有 router 目标（armv7 / arm64 / mips），但 OpenWrt 上没有
// NetworkManager，nmcli 那条路整个是断的。这里补上 UCI：
//
//	读  ubus call network.interface dump   —— JSON，字段名固定
//	写  uci set / add_list + uci commit + /etc/init.d/network reload
//
// 配置对象是 UCI 的 interface 段名（lan / wan / wwan），对应 Target.Service；
// Device 则是它当前的三层设备（br-lan / eth0 / wlan0），只用于展示。

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
)

// linuxBackend 判断这台机器该用哪套网络配置工具。一台机器不会中途换，所以只判一次。
// 读和写必须用同一个判断，否则会出现"从 UCI 读、往 nmcli 写"这种对不上的情况。
var linuxBackend = sync.OnceValue(func() string {
	if _, err := exec.LookPath("nmcli"); err == nil {
		return "nmcli"
	}
	if _, err := exec.LookPath("uci"); err == nil {
		return "uci"
	}
	return "nmcli" // 都没有时仍按 nmcli 走，错误信息里已经写明了依赖
})

// ubusDump 是 ubus call network.interface dump 的输出
type ubusDump struct {
	Interface []ubusInterface `json:"interface"`
}

type ubusInterface struct {
	Name     string `json:"interface"`
	Up       bool   `json:"up"`
	Proto    string `json:"proto"`
	Device   string `json:"device"`
	L3Device string `json:"l3_device"`
	IPv4     []struct {
		Address string `json:"address"`
		Mask    int    `json:"mask"`
	} `json:"ipv4-address"`
	Route []struct {
		Target  string `json:"target"`
		Mask    int    `json:"mask"`
		Nexthop string `json:"nexthop"`
	} `json:"route"`
	DNS []string `json:"dns-server"`
}

func uciNICs() ([]NIC, error) {
	out, err := runOut("ubus", "call", "network.interface", "dump")
	if err != nil {
		return nil, fmt.Errorf("读取网卡列表失败（OpenWrt 上依赖 ubus/netifd）: %v", err)
	}
	list, err := parseUbusNetworkDump(string(out))
	if err != nil {
		return nil, err
	}
	if ssid, _, err := currentSSID(); err == nil && ssid != "" {
		for i := range list {
			if list[i].Type == "wifi" && list[i].Active {
				list[i].SSID = ssid
			}
		}
	}
	return list, nil
}

// parseUbusNetworkDump 把 ubus 的接口清单转成 NIC 列表
func parseUbusNetworkDump(out string) ([]NIC, error) {
	var dump ubusDump
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &dump); err != nil {
		return nil, fmt.Errorf("解析 ubus 输出失败: %v", err)
	}

	list := make([]NIC, 0, len(dump.Interface))
	for _, in := range dump.Interface {
		device := in.L3Device
		if device == "" {
			device = in.Device
		}
		if in.Name == "loopback" || device == "lo" {
			continue
		}

		cfg := NIC{
			Device:  device,
			Service: in.Name,
			Type:    uciDeviceType(device),
			Method:  uciMethod(in.Proto),
			DNS:     append([]string(nil), in.DNS...),
		}
		if len(in.IPv4) > 0 {
			cfg.IP = in.IPv4[0].Address
			if prefix := in.IPv4[0].Mask; prefix > 0 && prefix <= 32 {
				cfg.Mask = net.IP(net.CIDRMask(prefix, 32)).String()
			}
		}
		for _, r := range in.Route {
			if r.Target == "0.0.0.0" && r.Mask == 0 && r.Nexthop != "" {
				cfg.Gateway = r.Nexthop
				break
			}
		}
		cfg.Active = cfg.IP != ""
		list = append(list, cfg)
	}
	return list, nil
}

// uciMethod 把 UCI 的 proto 翻成本程序的说法。
// OpenWrt 上还有 pppoe / wwan 等，本程序改不了，标成 unknown 只读不写。
func uciMethod(proto string) string {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "static":
		return "manual"
	case "dhcp":
		return "dhcp"
	case "none", "":
		return "off"
	}
	return "unknown"
}

// uciDeviceType 按设备名猜网卡类型。OpenWrt 上没有统一的类型字段，
// 只能看名字：wlan0 / ra0 / wl0 是无线，其余按有线算。
func uciDeviceType(device string) string {
	d := strings.ToLower(device)
	switch {
	case strings.HasPrefix(d, "wlan"), strings.HasPrefix(d, "wl"),
		strings.HasPrefix(d, "ra"), strings.HasPrefix(d, "ath"), strings.HasPrefix(d, "apcli"):
		return "wifi"
	case strings.HasPrefix(d, "eth"), strings.HasPrefix(d, "br-"), strings.HasPrefix(d, "lan"):
		return "ethernet"
	}
	return "other"
}

// buildUCIApplyScript 拼下发脚本。
//
// 整段交给 sh 一次执行，而不是像别的平台那样一条条来：UCI 改配置本来就是
// "改若干项 + commit + reload" 的一组动作，中途失败留下半套配置更糟；而且
// 删除一个不存在的选项时 uci 会返回非零，逐条执行会被当成失败中断。
func buildUCIApplyScript(service string, s Settings) (string, error) {
	if !validUCIName(service) {
		return "", fmt.Errorf("UCI 接口名 %q 不合法（只能是字母、数字和下划线）", service)
	}

	var b strings.Builder
	b.WriteString("set -e\n")
	set := func(option, value string) {
		fmt.Fprintf(&b, "uci set network.%s.%s='%s'\n", service, option, value)
	}
	del := func(option string) {
		// 选项本来就不存在时 uci 返回非零，这里不算失败
		fmt.Fprintf(&b, "uci -q delete network.%s.%s || true\n", service, option)
	}

	if s.Method == "dhcp" {
		set("proto", "dhcp")
		del("ipaddr")
		del("netmask")
		del("gateway")
	} else {
		set("proto", "static")
		set("ipaddr", s.IP)
		set("netmask", s.Mask)
		if s.Gateway != "" {
			set("gateway", s.Gateway)
		} else {
			del("gateway")
		}
	}

	del("dns")
	if len(s.DNS) > 0 {
		for _, d := range s.DNS {
			fmt.Fprintf(&b, "uci add_list network.%s.dns='%s'\n", service, d)
		}
		// 显式 DNS 必须同时关掉上游下发的，否则两份会并存
		set("peerdns", "0")
	} else {
		set("peerdns", "1")
	}

	b.WriteString("uci commit network\n")
	b.WriteString("/etc/init.d/network reload\n")
	return b.String(), nil
}

// validUCIName 校验 UCI 段名。这个值会拼进 shell 脚本，必须挡住注入；
// UCI 本身也只允许字母数字和下划线，所以并没有额外限制到用户。
func validUCIName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		isAlnum := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !isAlnum && r != '_' {
			return false
		}
	}
	return true
}

// parseIwinfoSSID 解析 iwinfo <dev> info 的第一行：
//
//	wlan0     ESSID: "MyNet"
func parseIwinfoSSID(out string) string {
	for _, line := range strings.Split(out, "\n") {
		i := strings.Index(line, "ESSID:")
		if i < 0 {
			continue
		}
		ssid := strings.TrimSpace(line[i+len("ESSID:"):])
		ssid = strings.Trim(ssid, `"`)
		if ssid == "" || ssid == "unknown" {
			continue
		}
		return ssid
	}
	return ""
}

// uciCurrentSSID 在 OpenWrt 上读当前关联的 Wi-Fi 名字。
// 只有路由器自己作为客户端（中继 / apcli）接入时才有意义，做 AP 时读不到属正常。
func uciCurrentSSID() (string, error) {
	out, err := runOut("iwinfo")
	if err != nil {
		return "", fmt.Errorf("读取 SSID 失败（OpenWrt 上依赖 iwinfo）: %v", err)
	}
	if ssid := parseIwinfoSSID(string(out)); ssid != "" {
		return ssid, nil
	}
	return "", fmt.Errorf("未检测到已连接的 Wi-Fi")
}
