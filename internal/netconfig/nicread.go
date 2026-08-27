package netconfig

// 读取当前网卡配置。三个平台各有各的命令与输出格式，解析部分都拆成纯函数便于测试。

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// ListNICs 返回本机所有网卡的当前配置
func ListNICs() ([]NIC, error) {
	switch runtime.GOOS {
	case "darwin":
		return darwinNICs()
	case "linux":
		return linuxNICs()
	case "windows":
		return windowsNICs()
	}
	return nil, fmt.Errorf("暂不支持在 %s 上读取网卡配置", runtime.GOOS)
}

// ---------------------------------------------------------
// macOS: networksetup
// ---------------------------------------------------------

type macService struct {
	Service      string
	Device       string
	HardwarePort string
	Disabled     bool
}

// parseNetworksetupOrder 解析 networksetup -listnetworkserviceorder：
//
//	(1) Wi-Fi
//	(Hardware Port: Wi-Fi, Device: en0)
//
// 被停用的服务名前带 *。
func parseNetworksetupOrder(out string) []macService {
	var list []macService
	var cur *macService

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "(Hardware Port:") {
			if cur == nil {
				continue
			}
			body := strings.TrimSuffix(strings.TrimPrefix(line, "("), ")")
			for _, part := range strings.Split(body, ", ") {
				kv := strings.SplitN(part, ": ", 2)
				if len(kv) != 2 {
					continue
				}
				switch strings.TrimSpace(kv[0]) {
				case "Hardware Port":
					cur.HardwarePort = strings.TrimSpace(kv[1])
				case "Device":
					cur.Device = strings.TrimSpace(kv[1])
				}
			}
			list = append(list, *cur)
			cur = nil
			continue
		}

		// "(1) Wi-Fi" —— 序号后面是服务名
		if !strings.HasPrefix(line, "(") {
			continue
		}
		closeIdx := strings.Index(line, ")")
		if closeIdx < 0 {
			continue
		}
		idx := line[1:closeIdx]
		if _, err := strconv.Atoi(idx); err != nil {
			continue // 说明书那行 "An asterisk (*) denotes..." 不是服务
		}
		name := strings.TrimSpace(line[closeIdx+1:])
		disabled := strings.HasPrefix(name, "*")
		cur = &macService{Service: strings.TrimPrefix(name, "*"), Disabled: disabled}
	}
	return list
}

// parseNetworksetupInfo 解析 networksetup -getinfo "<service>"
func parseNetworksetupInfo(out string) NIC {
	cfg := NIC{Method: "unknown"}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "DHCP Configuration", line == "BOOTP Configuration":
			cfg.Method = "dhcp"
			continue
		case line == "Manual Configuration":
			cfg.Method = "manual"
			continue
		case strings.HasPrefix(line, "Manually Using DHCP Router"):
			cfg.Method = "manual"
			continue
		}

		kv := strings.SplitN(line, ": ", 2)
		if len(kv) != 2 {
			continue
		}
		key, val := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		if val == "none" || val == "" {
			continue
		}
		switch key {
		case "IP address":
			if cfg.IP == "" { // 后面还有 IPv6 IP address，别覆盖
				cfg.IP = val
			}
		case "Subnet mask":
			cfg.Mask = val
		case "Router":
			cfg.Gateway = val
		}
	}
	cfg.Active = cfg.IP != ""
	return cfg
}

// parseMacDNSServers 解析 networksetup -getdnsservers：没配过时会打印一句
// "There aren't any DNS Servers set on Wi-Fi."
func parseMacDNSServers(out string) []string {
	var list []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if net.ParseIP(line) == nil {
			continue
		}
		list = append(list, line)
	}
	return list
}

func darwinNICs() ([]NIC, error) {
	out, err := exec.Command("networksetup", "-listnetworkserviceorder").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("读取网络服务列表失败: %s", strings.TrimSpace(string(out)))
	}

	services := parseNetworksetupOrder(string(out))
	ssid, _, _ := currentSSID()

	list := make([]NIC, 0, len(services))
	for _, svc := range services {
		cfg := NIC{
			Device:   svc.Device,
			Service:  svc.Service,
			Type:     macPortType(svc.HardwarePort),
			Method:   "unknown",
			Disabled: svc.Disabled,
		}

		infoOut, err := exec.Command("networksetup", "-getinfo", svc.Service).CombinedOutput()
		if err != nil {
			cfg.Error = strings.TrimSpace(string(infoOut))
		} else {
			parsed := parseNetworksetupInfo(string(infoOut))
			cfg.Method, cfg.IP, cfg.Mask, cfg.Gateway, cfg.Active = parsed.Method, parsed.IP, parsed.Mask, parsed.Gateway, parsed.Active
		}

		if dnsOut, err := exec.Command("networksetup", "-getdnsservers", svc.Service).CombinedOutput(); err == nil {
			cfg.DNS = parseMacDNSServers(string(dnsOut))
		}
		if cfg.Type == "wifi" && cfg.Active {
			cfg.SSID = ssid
		}
		list = append(list, cfg)
	}
	return list, nil
}

func macPortType(hardwarePort string) string {
	p := strings.ToLower(hardwarePort)
	switch {
	case strings.Contains(p, "wi-fi"), strings.Contains(p, "airport"), strings.Contains(p, "wifi"):
		return "wifi"
	case strings.Contains(p, "ethernet"), strings.Contains(p, "lan"), strings.Contains(p, "thunderbolt"), strings.Contains(p, "usb"):
		return "ethernet"
	}
	return "other"
}

// ---------------------------------------------------------
// Linux: nmcli
// ---------------------------------------------------------

// parseNmcliDeviceStatus 解析 nmcli -t -f DEVICE,TYPE,STATE,CONNECTION device status
func parseNmcliDeviceStatus(out string) []NIC {
	var list []NIC
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := splitNmcli(line)
		if len(fields) < 4 {
			continue
		}
		dev, typ, state, con := fields[0], fields[1], fields[2], fields[3]
		if typ == "loopback" {
			continue
		}
		kind := "other"
		switch typ {
		case "wifi":
			kind = "wifi"
		case "ethernet":
			kind = "ethernet"
		}
		list = append(list, NIC{
			Device:  dev,
			Service: con,
			Type:    kind,
			Method:  "unknown",
			Active:  strings.HasPrefix(state, "connected"),
		})
	}
	return list
}

// parseNmcliDeviceShow 解析 nmcli -t -f IP4.ADDRESS,IP4.GATEWAY,IP4.DNS device show <dev>
func parseNmcliDeviceShow(out string) NIC {
	cfg := NIC{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key, val := kv[0], strings.TrimSpace(kv[1])
		if val == "" || val == "--" {
			continue
		}
		switch {
		case strings.HasPrefix(key, "IP4.ADDRESS"):
			// 192.168.1.20/24
			parts := strings.SplitN(val, "/", 2)
			if cfg.IP == "" {
				cfg.IP = parts[0]
				if len(parts) == 2 {
					if prefix, err := strconv.Atoi(parts[1]); err == nil && prefix >= 0 && prefix <= 32 {
						cfg.Mask = net.IP(net.CIDRMask(prefix, 32)).String()
					}
				}
			}
		case strings.HasPrefix(key, "IP4.GATEWAY"):
			cfg.Gateway = val
		case strings.HasPrefix(key, "IP4.DNS"):
			cfg.DNS = append(cfg.DNS, val)
		}
	}
	cfg.Active = cfg.IP != ""
	return cfg
}

// splitNmcli 按 nmcli -t 的转义规则切分（字段分隔符是 :，字面冒号写作 \:）
func splitNmcli(line string) []string {
	var fields []string
	var cur strings.Builder
	escaped := false
	for _, r := range line {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == ':':
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	fields = append(fields, cur.String())
	return fields
}

// linuxNICs 按当前系统装的是哪套工具分流：桌面/服务器发行版走 NetworkManager，
// OpenWrt 之类没有 nmcli 的走 UCI。
func linuxNICs() ([]NIC, error) {
	if linuxBackend() == "uci" {
		return uciNICs()
	}
	return nmcliNICs()
}

func nmcliNICs() ([]NIC, error) {
	out, err := exec.Command("nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("读取网卡列表失败（本功能依赖 NetworkManager 的 nmcli）: %s", strings.TrimSpace(string(out)))
	}

	list := parseNmcliDeviceStatus(string(out))
	for i := range list {
		if showOut, err := exec.Command("nmcli", "-t", "-f", "IP4.ADDRESS,IP4.GATEWAY,IP4.DNS", "device", "show", list[i].Device).CombinedOutput(); err == nil {
			d := parseNmcliDeviceShow(string(showOut))
			list[i].IP, list[i].Mask, list[i].Gateway, list[i].DNS = d.IP, d.Mask, d.Gateway, d.DNS
		}
		if list[i].Service == "" {
			continue
		}
		if mOut, err := exec.Command("nmcli", "-t", "-f", "ipv4.method", "connection", "show", list[i].Service).CombinedOutput(); err == nil {
			switch strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(mOut)), "ipv4.method:")) {
			case "auto":
				list[i].Method = "dhcp"
			case "manual":
				list[i].Method = "manual"
			case "disabled":
				list[i].Method = "off"
			}
		}
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

// ---------------------------------------------------------
// Windows: netsh
// ---------------------------------------------------------

// parseNetshInterfaceConfig 解析 netsh interface ip show config
func parseNetshInterfaceConfig(out string) []NIC {
	var list []NIC
	var cur *NIC
	flush := func() {
		if cur != nil {
			cur.Active = cur.IP != ""
			list = append(list, *cur)
			cur = nil
		}
	}

	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(strings.ReplaceAll(raw, "\r", ""))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Configuration for interface") {
			flush()
			name := strings.TrimSpace(strings.TrimPrefix(line, "Configuration for interface"))
			name = strings.Trim(name, `" `)
			cur = &NIC{Device: name, Service: name, Type: "other", Method: "unknown"}
			continue
		}
		if cur == nil {
			continue
		}
		// DNS 服务器第二条起是没有键名的续行
		if net.ParseIP(line) != nil {
			if len(cur.DNS) > 0 {
				cur.DNS = append(cur.DNS, line)
			}
			continue
		}

		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key, val := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		switch {
		case strings.HasPrefix(key, "DHCP enabled"):
			if strings.EqualFold(val, "Yes") {
				cur.Method = "dhcp"
			} else {
				cur.Method = "manual"
			}
		case strings.HasPrefix(key, "IP Address"), strings.HasPrefix(key, "Static IP Address"):
			if cur.IP == "" {
				cur.IP = val
			}
		case strings.HasPrefix(key, "Subnet Prefix"):
			// "192.168.1.0/24 (mask 255.255.255.0)"
			if i := strings.Index(val, "mask "); i >= 0 {
				cur.Mask = strings.TrimSuffix(strings.TrimSpace(val[i+5:]), ")")
			}
		case strings.HasPrefix(key, "Default Gateway"):
			cur.Gateway = val
		case strings.HasPrefix(key, "Statically Configured DNS Servers"),
			strings.HasPrefix(key, "DNS servers configured through DHCP"):
			if net.ParseIP(val) != nil {
				cur.DNS = append(cur.DNS, val)
			}
		}
	}
	flush()
	return list
}

func windowsNICs() ([]NIC, error) {
	out, err := exec.Command("netsh", "interface", "ip", "show", "config").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("读取网卡配置失败: %s", strings.TrimSpace(string(out)))
	}
	list := parseNetshInterfaceConfig(string(out))

	ssid, _, _ := currentSSID()
	if wlanOut, err := exec.Command("netsh", "wlan", "show", "interfaces").CombinedOutput(); err == nil {
		name := parseNetshWlanInterfaceName(string(wlanOut))
		for i := range list {
			if name != "" && strings.EqualFold(list[i].Device, name) {
				list[i].Type = "wifi"
				list[i].SSID = ssid
			}
		}
	}
	return list, nil
}

func parseNetshWlanInterfaceName(out string) string {
	for _, line := range strings.Split(out, "\n") {
		kv := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(kv) == 2 && strings.HasPrefix(strings.TrimSpace(kv[0]), "Name") {
			return strings.TrimSpace(kv[1])
		}
	}
	return ""
}
