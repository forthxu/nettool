// Package netconfig 管理网卡的 IPv4 配置（地址/掩码/网关/DNS），
// 以及按当前连接的 Wi-Fi SSID 自动切换到对应的配置档。
//
// 三个平台的配置入口完全不同，这里统一成"目标 + 一组设置"：
//
//	macOS   networksetup，以"网络服务"为单位（一块网卡可能对应多个服务）
//	Linux   nmcli，以 NetworkManager 的"连接"为单位
//	Windows netsh，以接口名为单位
//
// 因此 Target.Service 才是真正的写入对象，Device（en0/eth0）只用于展示与匹配。
package netconfig

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Settings 是要写入一张网卡的 IPv4 配置。Method 为 dhcp 时 IP/Mask/Gateway
// 应为空；DNS 两种模式下都可以单独指定（留空表示跟随 DHCP）。
type Settings struct {
	Method  string   `json:"method"` // dhcp | manual
	IP      string   `json:"ip,omitempty"`
	Mask    string   `json:"mask,omitempty"` // 点分掩码，输入 24 这样的前缀也接受
	Gateway string   `json:"gateway,omitempty"`
	DNS     []string `json:"dns,omitempty"`
}

// NIC 是某张网卡当前的实际配置，供界面展示
type NIC struct {
	Device   string   `json:"device"`  // en0 / eth0
	Service  string   `json:"service"` // 配置入口名（macOS 网络服务 / nmcli 连接 / Windows 接口）
	Type     string   `json:"type"`    // wifi | ethernet | other
	Method   string   `json:"method"`  // dhcp | manual | off | unknown
	IP       string   `json:"ip,omitempty"`
	Mask     string   `json:"mask,omitempty"`
	Gateway  string   `json:"gateway,omitempty"`
	DNS      []string `json:"dns,omitempty"` // 手工配置的 DNS，空表示跟随 DHCP
	SSID     string   `json:"ssid,omitempty"`
	Active   bool     `json:"active"`          // 当前是否拿到了 IP
	Disabled bool     `json:"disabled"`        // macOS 上被停用的网络服务
	Error    string   `json:"error,omitempty"` // 读这张网卡时的错误
}

// Profile 是一个 Wi-Fi 网络对应的网卡配置档。
// SSID 同时充当主键与显示名；macOS 14 起系统可能不给读 SSID，这时 NetworkID
// （系统给该网络的指纹）才是真正用来匹配的东西，SSID 只是用户起的名字。
type Profile struct {
	SSID          string     `json:"ssid"`
	NetworkID     string     `json:"network_id,omitempty"` // 读不到 SSID 时用它匹配
	IsDefault     bool       `json:"is_default,omitempty"` // 连到没有单独配置的 Wi-Fi 时套用它
	Service       string     `json:"service"`              // 配置写到哪个网络服务/连接
	Device        string     `json:"device,omitempty"`
	Settings      Settings   `json:"settings"`
	Enabled       bool       `json:"enabled"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	LastAppliedAt *time.Time `json:"last_applied_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
}

// Target 指明这份配置要写到哪儿
type Target struct {
	Device  string
	Service string
}

// ---------------------------------------------------------
// 掩码与校验
// ---------------------------------------------------------

// normalizeMask 接受 "255.255.255.0" 或 "24" 两种写法，统一成点分掩码
func normalizeMask(mask string) (string, error) {
	mask = strings.TrimSpace(mask)
	if mask == "" {
		return "", fmt.Errorf("掩码不能为空")
	}
	if !strings.Contains(mask, ".") {
		prefix, err := strconv.Atoi(strings.TrimPrefix(mask, "/"))
		if err != nil || prefix < 0 || prefix > 32 {
			return "", fmt.Errorf("掩码 %q 不合法（可填 255.255.255.0 或 24）", mask)
		}
		m := net.CIDRMask(prefix, 32)
		return net.IP(m).String(), nil
	}
	ip := net.ParseIP(mask)
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("掩码 %q 不是合法的 IPv4 掩码", mask)
	}
	m := net.IPMask(ip.To4())
	_, bits := m.Size()
	if bits != 32 {
		// Size() 在非连续掩码上返回 0,0
		return "", fmt.Errorf("掩码 %q 不是连续掩码", mask)
	}
	return ip.To4().String(), nil
}

// maskToPrefix 把点分掩码转成前缀长度，nmcli 只认 ip/prefix 写法
func maskToPrefix(mask string) (int, error) {
	dotted, err := normalizeMask(mask)
	if err != nil {
		return 0, err
	}
	ip := net.ParseIP(dotted).To4()
	ones, bits := net.IPMask(ip).Size()
	if bits != 32 {
		return 0, fmt.Errorf("掩码 %q 不是连续掩码", mask)
	}
	return ones, nil
}

func validateIPv4(label, v string) error {
	ip := net.ParseIP(strings.TrimSpace(v))
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("%s %q 不是合法的 IPv4 地址", label, v)
	}
	return nil
}

// ValidateSettings 归一化并校验一组配置，返回可直接下发的副本。
// 手动配置下网关允许留空（二级网卡的常见用法），但 IP 与掩码必填。
func ValidateSettings(s Settings) (Settings, error) {
	out := Settings{Method: strings.ToLower(strings.TrimSpace(s.Method))}

	for _, d := range s.DNS {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if err := validateIPv4("DNS 服务器", d); err != nil {
			return out, err
		}
		out.DNS = append(out.DNS, d)
	}

	switch out.Method {
	case "dhcp":
		return out, nil
	case "manual":
	default:
		return out, fmt.Errorf("配置方式 %q 不支持，只能是 dhcp 或 manual", s.Method)
	}

	out.IP = strings.TrimSpace(s.IP)
	if err := validateIPv4("IP 地址", out.IP); err != nil {
		return out, err
	}
	mask, err := normalizeMask(s.Mask)
	if err != nil {
		return out, err
	}
	out.Mask = mask

	out.Gateway = strings.TrimSpace(s.Gateway)
	if out.Gateway != "" {
		if err := validateIPv4("网关", out.Gateway); err != nil {
			return out, err
		}
		// 网关必须和 IP 在同一网段，否则配下去必然不通
		if !sameSubnet(out.IP, out.Gateway, out.Mask) {
			return out, fmt.Errorf("网关 %s 与 IP %s/%s 不在同一网段", out.Gateway, out.IP, out.Mask)
		}
	}
	return out, nil
}

func sameSubnet(ip, gateway, mask string) bool {
	a, b := net.ParseIP(ip).To4(), net.ParseIP(gateway).To4()
	m := net.IPMask(net.ParseIP(mask).To4())
	if a == nil || b == nil || m == nil {
		return false
	}
	return a.Mask(m).Equal(b.Mask(m))
}

// sameSettings 判断当前网卡配置是否已经等于目标配置，避免无谓地重下发（会短暂断网）
func sameSettings(cur NIC, want Settings) bool {
	if cur.Method != want.Method {
		return false
	}
	if want.Method == "manual" {
		if cur.IP != want.IP || cur.Mask != want.Mask || cur.Gateway != want.Gateway {
			return false
		}
	}
	if len(cur.DNS) != len(want.DNS) {
		return false
	}
	for i := range want.DNS {
		if cur.DNS[i] != want.DNS[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------
// 下发
// ---------------------------------------------------------

// buildApplyCmds 返回要依次执行的命令。地址与 DNS 在三个平台上都是分开设置的，
// 所以这里返回的是一个命令序列而不是单条命令。拆成纯函数是为了能被测试覆盖。
func buildApplyCmds(osName string, t Target, s Settings) ([][]string, error) {
	if strings.TrimSpace(t.Service) == "" {
		return nil, fmt.Errorf("未指定要配置的网络服务/网卡")
	}
	s, err := ValidateSettings(s)
	if err != nil {
		return nil, err
	}

	switch osName {
	case "darwin":
		var cmds [][]string
		if s.Method == "dhcp" {
			cmds = append(cmds, []string{"networksetup", "-setdhcp", t.Service})
		} else {
			// networksetup -setmanual 的第三个参数是网关，留空表示不设网关
			cmds = append(cmds, []string{"networksetup", "-setmanual", t.Service, s.IP, s.Mask, s.Gateway})
		}
		if len(s.DNS) > 0 {
			cmds = append(cmds, append([]string{"networksetup", "-setdnsservers", t.Service}, s.DNS...))
		} else {
			// Empty 是 networksetup 约定的"清空，改回 DHCP 下发"写法
			cmds = append(cmds, []string{"networksetup", "-setdnsservers", t.Service, "Empty"})
		}
		return cmds, nil

	case "linux":
		args := []string{"nmcli", "connection", "modify", t.Service}
		if s.Method == "dhcp" {
			args = append(args, "ipv4.method", "auto", "ipv4.addresses", "", "ipv4.gateway", "")
		} else {
			prefix, err := maskToPrefix(s.Mask)
			if err != nil {
				return nil, err
			}
			args = append(args, "ipv4.method", "manual",
				"ipv4.addresses", fmt.Sprintf("%s/%d", s.IP, prefix),
				"ipv4.gateway", s.Gateway)
		}
		if len(s.DNS) > 0 {
			// 显式 DNS 必须同时关掉 DHCP 下发的，否则两份会并存
			args = append(args, "ipv4.dns", strings.Join(s.DNS, " "), "ipv4.ignore-auto-dns", "yes")
		} else {
			args = append(args, "ipv4.dns", "", "ipv4.ignore-auto-dns", "no")
		}
		// 改完要 up 一次才生效
		return [][]string{args, {"nmcli", "connection", "up", t.Service}}, nil

	case "windows":
		name := "name=" + t.Service
		var cmds [][]string
		if s.Method == "dhcp" {
			cmds = append(cmds, []string{"netsh", "interface", "ip", "set", "address", name, "source=dhcp"})
		} else {
			addr := []string{"netsh", "interface", "ip", "set", "address", name, "static", s.IP, s.Mask}
			if s.Gateway != "" {
				addr = append(addr, s.Gateway)
			}
			cmds = append(cmds, addr)
		}
		if len(s.DNS) > 0 {
			cmds = append(cmds, []string{"netsh", "interface", "ip", "set", "dns", name, "static", s.DNS[0], "primary"})
			for i, d := range s.DNS[1:] {
				cmds = append(cmds, []string{"netsh", "interface", "ip", "add", "dns", name, d, "index=" + strconv.Itoa(i+2)})
			}
		} else {
			cmds = append(cmds, []string{"netsh", "interface", "ip", "set", "dns", name, "source=dhcp"})
		}
		return cmds, nil
	}

	return nil, fmt.Errorf("暂不支持在 %s 上修改网卡配置", osName)
}

// Apply 真正下发配置。改网卡配置随时可能把当前这条管理连接一起切断，
// 所以每条命令都记日志，失败时把系统原始输出带回去。
func Apply(t Target, s Settings) error {
	cmds, err := buildApplyCmds(runtime.GOOS, t, s)
	if err != nil {
		return err
	}
	for _, args := range cmds {
		log.Printf("[NetConfig] 执行: %s", strings.Join(args, " "))
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		text := strings.TrimSpace(string(out))
		if err != nil {
			if text == "" {
				text = err.Error()
			}
			return fmt.Errorf("执行 `%s` 失败: %s", strings.Join(args, " "), text)
		}
		if text != "" {
			log.Printf("[NetConfig] 输出: %s", text)
		}
	}
	log.Printf("[NetConfig] %s(%s) 已应用: %s", t.Service, t.Device, Describe(s))
	return nil
}

// Describe 把一组配置说成一句人话，用于日志与界面回显
func Describe(s Settings) string {
	if s.Method == "dhcp" {
		if len(s.DNS) > 0 {
			return "DHCP, DNS " + strings.Join(s.DNS, ",")
		}
		return "DHCP"
	}
	desc := fmt.Sprintf("手动 %s/%s", s.IP, s.Mask)
	if s.Gateway != "" {
		desc += " 网关 " + s.Gateway
	}
	if len(s.DNS) > 0 {
		desc += " DNS " + strings.Join(s.DNS, ",")
	}
	return desc
}
