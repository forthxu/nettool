package netconfig

// Windows 上读网卡配置。
//
// 首选 PowerShell 的 Get-Net* 系列并让它输出 JSON：netsh 的输出跟着系统语言走
// （中文版打印的是"接口 xxx 的配置"、"DHCP 已启用"），靠英文串匹配的话在非英文
// 系统上会一条都认不出来。PowerShell 的**属性名**不随语言变化，枚举值取 [string]
// 之后也是固定的 Enabled/Disabled、Native802.11，因此是稳定的数据源。
//
// 老系统上 Get-Net* 可能不全（这些 cmdlet 从 Windows 8 / Server 2012 才有），
// 所以 netsh 那套解析保留下来当回落。

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// psListNICs 一次把网卡、IPv4 地址、DHCP 开关、默认网关、DNS、Wi-Fi 名字都取回来。
// Get-NetConnectionProfile 的 Name 对无线网卡而言就是 SSID，且不受系统语言影响。
const psListNICs = `$ErrorActionPreference='SilentlyContinue'
$list = @(Get-NetAdapter | ForEach-Object {
  $a = $_
  $ip = Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1
  $cfg = Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4 | Select-Object -First 1
  $gw = Get-NetRoute -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1
  $dns = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4).ServerAddresses)
  $media = [string]$a.PhysicalMediaType
  $ssid = ''
  if ($media -like '*802.11*') { $ssid = [string](Get-NetConnectionProfile -InterfaceIndex $a.ifIndex).Name }
  [PSCustomObject]@{
    Device = [string]$a.Name
    Media  = $media
    IP     = [string]$ip.IPAddress
    Prefix = [int]$ip.PrefixLength
    Dhcp   = [string]$cfg.Dhcp
    Gateway= [string]$gw.NextHop
    DNS    = $dns
    SSID   = $ssid
  }
})
ConvertTo-Json -InputObject $list -Depth 3 -Compress`

// psCurrentSSID 只问"当前连着的 Wi-Fi 叫什么"，供后台轮询用，比列全部网卡轻得多
const psCurrentSSID = `$ErrorActionPreference='SilentlyContinue'
$a = Get-NetAdapter | Where-Object { [string]$_.PhysicalMediaType -like '*802.11*' -and [int]$_.ifOperStatus -eq 1 } | Select-Object -First 1
if ($a) { [string](Get-NetConnectionProfile -InterfaceIndex $a.ifIndex).Name }`

// psNIC 是上面那段脚本吐出来的一条记录
type psNIC struct {
	Device  string      `json:"Device"`
	Media   string      `json:"Media"`
	IP      string      `json:"IP"`
	Prefix  int         `json:"Prefix"`
	Dhcp    string      `json:"Dhcp"`
	Gateway string      `json:"Gateway"`
	DNS     flexStrings `json:"DNS"`
	SSID    string      `json:"SSID"`
}

// flexStrings 容忍 PowerShell 把单元素数组塌缩成标量的老毛病
type flexStrings []string

func (f *flexStrings) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	var list []string
	if err := json.Unmarshal(b, &list); err == nil {
		*f = list
		return nil
	}
	var one string
	if err := json.Unmarshal(b, &one); err != nil {
		return err
	}
	if one != "" {
		*f = []string{one}
	}
	return nil
}

// runPowerShell 执行一段脚本并返回标准输出。用 Output 而不是 CombinedOutput，
// 免得警告信息混进 JSON 里。
func runPowerShell(script string) (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.Output()
	if err != nil {
		detail := strings.TrimSpace(string(out))
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			detail = strings.TrimSpace(string(ee.Stderr))
		}
		if detail == "" {
			detail = err.Error()
		}
		return "", fmt.Errorf("%s", detail)
	}
	return string(out), nil
}

// parsePowerShellNICs 把脚本输出的 JSON 转成 NIC 列表。
// 只有一块网卡时 ConvertTo-Json 可能给的是对象而不是数组，两种都接住。
func parsePowerShellNICs(out string) ([]NIC, error) {
	text := strings.TrimSpace(strings.TrimPrefix(out, "\ufeff"))
	if text == "" {
		return []NIC{}, nil
	}

	var raw []psNIC
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		var one psNIC
		if err2 := json.Unmarshal([]byte(text), &one); err2 != nil {
			return nil, fmt.Errorf("解析 PowerShell 输出失败: %v", err)
		}
		raw = []psNIC{one}
	}

	list := make([]NIC, 0, len(raw))
	for _, r := range raw {
		if r.Device == "" {
			continue
		}
		// netsh 写配置时是按接口别名找的，与这里的 Name 是同一个东西
		cfg := NIC{
			Device:  r.Device,
			Service: r.Device,
			Type:    windowsMediaType(r.Media),
			Method:  windowsMethod(r.Dhcp),
			IP:      r.IP,
			Gateway: r.Gateway,
			DNS:     append([]string(nil), r.DNS...),
			SSID:    r.SSID,
			Active:  r.IP != "",
		}
		if r.IP != "" && r.Prefix > 0 && r.Prefix <= 32 {
			cfg.Mask = net.IP(net.CIDRMask(r.Prefix, 32)).String()
		}
		list = append(list, cfg)
	}
	return list, nil
}

// windowsMethod 把 Get-NetIPInterface 的 Dhcp 枚举翻成本程序的说法。
// 枚举名不随系统语言变化，可以直接比。
func windowsMethod(dhcp string) string {
	switch strings.ToLower(strings.TrimSpace(dhcp)) {
	case "enabled":
		return "dhcp"
	case "disabled":
		return "manual"
	}
	return "unknown"
}

// windowsMediaType 按 PhysicalMediaType 判断网卡类型，同样是不本地化的枚举名
func windowsMediaType(media string) string {
	m := strings.ToLower(media)
	switch {
	case strings.Contains(m, "802.11"), strings.Contains(m, "wireless"):
		return "wifi"
	case strings.Contains(m, "802.3"), strings.Contains(m, "ethernet"):
		return "ethernet"
	}
	return "other"
}
