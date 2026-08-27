package netconfig

// 识别"当前连着哪个 Wi-Fi"。macOS 14 起不给定位权限就读不到 SSID，
// 所以这里除了 SSID 还带一个系统给的网络指纹（ProfileID），两者都能用来判断换网。

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// ssidRedacted 是 macOS 14 以后未授予定位权限时返回的占位串
const ssidRedacted = "<redacted>"

// wifiIdentity 描述"当前连着哪个 Wi-Fi"。SSID 拿不到时（macOS 的隐私限制）
// 靠 NetworkID 这个系统指纹也能把不同的 Wi-Fi 区分开，自动切换照样能工作。
type wifiIdentity struct {
	SSID      string
	NetworkID string
	Source    string
	Err       error
}

// key 是用来判断"换网了没有"的标识
func (id wifiIdentity) key() string {
	if id.SSID != "" {
		return id.SSID
	}
	return id.NetworkID
}

func (id wifiIdentity) empty() bool { return id.key() == "" }

// label 是供界面显示的名字
func (id wifiIdentity) label() string {
	if id.SSID != "" {
		return id.SSID
	}
	if id.NetworkID != "" {
		return "未知名称的 Wi-Fi(" + shortID(id.NetworkID) + ")"
	}
	return ""
}

func shortID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// currentWiFi 返回当前连接的 Wi-Fi 标识
func currentWiFi() wifiIdentity {
	switch runtime.GOOS {
	case "darwin":
		id := wifiIdentity{}
		for _, dev := range wifiDevices() {
			if out, e := exec.Command("networksetup", "-getairportnetwork", dev).CombinedOutput(); e == nil {
				if s := parseAirportNetwork(string(out)); s != "" && s != ssidRedacted {
					return wifiIdentity{SSID: s, Source: "networksetup -getairportnetwork " + dev}
				}
			}
			if out, e := exec.Command("ipconfig", "getsummary", dev).CombinedOutput(); e == nil {
				if s := parseIpconfigSummarySSID(string(out)); s != "" && s != ssidRedacted {
					return wifiIdentity{SSID: s, Source: "ipconfig getsummary " + dev}
				}
			}
			// SSID 被系统打码时退而求其次：ProfileID 是该网络的稳定指纹，
			// 不需要定位权限也能读到，足够用来区分"换了个 Wi-Fi"
			if ssid, profileID := darwinAirPortState(dev); ssid != "" || profileID != "" {
				if ssid != "" && ssid != ssidRedacted {
					return wifiIdentity{SSID: ssid, Source: "scutil AirPort " + dev}
				}
				if profileID != "" {
					id = wifiIdentity{NetworkID: profileID, Source: "scutil AirPort " + dev,
						Err: fmt.Errorf("系统未提供 SSID（macOS 14 起需要「定位服务」权限），已改用系统给该网络的指纹 %s 来识别", shortID(profileID))}
				}
			}
		}
		// wdutil 需要 root，作为最后一档
		if out, e := exec.Command("wdutil", "info").CombinedOutput(); e == nil {
			if s := parseWdutilSSID(string(out)); s != "" && s != ssidRedacted {
				return wifiIdentity{SSID: s, Source: "wdutil info"}
			}
		}
		if !id.empty() {
			return id
		}
		return wifiIdentity{Err: fmt.Errorf("未检测到已连接的 Wi-Fi")}

	default:
		ssid, source, err := currentSSID()
		return wifiIdentity{SSID: ssid, Source: source, Err: err}
	}
}

// darwinAirPortState 从 SCDynamicStore 里读 Wi-Fi 状态：
// SSID_STR 在没有定位权限时是空的，但 ProfileID 一直可读。
func darwinAirPortState(dev string) (ssid, profileID string) {
	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader("show State:/Network/Interface/" + dev + "/AirPort\n")
	out, err := cmd.Output()
	if err != nil {
		return "", ""
	}
	return parseScutilAirPort(string(out))
}

// parseScutilAirPort 解析 scutil 的 AirPort 字典
func parseScutilAirPort(out string) (ssid, profileID string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		kv := strings.SplitN(line, " : ", 2)
		if len(kv) != 2 {
			continue
		}
		key, val := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		switch key {
		case "SSID_STR":
			if val != "" && !strings.HasPrefix(val, "<data>") {
				ssid = val
			}
		case "ProfileID":
			profileID = val
		}
	}
	return ssid, profileID
}

// currentSSID 只读 SSID，供 Linux / Windows 以及网卡列表展示使用
func currentSSID() (ssid string, source string, err error) {
	switch runtime.GOOS {
	case "darwin":
		id := currentWiFi()
		return id.SSID, id.Source, id.Err

	case "linux":
		if linuxBackend() == "uci" {
			ssid, e := uciCurrentSSID()
			if e != nil {
				return "", "", e
			}
			return ssid, "iwinfo", nil
		}
		out, e := exec.Command("nmcli", "-t", "-f", "ACTIVE,SSID", "device", "wifi").CombinedOutput()
		if e != nil {
			return "", "", fmt.Errorf("读取 SSID 失败: %s", strings.TrimSpace(string(out)))
		}
		if s := parseNmcliWifiSSID(string(out)); s != "" {
			return s, "nmcli device wifi", nil
		}
		return "", "", fmt.Errorf("未检测到已连接的 Wi-Fi")

	case "windows":
		// Get-NetConnectionProfile 的 Name 对无线网卡就是 SSID，而且属性名不随
		// 系统语言变化；netsh 的输出是本地化的，只能当回落
		if out, e := runPowerShell(psCurrentSSID); e == nil {
			if s := strings.TrimSpace(out); s != "" {
				return s, "Get-NetConnectionProfile", nil
			}
			return "", "", fmt.Errorf("未检测到已连接的 Wi-Fi")
		}

		out, e := exec.Command("netsh", "wlan", "show", "interfaces").CombinedOutput()
		if e != nil {
			return "", "", fmt.Errorf("读取 SSID 失败: %s", strings.TrimSpace(string(out)))
		}
		if s := parseNetshWlanSSID(string(out)); s != "" {
			return s, "netsh wlan show interfaces", nil
		}
		return "", "", fmt.Errorf("未检测到已连接的 Wi-Fi")
	}
	return "", "", fmt.Errorf("暂不支持在 %s 上读取 SSID", runtime.GOOS)
}

// wifiDevices 列出 macOS 上的 Wi-Fi 网卡设备名（en0 / en7 因机型而异）
func wifiDevices() []string {
	out, err := exec.Command("networksetup", "-listnetworkserviceorder").CombinedOutput()
	if err != nil {
		return []string{"en0"}
	}
	var devs []string
	for _, svc := range parseNetworksetupOrder(string(out)) {
		if macPortType(svc.HardwarePort) == "wifi" && svc.Device != "" {
			devs = append(devs, svc.Device)
		}
	}
	if len(devs) == 0 {
		return []string{"en0"}
	}
	return devs
}

// parseAirportNetwork 解析 "Current Wi-Fi Network: MyNet"
func parseAirportNetwork(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "Current Wi-Fi Network: "); i >= 0 {
			return strings.TrimSpace(line[i+len("Current Wi-Fi Network: "):])
		}
	}
	return ""
}

// parseIpconfigSummarySSID 解析 ipconfig getsummary <dev> 里的 "SSID : MyNet"
func parseIpconfigSummarySSID(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "SSID") {
			continue
		}
		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 || strings.TrimSpace(kv[0]) != "SSID" {
			continue
		}
		if v := strings.TrimSpace(kv[1]); v != "" {
			return v
		}
	}
	return ""
}

// parseWdutilSSID 解析 wdutil info 输出里的 SSID 行
func parseWdutilSSID(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "SSID") {
			continue
		}
		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			continue
		}
		if v := strings.TrimSpace(kv[1]); v != "" && v != "None" {
			return v
		}
	}
	return ""
}

// parseNmcliWifiSSID 解析 nmcli -t -f ACTIVE,SSID device wifi
func parseNmcliWifiSSID(out string) string {
	for _, line := range strings.Split(out, "\n") {
		fields := splitNmcli(strings.TrimSpace(line))
		if len(fields) >= 2 && fields[0] == "yes" {
			return fields[1]
		}
	}
	return ""
}

// parseNetshWlanSSID 解析 netsh wlan show interfaces；注意要跳过 "BSSID" 行
func parseNetshWlanSSID(out string) string {
	for _, line := range strings.Split(out, "\n") {
		kv := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(kv) != 2 {
			continue
		}
		if strings.TrimSpace(kv[0]) == "SSID" {
			return strings.TrimSpace(kv[1])
		}
	}
	return ""
}
