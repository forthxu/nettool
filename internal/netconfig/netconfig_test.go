package netconfig

import (
	"strings"
	"testing"
)

func TestNormalizeMask(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "255.255.255.0", want: "255.255.255.0"},
		{in: "24", want: "255.255.255.0"},
		{in: "/24", want: "255.255.255.0"},
		{in: "23", want: "255.255.254.0"},
		{in: "32", want: "255.255.255.255"},
		{in: "255.255.0.255", wantErr: true}, // 非连续掩码
		{in: "33", wantErr: true},
		{in: "", wantErr: true},
		{in: "abc", wantErr: true},
	}
	for _, c := range cases {
		got, err := normalizeMask(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("normalizeMask(%q) = %q, 期望报错", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeMask(%q) 意外报错: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("normalizeMask(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

func TestValidateSettings(t *testing.T) {
	ok := []Settings{
		{Method: "dhcp"},
		{Method: "dhcp", DNS: []string{"8.8.8.8", "1.1.1.1"}},
		{Method: "manual", IP: "192.168.1.20", Mask: "24", Gateway: "192.168.1.1"},
		{Method: "manual", IP: "192.168.1.20", Mask: "255.255.255.0"}, // 网关可以留空
	}
	for _, s := range ok {
		if _, err := ValidateSettings(s); err != nil {
			t.Errorf("ValidateSettings(%+v) 意外报错: %v", s, err)
		}
	}

	bad := []Settings{
		{Method: "static"},                     // 只认 dhcp/manual
		{Method: "manual", Mask: "24"},         // 缺 IP
		{Method: "manual", IP: "192.168.1.20"}, // 缺掩码
		{Method: "manual", IP: "192.168.1.20", Mask: "24", Gateway: "10.0.0.1"},    // 网关跨网段
		{Method: "manual", IP: "192.168.1.300", Mask: "24"},                        // IP 非法
		{Method: "dhcp", DNS: []string{"not-an-ip"}},                               // DNS 非法
		{Method: "manual", IP: "192.168.1.20", Mask: "24", DNS: []string{"8.8.8"}}, // DNS 非法
	}
	for _, s := range bad {
		if _, err := ValidateSettings(s); err == nil {
			t.Errorf("ValidateSettings(%+v) 期望报错", s)
		}
	}

	// 掩码归一化 + DNS 去空白
	got, err := ValidateSettings(Settings{Method: "manual", IP: " 192.168.1.20 ", Mask: "24", DNS: []string{" 8.8.8.8 ", ""}})
	if err != nil {
		t.Fatalf("意外报错: %v", err)
	}
	if got.IP != "192.168.1.20" || got.Mask != "255.255.255.0" || len(got.DNS) != 1 || got.DNS[0] != "8.8.8.8" {
		t.Errorf("归一化结果不对: %+v", got)
	}
}

func TestBuildNICApplyCmds(t *testing.T) {
	target := Target{Device: "en0", Service: "Wi-Fi"}

	cases := []struct {
		name    string
		os      string
		target  Target
		set     Settings
		want    []string
		wantErr bool
	}{
		{
			name: "darwin 手动 + DNS", os: "darwin", target: target,
			set: Settings{Method: "manual", IP: "192.168.1.20", Mask: "24", Gateway: "192.168.1.1", DNS: []string{"8.8.8.8", "1.1.1.1"}},
			want: []string{
				"networksetup -setmanual Wi-Fi 192.168.1.20 255.255.255.0 192.168.1.1",
				"networksetup -setdnsservers Wi-Fi 8.8.8.8 1.1.1.1",
			},
		},
		{
			// 不填 DNS 要显式清空，否则会留着上一次手工配的
			name: "darwin DHCP 清空 DNS", os: "darwin", target: target,
			set: Settings{Method: "dhcp"},
			want: []string{
				"networksetup -setdhcp Wi-Fi",
				"networksetup -setdnsservers Wi-Fi Empty",
			},
		},
		{
			name: "darwin 手动无网关", os: "darwin", target: target,
			set: Settings{Method: "manual", IP: "192.168.1.20", Mask: "255.255.255.0"},
			want: []string{
				"networksetup -setmanual Wi-Fi 192.168.1.20 255.255.255.0 ",
				"networksetup -setdnsservers Wi-Fi Empty",
			},
		},
		{
			// nmcli 只认 ip/prefix，掩码要换算
			name: "linux 手动", os: "linux", target: Target{Device: "wlan0", Service: "home"},
			set: Settings{Method: "manual", IP: "192.168.1.20", Mask: "255.255.254.0", Gateway: "192.168.1.1", DNS: []string{"8.8.8.8"}},
			want: []string{
				"nmcli connection modify home ipv4.method manual ipv4.addresses 192.168.1.20/23 ipv4.gateway 192.168.1.1 ipv4.dns 8.8.8.8 ipv4.ignore-auto-dns yes",
				"nmcli connection up home",
			},
		},
		{
			name: "linux DHCP", os: "linux", target: Target{Device: "wlan0", Service: "home"},
			set: Settings{Method: "dhcp"},
			want: []string{
				"nmcli connection modify home ipv4.method auto ipv4.addresses  ipv4.gateway  ipv4.dns  ipv4.ignore-auto-dns no",
				"nmcli connection up home",
			},
		},
		{
			name: "windows 手动多 DNS", os: "windows", target: Target{Device: "以太网", Service: "以太网"},
			set: Settings{Method: "manual", IP: "192.168.1.20", Mask: "24", Gateway: "192.168.1.1", DNS: []string{"8.8.8.8", "1.1.1.1"}},
			want: []string{
				"netsh interface ip set address name=以太网 static 192.168.1.20 255.255.255.0 192.168.1.1",
				"netsh interface ip set dns name=以太网 static 8.8.8.8 primary",
				"netsh interface ip add dns name=以太网 1.1.1.1 index=2",
			},
		},
		{
			name: "windows DHCP", os: "windows", target: Target{Device: "WLAN", Service: "WLAN"},
			set: Settings{Method: "dhcp"},
			want: []string{
				"netsh interface ip set address name=WLAN source=dhcp",
				"netsh interface ip set dns name=WLAN source=dhcp",
			},
		},
		{name: "未指定服务", os: "darwin", target: Target{Device: "en0"}, set: Settings{Method: "dhcp"}, wantErr: true},
		{name: "不支持的系统", os: "plan9", target: target, set: Settings{Method: "dhcp"}, wantErr: true},
		{name: "非法配置", os: "darwin", target: target, set: Settings{Method: "manual", IP: "x"}, wantErr: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmds, err := buildApplyCmds(c.os, c.target, c.set)
			if c.wantErr {
				if err == nil {
					t.Fatalf("期望报错，实际得到 %v", cmds)
				}
				return
			}
			if err != nil {
				t.Fatalf("意外报错: %v", err)
			}
			if len(cmds) != len(c.want) {
				t.Fatalf("命令条数 = %d, 期望 %d: %v", len(cmds), len(c.want), cmds)
			}
			for i := range cmds {
				if got := strings.Join(cmds[i], " "); got != c.want[i] {
					t.Errorf("第 %d 条命令 = %q, 期望 %q", i+1, got, c.want[i])
				}
			}
		})
	}
}

func TestParseNetworksetupOrder(t *testing.T) {
	out := `An asterisk (*) denotes that a network service is disabled.
(1) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en0)

(2) Wi-Fi
(Hardware Port: Wi-Fi, Device: en7)

(3) *Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)
`
	list := parseNetworksetupOrder(out)
	if len(list) != 3 {
		t.Fatalf("解析到 %d 个网络服务, 期望 3: %+v", len(list), list)
	}
	if list[1].Service != "Wi-Fi" || list[1].Device != "en7" || macPortType(list[1].HardwarePort) != "wifi" {
		t.Errorf("Wi-Fi 服务解析有误: %+v", list[1])
	}
	if list[0].Device != "en0" || macPortType(list[0].HardwarePort) != "ethernet" {
		t.Errorf("有线服务解析有误: %+v", list[0])
	}
	if !list[2].Disabled || list[2].Service != "Thunderbolt Bridge" {
		t.Errorf("停用服务应去掉星号并标记 disabled: %+v", list[2])
	}
}

func TestParseNetworksetupInfo(t *testing.T) {
	dhcp := `DHCP Configuration
IP address: 192.168.10.124
Subnet mask: 255.255.255.0
Router: 192.168.10.2
Client ID:
IPv6: Automatic
IPv6 IP address: none
IPv6 Router: none
Wi-Fi ID: aa:bb:cc:dd:ee:01`

	cfg := parseNetworksetupInfo(dhcp)
	if cfg.Method != "dhcp" || cfg.IP != "192.168.10.124" || cfg.Mask != "255.255.255.0" || cfg.Gateway != "192.168.10.2" || !cfg.Active {
		t.Errorf("DHCP 解析有误: %+v", cfg)
	}

	manual := `Manual Configuration
IP address: 192.168.10.222
Subnet mask: 255.255.255.0
Router: 192.168.10.1
IPv6: Automatic
IPv6 IP address: none
IPv6 Router: none
Ethernet Address: aa:bb:cc:dd:ee:02`

	cfg = parseNetworksetupInfo(manual)
	if cfg.Method != "manual" || cfg.IP != "192.168.10.222" || cfg.Gateway != "192.168.10.1" {
		t.Errorf("手动配置解析有误: %+v", cfg)
	}

	// 没连上的服务：IPv6 那行不能被当成 IPv4 地址
	off := `DHCP Configuration
IP address: none
Subnet mask: none
Router: none
IPv6: Automatic
IPv6 IP address: none`
	cfg = parseNetworksetupInfo(off)
	if cfg.IP != "" || cfg.Active {
		t.Errorf("未连接的服务不应有 IP: %+v", cfg)
	}
}

func TestParseMacDNSServers(t *testing.T) {
	if got := parseMacDNSServers("8.8.8.8\n1.1.1.1\n"); len(got) != 2 || got[0] != "8.8.8.8" {
		t.Errorf("DNS 解析有误: %v", got)
	}
	if got := parseMacDNSServers("There aren't any DNS Servers set on Wi-Fi."); len(got) != 0 {
		t.Errorf("未配置 DNS 时应返回空: %v", got)
	}
}

func TestParseSSIDSources(t *testing.T) {
	if got := parseAirportNetwork("Current Wi-Fi Network: DemoNet_5G\n"); got != "DemoNet_5G" {
		t.Errorf("networksetup SSID 解析 = %q", got)
	}
	if got := parseAirportNetwork("You are not associated with an AirPort network."); got != "" {
		t.Errorf("未连接时应返回空, 得到 %q", got)
	}

	summary := `<dictionary> {
  SSID : DemoNet_5G
  SSID_STR : DemoNet_5G
}`
	if got := parseIpconfigSummarySSID(summary); got != "DemoNet_5G" {
		t.Errorf("ipconfig SSID 解析 = %q", got)
	}
	// macOS 14 起未授权定位时会打码，调用方要能识别出来
	if got := parseIpconfigSummarySSID("  SSID : <redacted>"); got != ssidRedacted {
		t.Errorf("打码的 SSID 应原样返回以便识别, 得到 %q", got)
	}

	if got := parseWdutilSSID("    SSID : DemoNet_5G\n    BSSID : aa:bb"); got != "DemoNet_5G" {
		t.Errorf("wdutil SSID 解析 = %q", got)
	}

	if got := parseNmcliWifiSSID("no:Neighbor\nyes:DemoNet_5G\nno:Other"); got != "DemoNet_5G" {
		t.Errorf("nmcli SSID 解析 = %q", got)
	}
	// SSID 里带冒号时 nmcli 会转义
	if got := parseNmcliWifiSSID(`yes:My\:Net`); got != "My:Net" {
		t.Errorf("转义 SSID 解析 = %q", got)
	}

	netshOut := `    Name                   : Wi-Fi
    SSID                   : DemoNet_5G
    BSSID                  : aa:bb:cc:dd:ee:ff`
	if got := parseNetshWlanSSID(netshOut); got != "DemoNet_5G" {
		t.Errorf("netsh SSID 解析 = %q（注意别把 BSSID 当成 SSID）", got)
	}
	if got := parseNetshWlanInterfaceName(netshOut); got != "Wi-Fi" {
		t.Errorf("netsh 接口名解析 = %q", got)
	}
}

func TestParseNmcliDevice(t *testing.T) {
	status := `wlan0:wifi:connected:home
eth0:ethernet:disconnected:
lo:loopback:unmanaged:`
	list := parseNmcliDeviceStatus(status)
	if len(list) != 2 {
		t.Fatalf("应跳过 loopback, 得到 %d 条: %+v", len(list), list)
	}
	if list[0].Device != "wlan0" || list[0].Type != "wifi" || list[0].Service != "home" || !list[0].Active {
		t.Errorf("wifi 设备解析有误: %+v", list[0])
	}
	if list[1].Active {
		t.Errorf("disconnected 设备不应标记为 active: %+v", list[1])
	}

	show := `IP4.ADDRESS[1]:192.168.1.20/23
IP4.GATEWAY:192.168.1.1
IP4.DNS[1]:8.8.8.8
IP4.DNS[2]:1.1.1.1`
	cfg := parseNmcliDeviceShow(show)
	if cfg.IP != "192.168.1.20" || cfg.Mask != "255.255.254.0" || cfg.Gateway != "192.168.1.1" {
		t.Errorf("地址解析有误: %+v", cfg)
	}
	if len(cfg.DNS) != 2 || cfg.DNS[1] != "1.1.1.1" {
		t.Errorf("DNS 解析有误: %v", cfg.DNS)
	}
}

func TestParseNetshInterfaceConfig(t *testing.T) {
	out := `Configuration for interface "以太网"
    DHCP enabled:                         No
    IP Address:                           192.168.1.20
    Subnet Prefix:                        192.168.1.0/24 (mask 255.255.255.0)
    Default Gateway:                      192.168.1.1
    Statically Configured DNS Servers:    8.8.8.8
                                          1.1.1.1

Configuration for interface "WLAN"
    DHCP enabled:                         Yes
    IP Address:                           192.168.10.124
    Subnet Prefix:                        192.168.10.0/24 (mask 255.255.255.0)
    Default Gateway:                      192.168.10.1
`
	list := parseNetshInterfaceConfig(out)
	if len(list) != 2 {
		t.Fatalf("应解析出 2 个接口, 得到 %d: %+v", len(list), list)
	}
	if list[0].Device != "以太网" || list[0].Method != "manual" || list[0].Mask != "255.255.255.0" || list[0].Gateway != "192.168.1.1" {
		t.Errorf("静态接口解析有误: %+v", list[0])
	}
	if len(list[0].DNS) != 2 || list[0].DNS[1] != "1.1.1.1" {
		t.Errorf("多行 DNS 解析有误: %v", list[0].DNS)
	}
	if list[1].Method != "dhcp" || !list[1].Active {
		t.Errorf("DHCP 接口解析有误: %+v", list[1])
	}
}

func TestSameSettings(t *testing.T) {
	cur := NIC{Method: "manual", IP: "192.168.1.20", Mask: "255.255.255.0", Gateway: "192.168.1.1", DNS: []string{"8.8.8.8"}}
	want := Settings{Method: "manual", IP: "192.168.1.20", Mask: "255.255.255.0", Gateway: "192.168.1.1", DNS: []string{"8.8.8.8"}}
	if !sameSettings(cur, want) {
		t.Error("完全一致时应判定为相同，避免无谓重下发")
	}

	diff := want
	diff.Gateway = "192.168.1.254"
	if sameSettings(cur, diff) {
		t.Error("网关不同应判定为不同")
	}

	diff = want
	diff.DNS = []string{"8.8.8.8", "1.1.1.1"}
	if sameSettings(cur, diff) {
		t.Error("DNS 条数不同应判定为不同")
	}

	// DHCP 下不比较地址（地址是 DHCP 给的）
	curDHCP := NIC{Method: "dhcp", IP: "192.168.10.124", Mask: "255.255.255.0", Gateway: "192.168.10.1"}
	if !sameSettings(curDHCP, Settings{Method: "dhcp"}) {
		t.Error("DHCP 模式下不应因为当前拿到的地址判定为不同")
	}
}

func TestParseScutilAirPort(t *testing.T) {
	// 有定位权限时 SSID_STR 有值
	withSSID := `<dictionary> {
  BSSID : <data> 0x020000000000
  ProfileID : 0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f
  SSID : <data> 0x6d7977696669
  SSID_STR : DemoNet_5G
}`
	ssid, id := parseScutilAirPort(withSSID)
	if ssid != "DemoNet_5G" || id != "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f" {
		t.Errorf("解析 = (%q, %q)", ssid, id)
	}

	// macOS 打码时 SSID_STR 是空的，只剩指纹可用
	redacted := `<dictionary> {
  ProfileID : 0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f
  SSID : <data> 0x00
  SSID_STR :
}`
	ssid, id = parseScutilAirPort(redacted)
	if ssid != "" {
		t.Errorf("SSID 被系统打码时不应解析出名字, 得到 %q", ssid)
	}
	if id != "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f" {
		t.Errorf("指纹解析 = %q", id)
	}
}

func TestWiFiIdentity(t *testing.T) {
	named := wifiIdentity{SSID: "DemoNet_5G", NetworkID: "abc123def456"}
	if named.key() != "DemoNet_5G" || named.label() != "DemoNet_5G" || named.empty() {
		t.Errorf("有 SSID 时应以 SSID 为准: %+v", named)
	}

	anon := wifiIdentity{NetworkID: "abc123def456"}
	if anon.key() != "abc123def456" || anon.empty() {
		t.Errorf("没有 SSID 时应退回指纹: %+v", anon)
	}
	if anon.label() != "未知名称的 Wi-Fi(abc123de)" {
		t.Errorf("匿名网络展示名 = %q", anon.label())
	}

	if !(wifiIdentity{}).empty() {
		t.Error("两者都没有时应视为未连接")
	}
}

func TestNetProfileMatch(t *testing.T) {
	s := &ProfileStore{profiles: map[string]Profile{
		"DemoNet_5G": {SSID: "DemoNet_5G", Service: "Wi-Fi"},
		"公司":        {SSID: "公司", NetworkID: "fingerprint-abc", Service: "Wi-Fi"},
	}}

	if p, ok := s.match(wifiIdentity{SSID: "DemoNet_5G"}); !ok || p.Service != "Wi-Fi" {
		t.Error("应按 SSID 命中")
	}
	// 系统不给 SSID 时靠指纹认出同一个网络
	if p, ok := s.match(wifiIdentity{NetworkID: "fingerprint-abc"}); !ok || p.SSID != "公司" {
		t.Error("应按网络指纹命中")
	}
	// SSID 优先于指纹
	if p, ok := s.match(wifiIdentity{SSID: "DemoNet_5G", NetworkID: "fingerprint-abc"}); !ok || p.SSID != "DemoNet_5G" {
		t.Errorf("SSID 应优先于指纹, 命中了 %+v", p)
	}
	if _, ok := s.match(wifiIdentity{SSID: "邻居家", NetworkID: "other"}); ok {
		t.Error("都对不上时不应命中")
	}
	if _, ok := s.match(wifiIdentity{}); ok {
		t.Error("未连接 Wi-Fi 时不应命中任何配置档")
	}
}

func TestNetProfileDefaultFallback(t *testing.T) {
	s := &ProfileStore{profiles: make(map[string]Profile)}

	if _, err := s.Save(Profile{SSID: "DemoNet_5G", Service: "Wi-Fi", Settings: Settings{Method: "manual", IP: "192.168.1.20", Mask: "24"}}); err != nil {
		t.Fatalf("保存具名配置档失败: %v", err)
	}
	// 默认档可以不起名字
	def, err := s.Save(Profile{IsDefault: true, Service: "Wi-Fi", Settings: Settings{Method: "dhcp"}})
	if err != nil {
		t.Fatalf("保存默认档失败: %v", err)
	}
	if def.SSID != defaultProfileName {
		t.Errorf("默认档没起名字时应叫 %q, 得到 %q", defaultProfileName, def.SSID)
	}

	// 有具名档时优先具名档
	if p, ok := s.match(wifiIdentity{SSID: "DemoNet_5G"}); !ok || p.SSID != "DemoNet_5G" {
		t.Errorf("应命中具名配置档, 得到 %+v", p)
	}
	// 陌生 Wi-Fi 落到默认档
	if p, ok := s.match(wifiIdentity{SSID: "咖啡馆"}); !ok || !p.IsDefault {
		t.Errorf("陌生 Wi-Fi 应落到默认档, 得到 %+v", p)
	}
	// 只有指纹、认不出名字的 Wi-Fi 也一样落到默认档
	if p, ok := s.match(wifiIdentity{NetworkID: "unknown-fingerprint"}); !ok || !p.IsDefault {
		t.Errorf("未知指纹应落到默认档, 得到 %+v", p)
	}
	// 没连 Wi-Fi 时不该套用默认档
	if _, ok := s.match(wifiIdentity{}); ok {
		t.Error("未连接 Wi-Fi 时不应命中默认档")
	}

	// 默认档只能有一个：新的顶掉旧的
	if _, err := s.Save(Profile{SSID: "备用默认", IsDefault: true, Service: "Wi-Fi", Settings: Settings{Method: "dhcp"}}); err != nil {
		t.Fatalf("保存第二个默认档失败: %v", err)
	}
	var defaults []string
	for _, p := range s.List() {
		if p.IsDefault {
			defaults = append(defaults, p.SSID)
		}
	}
	if len(defaults) != 1 || defaults[0] != "备用默认" {
		t.Errorf("默认档应只有一个且为最新保存的, 得到 %v", defaults)
	}

	// 默认档不该绑定到某个具体网络的指纹上
	bound, err := s.Save(Profile{SSID: "备用默认", IsDefault: true, NetworkID: "fingerprint-abc", Service: "Wi-Fi", Settings: Settings{Method: "dhcp"}})
	if err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	if bound.NetworkID != "" {
		t.Errorf("默认档不应保留网络指纹, 得到 %q", bound.NetworkID)
	}

	// 删掉默认档后，陌生 Wi-Fi 就没有兜底了
	s.Delete("备用默认")
	if _, ok := s.match(wifiIdentity{SSID: "咖啡馆"}); ok {
		t.Error("没有默认档时陌生 Wi-Fi 不应命中任何配置档")
	}
}

// 回归：界面每 10 秒拉一次 /api/net/wifi（observe），不能把"换网"这件事吃掉，
// 否则后台轮询再看时已经"没变化"，自动切换永远不触发。
func TestWiFiObservePollDoesNotSwallowSwitch(t *testing.T) {
	oldMon, oldProfiles := Monitor, Profiles
	defer func() { Monitor, Profiles = oldMon, oldProfiles }()

	Monitor = &Watcher{}
	Profiles = &ProfileStore{profiles: make(map[string]Profile)} // 空库：只走"没有匹配的配置档"分支，不会真的下发

	home := wifiIdentity{NetworkID: "fingerprint-home"}
	cafe := wifiIdentity{NetworkID: "fingerprint-cafe"}

	// 启动探测：记下当前网络，但不动网卡
	checkWiFiWith(home, CheckSeed)
	if Monitor.actedKey() != home.key() {
		t.Fatalf("启动探测后应把当前网络记成已处理, acted=%q", Monitor.actedKey())
	}
	if Monitor.lastSwitch != nil {
		t.Error("启动时不应发生切换")
	}

	// 用户换了 Wi-Fi，界面先拉了几次状态
	checkWiFiWith(cafe, CheckObserve)
	checkWiFiWith(cafe, CheckObserve)
	if Monitor.actedKey() != home.key() {
		t.Errorf("界面轮询不该改变已处理的网络, acted=%q", Monitor.actedKey())
	}

	// 后台轮询这时才跑到，必须仍然认得出"换网了"
	checkWiFiWith(cafe, CheckSwitch)
	if Monitor.lastSwitch == nil {
		t.Fatal("换网后后台轮询应处理一次（这里是记下没有匹配的配置档）")
	}
	if Monitor.actedKey() != cafe.key() {
		t.Errorf("处理完应更新已处理的网络, acted=%q", Monitor.actedKey())
	}

	// 同一个网络不应重复处理
	Monitor.lastSwitch = nil
	checkWiFiWith(cafe, CheckSwitch)
	if Monitor.lastSwitch != nil {
		t.Error("网络没变时不应重复处理")
	}

	// 断开 Wi-Fi 不触发任何动作
	checkWiFiWith(wifiIdentity{}, CheckSwitch)
	if Monitor.lastSwitch != nil {
		t.Error("未连接 Wi-Fi 时不应处理")
	}
}
