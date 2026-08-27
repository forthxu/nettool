package route

import (
	"strings"
	"testing"
)

func TestNormalizeDestination(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "192.168.2.0/24", want: "192.168.2.0/24"},
		{in: "192.168.2.5/24", want: "192.168.2.0/24"}, // 主机位会被掩掉
		{in: "10.0.0.1", want: "10.0.0.1/32"},          // 裸 IP 视为主机路由
		{in: "10.0.0.1/32", want: "10.0.0.1/32"},
		{in: "2001:db8::1", wantErr: true},    // 暂不支持 IPv6
		{in: "192.168.2.0/33", wantErr: true}, // 掩码越界
		{in: "example.com", wantErr: true},    // 域名不归它处理
	}

	for _, c := range cases {
		got, err := normalizeDestination(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("normalizeDestination(%q) = %q, 期望报错", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeDestination(%q) 意外报错: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("normalizeDestination(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

// 真正下发路由需要 root，这里只校验各平台命令行的拼装，
// 重点是域名解析产生的 /32 主机路由与网段路由写法不同。
func TestBuildRouteCmd(t *testing.T) {
	cases := []struct {
		name    string
		os      string
		action  string
		dest    string
		iface   string
		want    string
		wantErr bool
	}{
		{
			name: "linux 网段", os: "linux", action: "add", dest: "192.168.2.0/24",
			want: "ip route add 192.168.2.0/24 via 192.168.10.249 proto 210",
		},
		{
			name: "linux 主机(域名解析结果)", os: "linux", action: "add", dest: "104.20.23.154/32",
			want: "ip route add 104.20.23.154/32 via 192.168.10.249 proto 210",
		},
		{
			name: "linux 指定网卡", os: "linux", action: "add", dest: "192.168.2.0/24", iface: "eth0",
			want: "ip route add 192.168.2.0/24 via 192.168.10.249 dev eth0 proto 210",
		},
		{
			name: "linux 删除不带 dev", os: "linux", action: "del", dest: "192.168.2.0/24", iface: "eth0",
			want: "ip route del 192.168.2.0/24 via 192.168.10.249",
		},
		{
			name: "darwin 网段", os: "darwin", action: "add", dest: "192.168.2.0/24",
			want: "route -n add -net 192.168.2.0/24 192.168.10.249",
		},
		{
			name: "darwin 主机路由必须用 -host", os: "darwin", action: "add", dest: "104.20.23.154/32",
			want: "route -n add -host 104.20.23.154 192.168.10.249",
		},
		{
			name: "darwin 删除主机路由", os: "darwin", action: "del", dest: "104.20.23.154/32",
			want: "route -n delete -host 104.20.23.154 192.168.10.249",
		},
		{
			// 不带 -ifscope 的全局路由会被 en0 作用域里的克隆路由压掉
			name: "darwin 主机路由带作用域", os: "darwin", action: "add", dest: "104.20.23.154/32", iface: "en0",
			want: "route -n add -host 104.20.23.154 192.168.10.249 -ifscope en0",
		},
		{
			name: "darwin 网段路由带作用域", os: "darwin", action: "add", dest: "192.168.2.0/24", iface: "en0",
			want: "route -n add -net 192.168.2.0/24 192.168.10.249 -ifscope en0",
		},
		{
			// 删除同样要指定作用域，否则删不掉作用域内的那条
			name: "darwin 删除带作用域", os: "darwin", action: "del", dest: "104.20.23.154/32", iface: "en0",
			want: "route -n delete -host 104.20.23.154 192.168.10.249 -ifscope en0",
		},
		{
			// Linux 没有作用域概念，网卡走 dev
			name: "linux 不受 ifscope 影响", os: "linux", action: "add", dest: "104.20.23.154/32", iface: "eth0",
			want: "ip route add 104.20.23.154/32 via 192.168.10.249 dev eth0 proto 210",
		},
		{
			name: "windows 网段掩码", os: "windows", action: "add", dest: "192.168.2.0/24",
			want: "route ADD 192.168.2.0 MASK 255.255.255.0 192.168.10.249",
		},
		{
			name: "windows 主机掩码", os: "windows", action: "add", dest: "104.20.23.154/32",
			want: "route ADD 104.20.23.154 MASK 255.255.255.255 192.168.10.249",
		},
		{
			name: "windows 非 /24 网段", os: "windows", action: "add", dest: "172.20.0.0/23",
			want: "route ADD 172.20.0.0 MASK 255.255.254.0 192.168.10.249",
		},
		{
			name: "windows 删除需带掩码", os: "windows", action: "del", dest: "104.20.23.154/32",
			want: "route DELETE 104.20.23.154 MASK 255.255.255.255 192.168.10.249",
		},
		{name: "不支持的系统", os: "plan9", action: "add", dest: "192.168.2.0/24", wantErr: true},
		{name: "非法目标", os: "linux", action: "add", dest: "不是路由", wantErr: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd, err := buildRouteCmd(c.os, c.action, c.dest, "192.168.10.249", c.iface)
			if c.wantErr {
				if err == nil {
					t.Fatalf("期望报错，实际得到 %v", cmd.Args)
				}
				return
			}
			if err != nil {
				t.Fatalf("意外报错: %v", err)
			}
			// cmd.Path 是查找后的绝对路径，比较 Args 即可
			got := strings.Join(cmd.Args, " ")
			if got != c.want {
				t.Errorf("命令 = %q, 期望 %q", got, c.want)
			}
		})
	}
}

func TestNormalizeKernelDest(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "192.168.2.0/24", want: "192.168.2.0/24"},
		{in: "192.168.2", want: "192.168.2.0/24"},       // BSD 省略末尾 0 与掩码
		{in: "172.20.0/23", want: "172.20.0.0/23"},    // BSD 省略末尾 0 但带掩码
		{in: "104.20.23.154", want: "104.20.23.154/32"}, // 裸 IP = 主机路由
		{in: "10", want: "10.0.0.0/8"},
		{in: "fe80::1", wantErr: true},
		{in: "link#16", wantErr: true},
		{in: "999.1.1.1", wantErr: true},
	}

	for _, c := range cases {
		got, ok := normalizeKernelDest(c.in)
		if c.wantErr {
			if ok {
				t.Errorf("normalizeKernelDest(%q) = %q, 期望失败", c.in, got)
			}
			continue
		}
		if !ok {
			t.Errorf("normalizeKernelDest(%q) 失败, 期望 %q", c.in, c.want)
			continue
		}
		if got != c.want {
			t.Errorf("normalizeKernelDest(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

func TestParseLinuxRoutes(t *testing.T) {
	out := `default via 192.168.1.1 dev eth0 proto dhcp metric 100
104.20.23.154 via 192.168.10.249 dev eth0 proto 210
192.168.2.0/24 via 192.168.1.254 dev eth0 proto 210
10.8.0.0/24 via 10.8.0.1 dev tun0
192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.5`

	routes := parseLinuxRoutes(out)
	if len(routes) != 3 {
		t.Fatalf("解析到 %d 条, 期望 3 条 (default 与直连路由应被跳过): %+v", len(routes), routes)
	}
	if !KernelHasRoute(routes, "104.20.23.154/32", "192.168.10.249") {
		t.Error("应识别出域名解析产生的 /32 主机路由")
	}
	if !KernelHasRoute(routes, "192.168.2.0/24", "192.168.1.254") {
		t.Error("应识别出网段路由")
	}
	if KernelHasRoute(routes, "192.168.2.0/24", "192.168.10.249") {
		t.Error("网关不一致时不应判定为同一条路由")
	}

	var ours, notOurs int
	for _, r := range routes {
		if r.Ours {
			ours++
		} else {
			notOurs++
		}
	}
	if ours != 2 || notOurs != 1 {
		t.Errorf("proto 标记识别有误: 本程序 %d 条, 其他 %d 条", ours, notOurs)
	}
}

func TestParseDarwinRoutes(t *testing.T) {
	out := `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.10.1       UGScg                 en0
127.0.0.1          127.0.0.1          UH                    lo0
192.168.2          192.168.10.249     UGSc                  en0
104.20.23.154      192.168.10.249     UGHS                  en0
192.168.10         link#16            UCS                   en0      !
172.20.0/23       link#27            UC              bridge100      !`

	routes := parseDarwinRoutes(out)
	if !KernelHasRoute(routes, "192.168.2.0/24", "192.168.10.249") {
		t.Error("应识别出 BSD 缩写形式的网段路由 192.168.2 -> 192.168.2.0/24")
	}
	if !KernelHasRoute(routes, "104.20.23.154/32", "192.168.10.249") {
		t.Error("应识别出主机路由")
	}
	for _, r := range routes {
		if r.Gateway == "127.0.0.1" && r.Destination == "127.0.0.1/32" {
			continue // 回环表项被保留无所谓，只要不误判为我们的路由即可
		}
		if !strings.Contains(r.Gateway, ".") {
			t.Errorf("直连表项 (link#N) 不应被解析为路由: %+v", r)
		}
	}
}

func TestParseWindowsRoutes(t *testing.T) {
	// 中文版 Windows：表头与 "在链路上" 都是本地化文案，不能靠它们定位
	out := `IPv4 路由表
===========================================================================
活动路由:
网络目标        网络掩码          网关       接口   跃点数
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.10     25
      104.20.23.154  255.255.255.255   192.168.10.249    192.168.10.20      1
      192.168.2.0    255.255.255.0    192.168.1.254     192.168.1.10      1
      192.168.1.0    255.255.255.0          在链路上      192.168.1.10    281
===========================================================================`

	routes := parseWindowsRoutes(out)
	if !KernelHasRoute(routes, "192.168.2.0/24", "192.168.1.254") {
		t.Error("应识别出网段路由 192.168.2.0/24 -> 192.168.1.254")
	}
	if !KernelHasRoute(routes, "104.20.23.154/32", "192.168.10.249") {
		t.Error("应识别出主机路由")
	}
	for _, r := range routes {
		if r.Destination == "0.0.0.0/0" {
			t.Error("默认路由不应进入对账结果")
		}
		if r.Gateway == "" {
			t.Errorf("直连（在链路上）表项不应被解析为路由: %+v", r)
		}
		if r.Ours {
			t.Errorf("Windows 上没有 proto 标记，Ours 应恒为 false: %+v", r)
		}
	}
}

// macOS 上路由的作用域网卡是添加那一刻算出来存进台账的，网关后来换了网卡
// （比如 Wi-Fi 也把它设成默认网关）旧作用域就会变成黑洞，得能认出来并重下发。
func TestRescopeTarget(t *testing.T) {
	cases := []struct {
		name      string
		current   string
		want      string
		wantIface string
		wantNeed  bool
	}{
		{name: "没变化不用动", current: "en0", want: "en0", wantIface: "en0", wantNeed: false},
		{name: "网关换到了另一块网卡", current: "en0", want: "en7", wantIface: "en7", wantNeed: true},
		{name: "老台账没记作用域，补上", current: "", want: "en0", wantIface: "en0", wantNeed: true},
		{name: "网关暂时够不着就别动", current: "en0", want: "", wantIface: "en0", wantNeed: false},
		{name: "两边都没有也不动", current: "", want: "", wantIface: "", wantNeed: false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			iface, need := rescopeTarget(c.current, c.want)
			if iface != c.wantIface || need != c.wantNeed {
				t.Errorf("rescopeTarget(%q, %q) = (%q, %v), 期望 (%q, %v)",
					c.current, c.want, iface, need, c.wantIface, c.wantNeed)
			}
		})
	}
}
