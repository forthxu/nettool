package netutil

import "testing"

// 中文版 Windows 的 route print -4：表头、"在链路上" 全是本地化文案，
// 解析必须只认数据行的形状。
const zhRoutePrint = `===========================================================================
接口列表
 12...00 15 5d 01 02 03 ......Hyper-V Virtual Ethernet Adapter
===========================================================================

IPv4 路由表
===========================================================================
活动路由:
网络目标        网络掩码          网关       接口   跃点数
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.10     25
          0.0.0.0          0.0.0.0     192.168.10.1    192.168.10.20     35
      104.20.23.154  255.255.255.255   192.168.10.249    192.168.10.20      1
      192.168.2.0    255.255.255.0    192.168.1.254     192.168.1.10      1
      192.168.1.0    255.255.255.0          在链路上      192.168.1.10    281
        224.0.0.0        240.0.0.0          在链路上      192.168.1.10    281
===========================================================================
永久路由:
  网络地址          网络掩码  网关地址  跃点数
    192.168.9.0    255.255.255.0    192.168.1.254       1
===========================================================================
`

func TestParseWindowsRoutePrint(t *testing.T) {
	got := ParseWindowsRoutePrint(zhRoutePrint)

	want := []WinRoute{
		{Destination: "0.0.0.0/0", Gateway: "192.168.1.1", InterfaceIP: "192.168.1.10", Metric: 25},
		{Destination: "0.0.0.0/0", Gateway: "192.168.10.1", InterfaceIP: "192.168.10.20", Metric: 35},
		{Destination: "104.20.23.154/32", Gateway: "192.168.10.249", InterfaceIP: "192.168.10.20", Metric: 1},
		{Destination: "192.168.2.0/24", Gateway: "192.168.1.254", InterfaceIP: "192.168.1.10", Metric: 1},
		{Destination: "192.168.1.0/24", Gateway: "", InterfaceIP: "192.168.1.10", Metric: 281},
		{Destination: "224.0.0.0/4", Gateway: "", InterfaceIP: "192.168.1.10", Metric: 281},
	}

	if len(got) != len(want) {
		t.Fatalf("解析出 %d 条，期望 %d 条: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 条 = %+v, 期望 %+v", i, got[i], want[i])
		}
	}
}

// 德文的 "Auf Verbindung" 会被切成两个词，把后面的列挤走；这种行认不出来就该丢掉，
// 而不是错认成一条网关是 "Verbindung" 的路由。
func TestParseWindowsRoutePrintSkipsMultiWordOnLink(t *testing.T) {
	const out = `     192.168.1.0    255.255.255.0     Auf Verbindung      192.168.1.10    281
     192.168.2.0    255.255.255.0      192.168.1.254      192.168.1.10      1`

	got := ParseWindowsRoutePrint(out)
	if len(got) != 1 {
		t.Fatalf("解析出 %d 条，期望 1 条: %+v", len(got), got)
	}
	if got[0].Destination != "192.168.2.0/24" || got[0].Gateway != "192.168.1.254" {
		t.Errorf("= %+v, 期望 192.168.2.0/24 via 192.168.1.254", got[0])
	}
}

func TestWindowsDefaultGatewaysByIP(t *testing.T) {
	got := WindowsDefaultGatewaysByIP(zhRoutePrint)

	want := map[string]string{
		"192.168.1.10":  "192.168.1.1",
		"192.168.10.20": "192.168.10.1",
	}
	if len(got) != len(want) {
		t.Fatalf("= %v, 期望 %v", got, want)
	}
	for ip, gw := range want {
		if got[ip] != gw {
			t.Errorf("%s 的网关 = %q, 期望 %q", ip, got[ip], gw)
		}
	}
}

// 同一个出口地址有多条默认路由时应取跃点数最小的那条
func TestWindowsDefaultGatewaysByIPPrefersLowestMetric(t *testing.T) {
	const out = `          0.0.0.0          0.0.0.0     192.168.1.254     192.168.1.10     50
          0.0.0.0          0.0.0.0       192.168.1.1     192.168.1.10     25`

	if gw := WindowsDefaultGatewaysByIP(out)["192.168.1.10"]; gw != "192.168.1.1" {
		t.Errorf("= %q, 期望 192.168.1.1（跃点数 25 的那条）", gw)
	}
}
