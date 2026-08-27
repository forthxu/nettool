package proxy

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/armon/go-socks5"
)

// 实时连接监控里要看得出连的是哪儿：客户端用 --socks5-hostname 时给的是域名，
// 用 --socks5 时给的是已经解析好的 IP，两种都得显示得出来。
func TestDescribeTarget(t *testing.T) {
	cases := []struct {
		name string
		dest socks5.AddrSpec
		want string
	}{
		{
			name: "域名 + 已解析的 IP",
			dest: socks5.AddrSpec{FQDN: "myip.ipip.net", IP: net.ParseIP("104.20.23.154"), Port: 443},
			want: "myip.ipip.net:443 (104.20.23.154)",
		},
		{
			name: "只有域名（还没解析）",
			dest: socks5.AddrSpec{FQDN: "example.com", Port: 80},
			want: "example.com:80",
		},
		{
			name: "客户端直接给 IP",
			dest: socks5.AddrSpec{IP: net.ParseIP("1.1.1.1"), Port: 53},
			want: "1.1.1.1:53",
		},
		{
			name: "IPv6 目标要带方括号",
			dest: socks5.AddrSpec{IP: net.ParseIP("2606:4700:4700::1111"), Port: 443},
			want: "[2606:4700:4700::1111]:443",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := describeTarget(&c.dest); got != c.want {
				t.Errorf("describeTarget = %q, 期望 %q", got, c.want)
			}
		})
	}
}

// 代理自己解析域名时用哪个 DNS：只填 IP 要能自动补端口，非法值要挡住
func TestNormalizeDNSAddr(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "", want: ""},
		{in: "  ", want: ""},
		{in: "8.8.8.8", want: "8.8.8.8:53"},
		{in: "8.8.8.8:5353", want: "8.8.8.8:5353"},
		{in: "2001:4860:4860::8888", want: "[2001:4860:4860::8888]:53"}, // 裸 IPv6 自动补方括号和端口
		{in: "[2001:4860:4860::8888]:53", want: "[2001:4860:4860::8888]:53"},
		{in: "dns.google", wantErr: true}, // 上游 DNS 只能填 IP，填域名会变成鸡生蛋
		{in: "8.8.8", wantErr: true},
	}

	for _, c := range cases {
		got, err := NormalizeDNSAddr(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("NormalizeDNSAddr(%q) = %q, 期望报错", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeDNSAddr(%q) 意外报错: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("NormalizeDNSAddr(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

func TestDNSLocalAddr(t *testing.T) {
	ip := net.ParseIP("192.168.1.20")
	// DNS 查询也要从绑定的出口 IP 发出去，否则查询本身走的还是默认线路
	if a, ok := dnsLocalAddr("udp", ip).(*net.UDPAddr); !ok || !a.IP.Equal(ip) {
		t.Errorf("udp 应返回 *net.UDPAddr 并带上出口 IP, 得到 %#v", dnsLocalAddr("udp", ip))
	}
	if a, ok := dnsLocalAddr("tcp", ip).(*net.TCPAddr); !ok || !a.IP.Equal(ip) {
		t.Errorf("tcp 应返回 *net.TCPAddr 并带上出口 IP, 得到 %#v", dnsLocalAddr("tcp", ip))
	}
	if dnsLocalAddr("udp", nil) != nil {
		t.Error("没绑定出口 IP 时不该指定源地址")
	}
}

// 回归：代理运行中改「代理 DNS」，新值要真的存进配置。
// startLocked 曾漏写 p.dns，结果新 DNS 立即生效了，GetConfig 与界面却还报旧值。
func TestSetConfigKeepsDNSWhileRunning(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("找空闲端口失败: %v", err)
	}
	_, port, _ := net.SplitHostPort(probe.Addr().String())
	probe.Close()

	p := &Server{}
	if err := p.Start(port, "", "8.8.8.8"); err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}
	t.Cleanup(func() { p.Stop() })

	// 只填 IP 的写法会补上 :53，存的应当是归一化之后的那份
	if _, _, dns := p.GetConfig(); dns != "8.8.8.8:53" {
		t.Errorf("启动时的 DNS = %q, 期望 8.8.8.8:53", dns)
	}

	// 运行中改配置会带新配置重启，改完必须能读回来
	if err := p.SetConfig(port, "", "1.1.1.1:5353"); err != nil {
		t.Fatalf("运行中改配置失败: %v", err)
	}
	gotPort, _, dns := p.GetConfig()
	if dns != "1.1.1.1:5353" {
		t.Errorf("改完的 DNS = %q, 期望 1.1.1.1:5353", dns)
	}
	if gotPort != port || !p.Running() {
		t.Errorf("改配置后应仍在同一端口运行, port=%q running=%v", gotPort, p.Running())
	}

	// 清空也要生效（回到跟随系统解析）
	if err := p.SetConfig(port, "", ""); err != nil {
		t.Fatalf("清空 DNS 失败: %v", err)
	}
	if _, _, dns := p.GetConfig(); dns != "" {
		t.Errorf("清空后的 DNS = %q, 期望空", dns)
	}

	// 停止状态下保存配置同样要存下来，且不会把代理拉起来
	if err := p.Stop(); err != nil {
		t.Fatalf("停止代理失败: %v", err)
	}
	if err := p.SetConfig(port, "", "223.5.5.5"); err != nil {
		t.Fatalf("停止状态下改配置失败: %v", err)
	}
	if _, _, dns := p.GetConfig(); dns != "223.5.5.5:53" {
		t.Errorf("停止状态下保存的 DNS = %q, 期望 223.5.5.5:53", dns)
	}
	if p.Running() {
		t.Error("保存配置不应把停着的代理拉起来")
	}
}

// 进程重启后要按上次的开关状态恢复：上次开着就自动起来，点过停止就保持停止
func TestPersistRunStateAcrossRestart(t *testing.T) {
	savedPath := configPath
	t.Cleanup(func() { configPath = savedPath })
	path := filepath.Join(t.TempDir(), "proxy.json")
	configPath = path

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("找空闲端口失败: %v", err)
	}
	_, port, _ := net.SplitHostPort(probe.Addr().String())
	probe.Close()

	// 模拟用户在后台配好并点了「启动代理」
	p := &Server{port: "1080"}
	if err := p.SetConfig(port, "", "8.8.8.8"); err != nil {
		t.Fatalf("保存配置失败: %v", err)
	}
	if readPersistedProxy(t, path).Running {
		t.Error("只保存配置不该把 running 记成 true")
	}
	if err := p.StartCurrent(); err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}
	t.Cleanup(func() { p.Stop() })

	saved := readPersistedProxy(t, path)
	if !saved.Running || saved.Port != port || saved.DNS != "8.8.8.8:53" {
		t.Fatalf("落盘的配置不对: %+v", saved)
	}

	// 模拟进程重启：新实例只读文件，就该知道上次是开着的、端口和 DNS 是哪个
	reborn := &Server{port: "1080"}
	if !reborn.Load(path) {
		t.Fatal("读取配置失败")
	}
	if !reborn.WasRunning() {
		t.Error("上次是开着的，WasRunning 应当为 true")
	}
	if gotPort, _, gotDNS := reborn.GetConfig(); gotPort != port || gotDNS != "8.8.8.8:53" {
		t.Errorf("恢复的配置 = %q / %q, 期望 %q / 8.8.8.8:53", gotPort, gotDNS, port)
	}

	// 点停止之后，下次启动就不该再自动起来
	if err := p.Stop(); err != nil {
		t.Fatalf("停止代理失败: %v", err)
	}
	if readPersistedProxy(t, path).Running {
		t.Fatal("点了停止之后配置里应当记下 running=false")
	}
	reborn2 := &Server{port: "1080"}
	reborn2.Load(path)
	if reborn2.WasRunning() {
		t.Error("上次是停着的，WasRunning 应当为 false")
	}
}

// 命令行只覆盖真填了的那几项，其余沿用上次存下来的
func TestApplyProxyFlagsOverridesOnlyWhatIsGiven(t *testing.T) {
	saved, savedPath := Default, configPath
	t.Cleanup(func() { Default, configPath = saved, savedPath })

	configPath = "" // 单测不落盘
	Default = &Server{port: "1080", dns: "223.5.5.5:53"}

	if err := ApplyFlags("", "", ""); err != nil {
		t.Fatalf("应用命令行参数失败: %v", err)
	}
	if port, _, dns := Default.GetConfig(); port != "1080" || dns != "223.5.5.5:53" {
		t.Errorf("没给参数时不该动已有配置, 得到 %q / %q", port, dns)
	}

	if err := ApplyFlags("1081", "", ""); err != nil {
		t.Fatalf("应用命令行参数失败: %v", err)
	}
	port, _, dns := Default.GetConfig()
	if port != "1081" {
		t.Errorf("端口 = %q, 期望 1081", port)
	}
	if dns != "223.5.5.5:53" {
		t.Errorf("只给了端口，代理 DNS 被冲掉了: %q", dns)
	}

	if err := ApplyFlags("", "", "8.8.8"); err == nil {
		t.Error("非法 DNS 应当报错")
	}
}

func readPersistedProxy(t *testing.T, path string) configFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取配置文件失败: %v", err)
	}
	var state configFile
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("配置文件不是合法 JSON: %v", err)
	}
	return state
}

// 统计口径按用户视角，不按 socket 视角：MonitoredConn 包的是客户端那一侧的
// 连接，所以写给客户端的才是下行，从客户端读到的是上行。方向弄反过一次，
// 界面上会变成「下行 3MB / 上行 15MB」这种一眼假的数，这里钉死。
func TestMonitoredConnByteDirection(t *testing.T) {
	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()
	defer proxySide.Close()

	info := &ConnectionInfo{ID: "test-direction"}
	mc := &MonitoredConn{Conn: proxySide, info: info}

	beforeIn := atomic.LoadInt64(&Stats.totalBytesIn)
	beforeOut := atomic.LoadInt64(&Stats.totalBytesOut)

	// 代理写给客户端 = 客户端在下载
	download := []byte("0123456789")
	go io.ReadFull(clientSide, make([]byte, len(download)))
	if _, err := mc.Write(download); err != nil {
		t.Fatalf("写给客户端失败: %v", err)
	}

	// 客户端发给代理 = 客户端在上传
	upload := []byte("abc")
	go clientSide.Write(upload)
	if _, err := io.ReadFull(mc, make([]byte, len(upload))); err != nil {
		t.Fatalf("从客户端读失败: %v", err)
	}

	if info.BytesIn != int64(len(download)) {
		t.Errorf("单连接下行 BytesIn = %d, 期望 %d", info.BytesIn, len(download))
	}
	if info.BytesOut != int64(len(upload)) {
		t.Errorf("单连接上行 BytesOut = %d, 期望 %d", info.BytesOut, len(upload))
	}
	if got := atomic.LoadInt64(&Stats.totalBytesIn) - beforeIn; got != int64(len(download)) {
		t.Errorf("全局下行增量 = %d, 期望 %d", got, len(download))
	}
	if got := atomic.LoadInt64(&Stats.totalBytesOut) - beforeOut; got != int64(len(upload)) {
		t.Errorf("全局上行增量 = %d, 期望 %d", got, len(upload))
	}
}
