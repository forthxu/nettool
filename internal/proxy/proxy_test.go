package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/armon/go-socks5"

	"nettool/internal/sockopt"
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

// TestResolverUsesInstanceEgress 锁死 DNS 泄漏这条：代理自己解析域名时，
// 查询必须和数据连接走同一个出口。漏了的话在被污染的网络里会拿到假地址，
// 而且泄漏了「这个实例在查什么」。
//
// 这里只验证 resolver 确实把实例的出口约束交给了拨号器（构造成功且约束不为空），
// 真正的出口生效与否要靠 uplink 包的验证与真机抓包，见 README 的「测试」一节。
func TestResolverUsesInstanceEgress(t *testing.T) {
	egress := sockopt.Egress{
		Options:   sockopt.Options{IfIndex: 1},
		SourceIP:  "192.168.1.20",
		PortStart: 20000, PortEnd: 20255,
	}
	r := &resolver{dns: "8.8.8.8:53", egress: egress}
	if r.egress.Empty() {
		t.Fatal("resolver 必须带上实例的出口约束，否则 DNS 会从默认网关漏出去")
	}
	if _, err := sockopt.NewDialer(r.egress, net.Dialer{}); err != nil {
		t.Fatalf("resolver 的出口约束应当能构造出拨号器: %v", err)
	}

	// 限定了源端口段却没有源地址是自相矛盾的：PF 规则按两者一起匹配，
	// 只绑端口不绑地址的包匹配不上，会静默从默认网关出去
	bad := sockopt.Egress{PortStart: 20000, PortEnd: 20255}
	if _, err := sockopt.NewDialer(bad, net.Dialer{}); err == nil {
		t.Error("缺源地址的端口段约束必须被拒绝")
	}
}

// newTestManager 造一个用临时目录落盘的 Manager，并返回它的主实例。
// 改造前这几个测试是直接改包级变量（Default、configPath）再在 Cleanup 里还原的，
// 现在没有包级状态可改，测试之间天然隔离。
func newTestManager(t *testing.T) (*Manager, *Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proxy.json")
	m := NewManager()
	m.Load(path) // 文件不存在，会建一个默认实例
	s := m.Primary()
	if s == nil {
		t.Fatal("Load 之后应当有一个默认实例")
	}
	return m, s, path
}

func freePort(t *testing.T) string {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("找空闲端口失败: %v", err)
	}
	defer probe.Close()
	_, port, _ := net.SplitHostPort(probe.Addr().String())
	return port
}

// 回归：代理运行中改「代理 DNS」，新值要真的存进配置。
// startLocked 曾漏写 p.dns，结果新 DNS 立即生效了，Config() 与界面却还报旧值。
func TestSetConfigKeepsDNSWhileRunning(t *testing.T) {
	_, p, _ := newTestManager(t)
	port := freePort(t)

	cfg := p.Config()
	cfg.Port, cfg.DNS = port, "8.8.8.8"
	if err := p.Start(cfg); err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}
	t.Cleanup(func() { p.Stop() })

	// 只填 IP 的写法会补上 :53，存的应当是归一化之后的那份
	if dns := p.Config().DNS; dns != "8.8.8.8:53" {
		t.Errorf("启动时的 DNS = %q, 期望 8.8.8.8:53", dns)
	}

	// 运行中改配置会带新配置重启，改完必须能读回来
	cfg.DNS = "1.1.1.1:5353"
	if err := p.SetConfig(cfg); err != nil {
		t.Fatalf("运行中改配置失败: %v", err)
	}
	got := p.Config()
	if got.DNS != "1.1.1.1:5353" {
		t.Errorf("改完的 DNS = %q, 期望 1.1.1.1:5353", got.DNS)
	}
	if got.Port != port || !p.Running() {
		t.Errorf("改配置后应仍在同一端口运行, port=%q running=%v", got.Port, p.Running())
	}

	// 清空也要生效（回到跟随系统解析）
	cfg.DNS = ""
	if err := p.SetConfig(cfg); err != nil {
		t.Fatalf("清空 DNS 失败: %v", err)
	}
	if dns := p.Config().DNS; dns != "" {
		t.Errorf("清空后的 DNS = %q, 期望空", dns)
	}

	// 停止状态下保存配置同样要存下来，且不会把代理拉起来
	if err := p.Stop(); err != nil {
		t.Fatalf("停止代理失败: %v", err)
	}
	cfg.DNS = "223.5.5.5"
	if err := p.SetConfig(cfg); err != nil {
		t.Fatalf("停止状态下改配置失败: %v", err)
	}
	if dns := p.Config().DNS; dns != "223.5.5.5:53" {
		t.Errorf("停止状态下保存的 DNS = %q, 期望 223.5.5.5:53", dns)
	}
	if p.Running() {
		t.Error("保存配置不应把停着的代理拉起来")
	}
}

// 进程重启后要按上次的开关状态恢复：上次开着就自动起来，点过停止就保持停止
func TestPersistRunStateAcrossRestart(t *testing.T) {
	_, p, path := newTestManager(t)
	port := freePort(t)

	// 模拟用户在后台配好并点了「启动代理」
	cfg := p.Config()
	cfg.Port, cfg.DNS = port, "8.8.8.8"
	if err := p.SetConfig(cfg); err != nil {
		t.Fatalf("保存配置失败: %v", err)
	}
	if readPersistedProxy(t, path).Instances[0].Running {
		t.Error("只保存配置不该把 running 记成 true")
	}
	if err := p.StartCurrent(); err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}
	t.Cleanup(func() { p.Stop() })

	saved := readPersistedProxy(t, path).Instances[0]
	if !saved.Running || saved.Port != port || saved.DNS != "8.8.8.8:53" {
		t.Fatalf("落盘的配置不对: %+v", saved)
	}

	// 模拟进程重启：新 Manager 只读文件，就该知道上次是开着的、端口和 DNS 是哪个
	reborn := NewManager()
	if !reborn.Load(path) {
		t.Fatal("读取配置失败")
	}
	rs := reborn.Primary()
	if !rs.WasRunning() {
		t.Error("上次是开着的，WasRunning 应当为 true")
	}
	if got := rs.Config(); got.Port != port || got.DNS != "8.8.8.8:53" {
		t.Errorf("恢复的配置 = %q / %q, 期望 %q / 8.8.8.8:53", got.Port, got.DNS, port)
	}

	// 点停止之后，下次启动就不该再自动起来
	if err := p.Stop(); err != nil {
		t.Fatalf("停止代理失败: %v", err)
	}
	if readPersistedProxy(t, path).Instances[0].Running {
		t.Fatal("点了停止之后配置里应当记下 running=false")
	}
	reborn2 := NewManager()
	reborn2.Load(path)
	if reborn2.Primary().WasRunning() {
		t.Error("上次是停着的，WasRunning 应当为 false")
	}
}

// v1 是单个扁平对象，v2 是实例列表。老用户升级上来配置一个字段都不能丢，
// 否则代理端口、开关状态全部回到默认值——这是本次改造唯一会伤到
// 现有用户的地方，必须钉死。
func TestMigrateProxyConfigV1ToV2(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.json")
	v1 := `{"version":1,"saved_at":"2025-06-01T10:00:00+08:00",
	        "running":true,"port":"1080","outbound_ip":"127.0.0.1","dns":"8.8.8.8:53"}`
	if err := os.WriteFile(path, []byte(v1), 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewManager()
	if !m.Load(path) {
		t.Fatal("载入 v1 配置应当成功")
	}
	if n := m.Count(); n != 1 {
		t.Fatalf("v1 应当迁成 1 个实例，实际 %d 个", n)
	}
	cfg := m.Primary().Config()
	if cfg.Port != "1080" {
		t.Errorf("端口 = %q, 期望 1080", cfg.Port)
	}
	if cfg.LegacyOutboundIP != "" {
		t.Errorf("迁移后 outbound_ip 应当已被清空，实际 %q", cfg.LegacyOutboundIP)
	}
	if cfg.DNS != "8.8.8.8:53" {
		t.Errorf("DNS = %q, 期望 8.8.8.8:53", cfg.DNS)
	}
	if !m.Primary().WasRunning() {
		t.Error("v1 里 running=true，迁移后开关意愿应当保留")
	}

	// 原文件要备份下来，让降级回旧版本仍有退路
	backup, err := os.ReadFile(path + ".v1.bak")
	if err != nil {
		t.Fatalf("应当留下 v1 备份: %v", err)
	}
	if string(backup) != v1 {
		t.Error("备份内容与原文件不一致")
	}

	// 落盘之后应当是 v2 形状，且再读一次结果不变。
	// 迁移本身不写盘，等第一次配置变动才写——这里改个名触发一次。
	cfg.Name = "默认代理"
	if err := m.Primary().SetConfig(cfg); err != nil {
		t.Fatalf("保存配置失败: %v", err)
	}
	saved := readPersistedProxy(t, path)
	if saved.Version != 2 || len(saved.Instances) != 1 {
		t.Fatalf("落盘后应当是 v2 单实例，实际: %+v", saved)
	}
	again := NewManager()
	again.Load(path)
	if got := again.Primary().Config(); got.Port != "1080" || got.DNS != "8.8.8.8:53" {
		t.Errorf("二次载入结果变了: %+v", got)
	}
}

// v1 里 running 明确是 false 时，不能被当成"没有这个字段"而丢掉
func TestMigrateV1KeepsExplicitStoppedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"running":false,"port":"1080"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	m := NewManager()
	m.Load(path)
	if m.Primary().Config().Port != "1080" {
		t.Error("running=false 的 v1 配置也要迁移，不能整条丢掉")
	}
	if m.Primary().WasRunning() {
		t.Error("v1 里 running=false，不该变成 true")
	}
}

// 端口撞车要给出人话，而不是一句 bind: address already in use
func TestPortCollisionAcrossInstances(t *testing.T) {
	m, first, _ := newTestManager(t)
	cfg := first.Config()
	cfg.Name, cfg.Port = "线路A", "18091"
	if err := first.SetConfig(cfg); err != nil {
		t.Fatalf("配置主实例失败: %v", err)
	}

	// 新建实例时撞车
	if _, err := m.Add(Instance{Name: "线路B", Port: "18091"}); err == nil {
		t.Fatal("端口撞车时新建实例应当报错")
	} else if !strings.Contains(err.Error(), "线路A") {
		t.Errorf("错误信息里应当指出是被哪个实例占了，实际: %v", err)
	}

	second, err := m.Add(Instance{Name: "线路B", Port: "18092"})
	if err != nil {
		t.Fatalf("新建第二个实例失败: %v", err)
	}
	// 改配置时撞车
	c2 := second.Config()
	c2.Port = "18091"
	if err := second.SetConfig(c2); err == nil {
		t.Error("改成已被占用的端口应当报错")
	}
	// 改成自己原本的端口不算撞车
	c2.Port = "18092"
	if err := second.SetConfig(c2); err != nil {
		t.Errorf("改成自己原本的端口不该报错: %v", err)
	}
}

// 每个实例一份统计口径。共用一份的话，SetTarget 会按客户端地址扫到别的实例的
// 连接上，界面上就会看到 A 实例的连接显示着 B 实例的目标地址。
func TestSetTargetMatchesOwnInstanceOnly(t *testing.T) {
	a, b := newStats(), newStats()
	const client = "192.168.1.9:54321"

	ca := a.AddConnection("conn-1", client, "握手中…")
	cb := b.AddConnection("conn-1", client, "握手中…")

	a.SetTarget(client, "a.example.com:443")
	if ca.TargetAddr != "a.example.com:443" {
		t.Errorf("本实例的连接没被回填: %q", ca.TargetAddr)
	}
	if cb.TargetAddr != "握手中…" {
		t.Errorf("另一个实例的连接被串改了: %q", cb.TargetAddr)
	}

	// 客户端临时端口被复用时，要命中新连接而不是旧的
	a.RemoveConnection("conn-1")
	fresh := a.AddConnection("conn-2", client, "握手中…")
	a.SetTarget(client, "new.example.com:443")
	if fresh.TargetAddr != "new.example.com:443" {
		t.Errorf("端口复用后新连接没被回填: %q", fresh.TargetAddr)
	}
	if ca.TargetAddr != "a.example.com:443" {
		t.Errorf("已结束的旧连接被改动了: %q", ca.TargetAddr)
	}
}

// 索引维护：新连接顶掉同地址的旧连接后，旧连接结束不能把新连接的索引删掉
func TestRemoveConnectionKeepsNewerIndex(t *testing.T) {
	s := newStats()
	const client = "10.0.0.2:5000"

	old := s.AddConnection("conn-1", client, "握手中…")
	fresh := s.AddConnection("conn-2", client, "握手中…")
	s.RemoveConnection("conn-1") // 旧连接后结束

	s.SetTarget(client, "target:443")
	if fresh.TargetAddr != "target:443" {
		t.Errorf("旧连接结束后，新连接的索引被误删了: %q", fresh.TargetAddr)
	}
	if old.TargetAddr != "握手中…" {
		t.Errorf("已移除的旧连接不该再被回填: %q", old.TargetAddr)
	}
}

// 命令行只覆盖真填了的那几项，其余沿用上次存下来的；且只作用于主实例
// 监听地址默认只听本机：SOCKS5 这层没有任何客户端鉴权，一旦默认绑到
// 0.0.0.0，装上就是一台谁都能用的公开代理。旧台账里没有这个字段，
// 也必须补成 127.0.0.1 而不是沿用从前的 0.0.0.0。
func TestListenDefaultsToLoopback(t *testing.T) {
	m := NewManager()
	m.Load("")
	if got := m.Primary().Config().Listen; got != "127.0.0.1" {
		t.Errorf("新实例监听地址 = %q, 期望 127.0.0.1", got)
	}

	// 旧配置（v2 但没有 listen 字段）走 sanitizeInstance 也要补上
	if got := sanitizeInstance(Instance{ID: "p9", Port: "8091"}).Listen; got != "127.0.0.1" {
		t.Errorf("旧台账补全后的监听地址 = %q, 期望 127.0.0.1", got)
	}
	// 手写坏了的地址退回默认，而不是让整条实例消失
	if got := sanitizeInstance(Instance{ID: "p9", Port: "8091", Listen: "不是IP"}).Listen; got != "127.0.0.1" {
		t.Errorf("非法监听地址应退回 127.0.0.1, 得到 %q", got)
	}

	// 显式设成 0.0.0.0 是允许的，路由器上要给局域网设备用就得这么配
	p := m.Primary()
	cfg := p.Config()
	cfg.Listen = "0.0.0.0"
	if err := p.SetConfig(cfg); err != nil {
		t.Fatalf("设置 0.0.0.0 应当被接受: %v", err)
	}
	if got := p.Config().Listen; got != "0.0.0.0" {
		t.Errorf("监听地址 = %q, 期望 0.0.0.0", got)
	}

	cfg.Listen = "不是IP"
	if err := p.SetConfig(cfg); err == nil {
		t.Error("非法监听地址应当报错")
	}
}

func TestApplyProxyFlagsOverridesOnlyWhatIsGiven(t *testing.T) {
	m := NewManager()
	m.Load("") // 不落盘
	p := m.Primary()
	cfg := p.Config()
	cfg.Port, cfg.DNS = "1080", "223.5.5.5:53"
	if err := p.SetConfig(cfg); err != nil {
		t.Fatalf("准备配置失败: %v", err)
	}

	if err := m.ApplyFlags("", "", ""); err != nil {
		t.Fatalf("应用命令行参数失败: %v", err)
	}
	if got := p.Config(); got.Port != "1080" || got.DNS != "223.5.5.5:53" {
		t.Errorf("没给参数时不该动已有配置, 得到 %q / %q", got.Port, got.DNS)
	}

	if err := m.ApplyFlags("", "1081", ""); err != nil {
		t.Fatalf("应用命令行参数失败: %v", err)
	}
	got := p.Config()
	if got.Port != "1081" {
		t.Errorf("端口 = %q, 期望 1081", got.Port)
	}
	if got.DNS != "223.5.5.5:53" {
		t.Errorf("只给了端口，代理 DNS 被冲掉了: %q", got.DNS)
	}

	if err := m.ApplyFlags("", "", "8.8.8"); err == nil {
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

	stats := newStats()
	info := &ConnectionInfo{ID: "test-direction"}
	mc := &MonitoredConn{Conn: proxySide, info: info, stats: stats}

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
	if got := atomic.LoadInt64(&stats.totalBytesIn); got != int64(len(download)) {
		t.Errorf("实例下行合计 = %d, 期望 %d", got, len(download))
	}
	if got := atomic.LoadInt64(&stats.totalBytesOut); got != int64(len(upload)) {
		t.Errorf("实例上行合计 = %d, 期望 %d", got, len(upload))
	}
}

// 绑定了未生效出口线路的实例必须拒绝启动，而不是悄悄从默认网关出去
func TestInstanceRefusesBrokenUplink(t *testing.T) {
	m, p, _ := newTestManager(t)
	m.SetUplinks(brokenUplinks{})

	cfg := p.Config()
	cfg.Port, cfg.UplinkID = freePort(t), "u1"
	if err := p.SetConfig(cfg); err == nil {
		t.Fatal("出口线路没生效时应当拒绝保存并启动")
	}
	if p.Running() {
		t.Error("实例不该被拉起来")
	}

	// 没接出口线路查询时同样要拒绝，不能当成"没绑线路"放行
	m2 := NewManager()
	m2.Load("")
	c2 := m2.Primary().Config()
	c2.UplinkID = "u1"
	if err := m2.Primary().SetConfig(c2); err == nil {
		t.Error("没有出口线路管理时，绑了线路的实例应当拒绝启动")
	}
}

type brokenUplinks struct{}

func (brokenUplinks) DialOptions(id string) (sockopt.Egress, error) {
	return sockopt.Egress{}, errors.New("出口线路「测试」当前未生效: ip rule 下发失败")
}

func (brokenUplinks) EnsureForSourceIP(ip, name string) (string, error) {
	return "", errors.New("测试用：不建线路")
}

// fakeUplinks 记录 EnsureForSourceIP 被拿什么参数调过，用来验证迁移
type fakeUplinks struct {
	asked []string
	id    string
	err   error
}

func (f *fakeUplinks) DialOptions(id string) (sockopt.Egress, error) {
	return sockopt.Egress{Options: sockopt.Options{Mark: 0x40000000}}, nil
}

func (f *fakeUplinks) EnsureForSourceIP(ip, name string) (string, error) {
	f.asked = append(f.asked, ip)
	return f.id, f.err
}

// 旧配置里的「绑定出口 IP」必须转成出口线路，而不是直接丢掉。
// 丢掉的话升级后实例就悄悄改从默认网关出去了，用户看不到任何提示。
func TestMigrateOutboundIPToUplink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.json")
	v1 := `{"version":1,"running":true,"port":"1080","outbound_ip":"192.168.1.5"}`
	if err := os.WriteFile(path, []byte(v1), 0o644); err != nil {
		t.Fatal(err)
	}

	fake := &fakeUplinks{id: "u1"}
	m := NewManager()
	m.SetUplinks(fake)
	m.Load(path)

	if len(fake.asked) != 1 || fake.asked[0] != "192.168.1.5" {
		t.Fatalf("应当拿旧的出口 IP 去建线路，实际调用参数: %v", fake.asked)
	}
	cfg := m.Primary().Config()
	if cfg.UplinkID != "u1" {
		t.Errorf("迁移后应当绑上线路 u1，实际 %q", cfg.UplinkID)
	}

	// 落盘之后 outbound_ip 要彻底消失，uplink_id 要留下
	saved := readPersistedProxy(t, path)
	if len(saved.Instances) != 1 {
		t.Fatalf("落盘结果不对: %+v", saved)
	}
	if saved.Instances[0].LegacyOutboundIP != "" {
		t.Errorf("outbound_ip 应当已从文件里消失，实际 %q", saved.Instances[0].LegacyOutboundIP)
	}
	if saved.Instances[0].UplinkID != "u1" {
		t.Errorf("uplink_id 应当已落盘，实际 %q", saved.Instances[0].UplinkID)
	}

	// 再载入一次不应该重复建线路
	fake2 := &fakeUplinks{id: "u9"}
	m2 := NewManager()
	m2.SetUplinks(fake2)
	m2.Load(path)
	if len(fake2.asked) != 0 {
		t.Errorf("已经迁移过的配置不该再建线路，实际又调用了: %v", fake2.asked)
	}
	if got := m2.Primary().Config().UplinkID; got != "u1" {
		t.Errorf("二次载入后线路绑定变了: %q", got)
	}
}

// 线路建好但下发失败时仍然要绑上：实例会拒绝启动并报出原因，
// 好过让它悄悄从默认网关出去。
func TestMigrateBindsEvenWhenUplinkNotApplied(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"port":"1080","outbound_ip":"192.168.1.5"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	m := NewManager()
	m.SetUplinks(&fakeUplinks{id: "u1", err: errors.New("没有 root，ip rule 下发失败")})
	m.Load(path)

	if got := m.Primary().Config().UplinkID; got != "u1" {
		t.Errorf("线路下发失败时也应当绑上，实际 %q", got)
	}
}

// 完全建不出线路时（网卡拔了之类）只能放弃绑定，但不能把配置搞坏
func TestMigrateFallsBackWhenUplinkCannotBeCreated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"port":"1080","outbound_ip":"192.168.1.5"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	m := NewManager()
	m.SetUplinks(&fakeUplinks{id: "", err: errors.New("本机没有 IP 为 192.168.1.5 的网卡")})
	m.Load(path)

	cfg := m.Primary().Config()
	if cfg.UplinkID != "" {
		t.Errorf("建不出线路时不该乱绑，实际 %q", cfg.UplinkID)
	}
	if cfg.Port != "1080" {
		t.Errorf("迁移失败不该影响其他字段，端口 = %q", cfg.Port)
	}
}
