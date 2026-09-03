package dnsserver

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestNormalizeUpstream(t *testing.T) {
	cases := []struct {
		name     string
		in       Upstream
		wantType string
		wantAddr string
		wantHost string
		wantErr  bool
	}{
		{name: "裸 IP 补 53", in: Upstream{Address: "8.8.8.8"}, wantType: upstreamUDP, wantAddr: "8.8.8.8:53"},
		{name: "带端口", in: Upstream{Address: "223.5.5.5:5353"}, wantType: upstreamUDP, wantAddr: "223.5.5.5:5353"},
		{name: "udp scheme", in: Upstream{Address: "udp://1.1.1.1"}, wantType: upstreamUDP, wantAddr: "1.1.1.1:53"},
		{name: "tcp scheme", in: Upstream{Address: "tcp://1.1.1.1"}, wantType: upstreamTCP, wantAddr: "1.1.1.1:53"},
		{name: "DoT 域名", in: Upstream{Address: "tls://dns.google"}, wantType: upstreamTLS, wantAddr: "dns.google:853", wantHost: "dns.google"},
		{name: "DoT IP@域名", in: Upstream{Address: "tls://1.1.1.1@one.one.one.one"}, wantType: upstreamTLS, wantAddr: "1.1.1.1:853", wantHost: "one.one.one.one"},
		{name: "DoH 补路径", in: Upstream{Address: "https://dns.google"}, wantType: upstreamHTTPS, wantAddr: "https://dns.google/dns-query", wantHost: "dns.google"},
		{name: "DoH 完整 URL", in: Upstream{Address: "https://doh.pub/dns-query"}, wantType: upstreamHTTPS, wantAddr: "https://doh.pub/dns-query", wantHost: "doh.pub"},
		{name: "类型字段生效", in: Upstream{Type: upstreamTCP, Address: "9.9.9.9"}, wantType: upstreamTCP, wantAddr: "9.9.9.9:53"},

		{name: "空地址", in: Upstream{Address: ""}, wantErr: true},
		{name: "DoT 只给 IP 无法校验证书", in: Upstream{Address: "tls://1.1.1.1"}, wantErr: true},
		{name: "明文 http 的 DoH", in: Upstream{Address: "http://dns.google/dns-query"}, wantErr: true},
		{name: "端口越界", in: Upstream{Address: "8.8.8.8:70000"}, wantErr: true},
		{name: "未知类型", in: Upstream{Type: "quic", Address: "8.8.8.8"}, wantErr: true},
		{name: "bootstrap 必须是 IP", in: Upstream{Address: "tls://dns.google", Bootstrap: "dns.example.com"}, wantErr: true},
	}

	for _, c := range cases {
		got, err := normalizeUpstream(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: normalizeUpstream(%+v) 期望报错，实际得到 %+v", c.name, c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: 意外报错: %v", c.name, err)
			continue
		}
		if got.Type != c.wantType {
			t.Errorf("%s: type = %q, 期望 %q", c.name, got.Type, c.wantType)
		}
		if got.Address != c.wantAddr {
			t.Errorf("%s: address = %q, 期望 %q", c.name, got.Address, c.wantAddr)
		}
		if c.wantHost != "" && got.Hostname != c.wantHost {
			t.Errorf("%s: hostname = %q, 期望 %q", c.name, got.Hostname, c.wantHost)
		}
		if got.Name == "" {
			t.Errorf("%s: name 不该为空", c.name)
		}
	}
}

func TestNormalizeUpstreamDomains(t *testing.T) {
	got, err := normalizeUpstream(Upstream{
		Address: "8.8.8.8",
		Domains: []string{" Example.COM ", "example.com", "", ".google.com.", "  "},
	})
	if err != nil {
		t.Fatalf("意外报错: %v", err)
	}
	want := []string{"example.com", "google.com"}
	if len(got.Domains) != len(want) {
		t.Fatalf("domains = %v, 期望 %v", got.Domains, want)
	}
	for i := range want {
		if got.Domains[i] != want[i] {
			t.Errorf("domains[%d] = %q, 期望 %q", i, got.Domains[i], want[i])
		}
	}
}

func TestValidateSettings(t *testing.T) {
	s, err := validateSettings(Settings{})
	if err != nil {
		t.Fatalf("空配置应当被补成默认值: %v", err)
	}
	if s.Listen != "127.0.0.1" || s.Port != "53" || s.Strategy != strategySequential {
		t.Errorf("默认值不对: %+v", s)
	}
	if s.TimeoutMS != 5000 || s.CacheSize != 4096 {
		t.Errorf("超时/缓存默认值不对: %+v", s)
	}

	// 上游重名要被自动区分开，否则统计会混在一起
	dup, err := validateSettings(Settings{Upstreams: []Upstream{
		{Name: "主力", Address: "8.8.8.8"},
		{Name: "主力", Address: "1.1.1.1"},
		{Name: "主力", Address: "9.9.9.9"},
	}})
	if err != nil {
		t.Fatalf("意外报错: %v", err)
	}
	names := map[string]bool{}
	for _, u := range dup.Upstreams {
		if names[u.Name] {
			t.Errorf("上游名字重复: %q", u.Name)
		}
		names[u.Name] = true
	}

	// 边界值被夹住
	clamped, err := validateSettings(Settings{TimeoutMS: 1, CacheSize: -5, MinTTL: 600, MaxTTL: 60})
	if err != nil {
		t.Fatalf("意外报错: %v", err)
	}
	if clamped.TimeoutMS != 200 {
		t.Errorf("timeout = %d, 期望夹到 200", clamped.TimeoutMS)
	}
	if clamped.MaxTTL < clamped.MinTTL {
		t.Errorf("max_ttl(%d) 不应小于 min_ttl(%d)", clamped.MaxTTL, clamped.MinTTL)
	}

	errCases := []Settings{
		{Listen: "不是IP"},
		{Port: "0"},
		{Port: "abc"},
		{Strategy: "random"},
		{Hosts: []HostRecord{{Domain: "example.com", IP: "999.1.1.1"}}},
		{Hosts: []HostRecord{{Domain: "!!", IP: "1.2.3.4"}}},
		{Upstreams: []Upstream{{Address: "tls://1.1.1.1"}}},
	}
	for i, c := range errCases {
		if _, err := validateSettings(c); err == nil {
			t.Errorf("第 %d 个非法配置期望报错: %+v", i, c)
		}
	}
}

func TestSelectUpstreams(t *testing.T) {
	ups := []Upstream{
		{Name: "默认", Address: "8.8.8.8:53", Enabled: true},
		{Name: "国内", Address: "223.5.5.5:53", Enabled: true, Domains: []string{"cn", "example.com"}},
		{Name: "更细", Address: "114.114.114.114:53", Enabled: true, Domains: []string{"mail.example.com"}},
		{Name: "停用的", Address: "1.1.1.1:53", Enabled: false, Domains: []string{"example.com"}},
	}

	cases := []struct {
		name string
		want []string
	}{
		{"google.com", []string{"默认"}},
		{"example.com", []string{"国内"}},
		{"www.example.com", []string{"国内"}},
		{"mail.example.com", []string{"更细"}},   // 最长匹配优先
		{"a.mail.example.com", []string{"更细"}}, // 子域也归最长的那条
		{"weibo.cn", []string{"国内"}},
		{"notexample.com", []string{"默认"}}, // 不能被 example.com 后缀误伤
	}
	for _, c := range cases {
		got := selectUpstreams(ups, c.name)
		if len(got) != len(c.want) {
			t.Errorf("selectUpstreams(%q) = %v, 期望 %v", c.name, upstreamNames(got), c.want)
			continue
		}
		for i := range c.want {
			if got[i].Name != c.want[i] {
				t.Errorf("selectUpstreams(%q)[%d] = %q, 期望 %q", c.name, i, got[i].Name, c.want[i])
			}
		}
	}

	if got := selectUpstreams([]Upstream{{Name: "x", Enabled: false}}, "a.com"); len(got) != 0 {
		t.Errorf("全部停用时应当没有可选上游, 得到 %v", upstreamNames(got))
	}
}

func upstreamNames(ups []Upstream) []string {
	out := make([]string, 0, len(ups))
	for _, u := range ups {
		out = append(out, u.Name)
	}
	return out
}

func TestMatchHosts(t *testing.T) {
	hosts := []HostRecord{
		{Domain: "nas.local", IP: "192.168.1.10"},
		{Domain: "nas.local", IP: "192.168.1.11"},
		{Domain: "*.dev.local", IP: "127.0.0.1"},
		{Domain: "v6.local", IP: "fd00::1"},
	}

	if got := matchHosts(hosts, "nas.local", dnsmessage.TypeA); len(got) != 2 {
		t.Errorf("同名多 IP 应当都返回, 得到 %v", got)
	}
	if got := matchHosts(hosts, "api.dev.local", dnsmessage.TypeA); len(got) != 1 || got[0].String() != "127.0.0.1" {
		t.Errorf("通配符没命中: %v", got)
	}
	if got := matchHosts(hosts, "dev.local", dnsmessage.TypeA); len(got) != 0 {
		t.Errorf("*.dev.local 不该匹配 dev.local 本身: %v", got)
	}
	if got := matchHosts(hosts, "nas.local", dnsmessage.TypeAAAA); len(got) != 0 {
		t.Errorf("查 AAAA 不该返回 IPv4: %v", got)
	}
	if got := matchHosts(hosts, "v6.local", dnsmessage.TypeAAAA); len(got) != 1 {
		t.Errorf("IPv6 静态记录没命中: %v", got)
	}
	if got := matchHosts(hosts, "nas.local", dnsmessage.TypeMX); len(got) != 0 {
		t.Errorf("静态记录只该管 A/AAAA: %v", got)
	}
}

func TestDNSCacheTTLDecay(t *testing.T) {
	c := newCache(10)
	q := dnsmessage.Question{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{Response: true},
		Questions: []dnsmessage.Question{q},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
			Body:   &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}},
		}},
	}

	base := time.Now()
	key := cacheKey(q)
	c.put(key, msg, 300*time.Second, base)

	got, ok := c.get(key, base.Add(100*time.Second))
	if !ok {
		t.Fatal("缓存应当命中")
	}
	if got.Answers[0].Header.TTL != 200 {
		t.Errorf("TTL = %d, 期望扣掉已缓存的 100 秒后是 200", got.Answers[0].Header.TTL)
	}
	// 存进去的那份不能被改坏，否则第二次命中会重复扣减
	if msg.Answers[0].Header.TTL != 300 {
		t.Errorf("原始记录的 TTL 被改成了 %d", msg.Answers[0].Header.TTL)
	}

	if _, ok := c.get(key, base.Add(301*time.Second)); ok {
		t.Error("过期后不该再命中")
	}
	if c.len() != 0 {
		t.Errorf("过期项应当被顺手清掉, 还剩 %d", c.len())
	}
}

func TestDNSCacheEviction(t *testing.T) {
	c := newCache(8)
	now := time.Now()
	for i := 0; i < 40; i++ {
		c.put("key"+string(rune('a'+i)), dnsmessage.Message{}, time.Minute, now)
	}
	if c.len() > 8 {
		t.Errorf("缓存条目 %d 超过上限 8", c.len())
	}
}

func TestCacheTTLClamp(t *testing.T) {
	rt := newEngine(Settings{MinTTL: 30, MaxTTL: 600, TimeoutMS: 1000}, newStats())
	mk := func(rcode dnsmessage.RCode, ttls ...uint32) dnsmessage.Message {
		m := dnsmessage.Message{Header: dnsmessage.Header{Response: true, RCode: rcode}}
		for _, ttl := range ttls {
			m.Answers = append(m.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{TTL: ttl, Type: dnsmessage.TypeA},
				Body:   &dnsmessage.AResource{},
			})
		}
		return m
	}

	if got := rt.cacheTTL(mk(dnsmessage.RCodeSuccess, 5, 900)); got != 30*time.Second {
		t.Errorf("最小 TTL 应被抬到 30s, 得到 %v", got)
	}
	if got := rt.cacheTTL(mk(dnsmessage.RCodeSuccess, 3600)); got != 600*time.Second {
		t.Errorf("超长 TTL 应被压到 600s, 得到 %v", got)
	}
	if got := rt.cacheTTL(mk(dnsmessage.RCodeNameError)); got != negativeTTL {
		t.Errorf("NXDOMAIN 应走负缓存, 得到 %v", got)
	}
	if got := rt.cacheTTL(mk(dnsmessage.RCodeServerFailure, 60)); got != 0 {
		t.Errorf("SERVFAIL 不该缓存, 得到 %v", got)
	}
}

func TestUDPBufferSize(t *testing.T) {
	plain := mustPackQuery(t, "example.com.", dnsmessage.TypeA, 0)
	if got := udpBufferSize(plain); got != 512 {
		t.Errorf("没有 EDNS 时应当是 512, 得到 %d", got)
	}
	withEDNS := mustPackQuery(t, "example.com.", dnsmessage.TypeA, 1232)
	if got := udpBufferSize(withEDNS); got != 1232 {
		t.Errorf("EDNS 缓冲区应当是 1232, 得到 %d", got)
	}
	if got := udpBufferSize([]byte{1, 2, 3}); got != 512 {
		t.Errorf("坏报文应当退回 512, 得到 %d", got)
	}
}

func TestBuildResponse(t *testing.T) {
	q := dnsmessage.Question{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	raw := buildResponse(dnsmessage.Header{ID: 0x1234, RecursionDesired: true}, q, dnsmessage.RCodeServerFailure, nil)

	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		t.Fatalf("生成的应答解不开: %v", err)
	}
	if msg.Header.ID != 0x1234 || !msg.Header.Response {
		t.Errorf("头部不对: %+v", msg.Header)
	}
	if msg.Header.RCode != dnsmessage.RCodeServerFailure {
		t.Errorf("RCode = %v, 期望 SERVFAIL", msg.Header.RCode)
	}
	if len(msg.Questions) != 1 || msg.Questions[0].Name.String() != "example.com." {
		t.Errorf("问题段没带回来: %+v", msg.Questions)
	}

	// 连问题段都没有时也要能打包出一个合法应答
	if raw := buildResponse(dnsmessage.Header{ID: 7}, dnsmessage.Question{}, dnsmessage.RCodeFormatError, nil); len(raw) < 12 {
		t.Errorf("空问题段的应答长度 %d 不合法", len(raw))
	}
}

// ---------------------------------------------------------------------------
// 端到端：起一个假的上游 DNS，再起本地服务，从 UDP/TCP 两侧各问一遍
// ---------------------------------------------------------------------------

// fakeUpstream 是个只回一条 A 记录的极简 DNS 服务器
type fakeUpstream struct {
	conn  *net.UDPConn
	addr  string
	ip    [4]byte
	ttl   uint32
	count int64 // 收到过几次查询，测试里跨 goroutine 读，用原子操作
}

func (f *fakeUpstream) hits() int64 { return atomic.LoadInt64(&f.count) }

func startFakeUpstream(t *testing.T, ip [4]byte, ttl uint32) *fakeUpstream {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("假上游监听失败: %v", err)
	}
	f := &fakeUpstream{conn: conn, addr: conn.LocalAddr().String(), ip: ip, ttl: ttl}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, client, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			hdr, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			atomic.AddInt64(&f.count, 1)
			resp := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: hdr.ID, Response: true, RecursionAvailable: true},
				Questions: []dnsmessage.Question{q},
				Answers: []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: f.ttl},
					Body:   &dnsmessage.AResource{A: f.ip},
				}},
			}
			packed, err := resp.Pack()
			if err != nil {
				continue
			}
			conn.WriteToUDP(packed, client)
		}
	}()

	t.Cleanup(func() { conn.Close() })
	return f
}

func mustPackQuery(t *testing.T, name string, qtype dnsmessage.Type, ednsSize uint16) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x4242, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: qtype, Class: dnsmessage.ClassINET}},
	}
	if ednsSize > 0 {
		msg.Additionals = append(msg.Additionals, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: dnsmessage.Class(ednsSize)},
			Body:   &dnsmessage.OPTResource{},
		})
	}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatalf("打包查询失败: %v", err)
	}
	return packed
}

// startTestServer 在随机端口上起一个本地 DNS 服务，返回地址
func startTestServer(t *testing.T, s Settings) (*Server, string) {
	t.Helper()

	// 借系统分配一个空闲端口，再让服务自己去占——单测不能碰 53
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("找空闲端口失败: %v", err)
	}
	_, port, _ := net.SplitHostPort(probe.LocalAddr().String())
	probe.Close()

	s.Listen, s.Port = "127.0.0.1", port
	srv := &Server{settings: defaultSettings(), stats: newStats()}
	if err := srv.SetConfig(s); err != nil {
		t.Fatalf("配置无效: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("启动 DNS 服务失败: %v", err)
	}
	t.Cleanup(srv.Stop)
	return srv, net.JoinHostPort("127.0.0.1", port)
}

func queryUDP(t *testing.T, addr string, req []byte) dnsmessage.Message {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("连本地 DNS 失败: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("发送查询失败: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("读取应答失败: %v", err)
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(buf[:n]); err != nil {
		t.Fatalf("应答解析失败: %v", err)
	}
	return msg
}

func queryTCP(t *testing.T, addr string, req []byte) dnsmessage.Message {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("连本地 DNS(TCP) 失败: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	framed := append([]byte{byte(len(req) >> 8), byte(len(req))}, req...)
	if _, err := conn.Write(framed); err != nil {
		t.Fatalf("发送查询失败: %v", err)
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatalf("读长度前缀失败: %v", err)
	}
	body := make([]byte, int(lenBuf[0])<<8|int(lenBuf[1]))
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("读应答失败: %v", err)
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(body); err != nil {
		t.Fatalf("应答解析失败: %v", err)
	}
	return msg
}

func firstA(t *testing.T, msg dnsmessage.Message) string {
	t.Helper()
	for _, rr := range msg.Answers {
		if a, ok := rr.Body.(*dnsmessage.AResource); ok {
			return net.IP(a.A[:]).String()
		}
	}
	t.Fatalf("应答里没有 A 记录: %+v", msg)
	return ""
}

func TestServerForwardAndCache(t *testing.T) {
	up := startFakeUpstream(t, [4]byte{93, 184, 216, 34}, 300)
	srv, addr := startTestServer(t, Settings{
		Cache:     true,
		Upstreams: []Upstream{{Name: "假上游", Address: up.addr, Enabled: true}},
	})

	req := mustPackQuery(t, "example.com.", dnsmessage.TypeA, 0)

	msg := queryUDP(t, addr, req)
	if msg.Header.ID != 0x4242 {
		t.Errorf("事务 ID = %#x, 期望 0x4242", msg.Header.ID)
	}
	if got := firstA(t, msg); got != "93.184.216.34" {
		t.Errorf("解析结果 = %s", got)
	}
	if up.hits() != 1 {
		t.Errorf("上游被问了 %d 次, 期望 1 次", up.hits())
	}

	// 第二次应当直接从缓存出，不再打扰上游
	if got := firstA(t, queryUDP(t, addr, req)); got != "93.184.216.34" {
		t.Errorf("缓存命中的结果 = %s", got)
	}
	if up.hits() != 1 {
		t.Errorf("缓存没生效, 上游被问了 %d 次", up.hits())
	}

	// TCP 侧走的是同一套逻辑
	if got := firstA(t, queryTCP(t, addr, req)); got != "93.184.216.34" {
		t.Errorf("TCP 查询结果 = %s", got)
	}

	stats := srv.stats.snapshot()
	if stats["queries"].(int64) != 3 {
		t.Errorf("统计到 %v 次查询, 期望 3", stats["queries"])
	}
	if stats["cache_hits"].(int64) != 2 {
		t.Errorf("统计到 %v 次缓存命中, 期望 2", stats["cache_hits"])
	}
	if recent := stats["recent"].([]queryLog); len(recent) != 3 || recent[0].Name != "example.com." {
		t.Errorf("最近查询日志不对: %+v", recent)
	}
}

func TestServerDomainRouting(t *testing.T) {
	cn := startFakeUpstream(t, [4]byte{1, 1, 1, 1}, 60)
	global := startFakeUpstream(t, [4]byte{2, 2, 2, 2}, 60)

	_, addr := startTestServer(t, Settings{
		Upstreams: []Upstream{
			{Name: "全球", Address: global.addr, Enabled: true},
			{Name: "国内", Address: cn.addr, Enabled: true, Domains: []string{"example.com"}},
		},
	})

	if got := firstA(t, queryUDP(t, addr, mustPackQuery(t, "www.example.com.", dnsmessage.TypeA, 0))); got != "1.1.1.1" {
		t.Errorf("example.com 应当走国内上游, 得到 %s", got)
	}
	if got := firstA(t, queryUDP(t, addr, mustPackQuery(t, "www.other.com.", dnsmessage.TypeA, 0))); got != "2.2.2.2" {
		t.Errorf("其他域名应当走兜底上游, 得到 %s", got)
	}
}

func TestServerStaticHostsAndFallback(t *testing.T) {
	dead := "127.0.0.1:1" // 必然连不上，用来验证失败路径
	up := startFakeUpstream(t, [4]byte{5, 6, 7, 8}, 60)

	_, addr := startTestServer(t, Settings{
		Hosts: []HostRecord{{Domain: "nas.local", IP: "192.168.9.9"}},
		Upstreams: []Upstream{
			{Name: "坏的", Address: dead, Enabled: true},
			{Name: "好的", Address: up.addr, Enabled: true},
		},
		TimeoutMS: 1000,
	})

	// 静态记录不该惊动上游
	if got := firstA(t, queryUDP(t, addr, mustPackQuery(t, "nas.local.", dnsmessage.TypeA, 0))); got != "192.168.9.9" {
		t.Errorf("静态记录 = %s", got)
	}
	if up.hits() != 0 {
		t.Errorf("静态记录不该转发给上游, 上游被问了 %d 次", up.hits())
	}

	// 顺序策略下第一个上游失败要能自动落到第二个
	if got := firstA(t, queryUDP(t, addr, mustPackQuery(t, "example.org.", dnsmessage.TypeA, 0))); got != "5.6.7.8" {
		t.Errorf("失败回退结果 = %s", got)
	}
}

func TestServerNoUpstreamServfail(t *testing.T) {
	_, addr := startTestServer(t, Settings{})
	msg := queryUDP(t, addr, mustPackQuery(t, "example.com.", dnsmessage.TypeA, 0))
	if msg.Header.RCode != dnsmessage.RCodeServerFailure {
		t.Errorf("没有上游时应当回 SERVFAIL, 得到 %v", msg.Header.RCode)
	}
}

func TestServerRaceStrategy(t *testing.T) {
	dead := "127.0.0.1:1"
	up := startFakeUpstream(t, [4]byte{8, 8, 4, 4}, 60)

	_, addr := startTestServer(t, Settings{
		Strategy:  strategyRace,
		TimeoutMS: 2000,
		Upstreams: []Upstream{
			{Name: "坏的", Address: dead, Enabled: true},
			{Name: "好的", Address: up.addr, Enabled: true},
		},
	})

	if got := firstA(t, queryUDP(t, addr, mustPackQuery(t, "example.net.", dnsmessage.TypeA, 0))); got != "8.8.4.4" {
		t.Errorf("并发策略结果 = %s", got)
	}
}

func TestServerRestartAndTestQuery(t *testing.T) {
	up := startFakeUpstream(t, [4]byte{10, 0, 0, 1}, 60)
	srv, addr := startTestServer(t, Settings{
		Upstreams: []Upstream{{Name: "假上游", Address: up.addr, Enabled: true}},
	})

	// 改配置时服务在跑，应当带着新配置重启并继续可用
	s := srv.Settings()
	s.Strategy = strategyRace
	if err := srv.SetConfig(s); err != nil {
		t.Fatalf("改配置失败: %v", err)
	}
	if !srv.Running() {
		t.Fatal("改完配置服务应当还在跑")
	}
	if got := firstA(t, queryUDP(t, addr, mustPackQuery(t, "restart.example.", dnsmessage.TypeA, 0))); got != "10.0.0.1" {
		t.Errorf("重启后查询结果 = %s", got)
	}

	result, err := srv.TestQuery("test.example", "A", "")
	if err != nil {
		t.Fatalf("测试查询失败: %v", err)
	}
	if result["answer"] != "10.0.0.1" {
		t.Errorf("测试查询结果 = %v", result["answer"])
	}
	if result["upstream"] != "假上游" {
		t.Errorf("测试查询用的上游 = %v", result["upstream"])
	}

	if _, err := srv.TestQuery("test.example", "A", "不存在的上游"); err == nil {
		t.Error("指定不存在的上游应当报错")
	}
	if _, err := srv.TestQuery("", "A", ""); err == nil {
		t.Error("空域名应当报错")
	}
	if _, err := srv.TestQuery("example.com", "WHAT", ""); err == nil {
		t.Error("未知记录类型应当报错")
	}

	srv.Stop()
	if srv.Running() {
		t.Error("停止后 Running 应当是 false")
	}
	// 停掉之后端口要真的放开
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Errorf("端口没有释放: %v", err)
	} else {
		conn.Close()
	}
}

func TestServerBadConfigRollback(t *testing.T) {
	up := startFakeUpstream(t, [4]byte{4, 3, 2, 1}, 60)
	srv, addr := startTestServer(t, Settings{
		Upstreams: []Upstream{{Name: "假上游", Address: up.addr, Enabled: true}},
	})

	// 换成一个必然占不上的端口，服务要回滚到旧配置继续服务
	s := srv.Settings()
	s.Port = "1" // 非 root 起不来
	if err := srv.SetConfig(s); err == nil {
		t.Skip("当前环境能监听 1 端口（多半是 root），跳过回滚检查")
	}
	if !srv.Running() {
		t.Fatal("新配置起不来时应当回滚到旧配置继续服务")
	}
	if got := firstA(t, queryUDP(t, addr, mustPackQuery(t, "rollback.example.", dnsmessage.TypeA, 0))); got != "4.3.2.1" {
		t.Errorf("回滚后查询结果 = %s", got)
	}
	if srv.Settings().Port == "1" {
		t.Error("回滚后不该留下坏配置")
	}
}

func TestApplyDNSFlagsKeepsExistingUpstreams(t *testing.T) {
	saved := Default
	savedPath := configPath
	t.Cleanup(func() { Default, configPath = saved, savedPath })

	configPath = "" // 单测不落盘
	Default = &Server{settings: defaultSettings(), stats: newStats()}

	if err := ApplyFlags("", "5353", "223.5.5.5, https://dns.google/dns-query"); err != nil {
		t.Fatalf("应用命令行参数失败: %v", err)
	}
	s := Default.Settings()
	if s.Port != "5353" {
		t.Errorf("端口 = %q, 期望 5353", s.Port)
	}
	if len(s.Upstreams) != 2 || s.Upstreams[0].Address != "223.5.5.5:53" || s.Upstreams[1].Type != upstreamHTTPS {
		t.Fatalf("上游解析不对: %+v", s.Upstreams)
	}

	// 配置里已经有上游时，命令行的那份不再覆盖
	if err := ApplyFlags("", "", "8.8.8.8"); err != nil {
		t.Fatalf("应用命令行参数失败: %v", err)
	}
	if got := Default.Settings().Upstreams; len(got) != 2 {
		t.Errorf("已有上游被命令行覆盖了: %+v", got)
	}

	if err := ApplyFlags("", "70000", ""); err == nil {
		t.Error("非法端口应当报错")
	}
}

func TestDNSTypeNameAndSummary(t *testing.T) {
	if got := typeName(dnsmessage.TypeAAAA); got != "AAAA" {
		t.Errorf("dnsTypeName = %q", got)
	}
	if got := summarizeAnswers(nil); !strings.Contains(got, "无记录") {
		t.Errorf("空应答摘要 = %q", got)
	}
	answers := []dnsmessage.Resource{
		{Header: dnsmessage.ResourceHeader{Type: dnsmessage.TypeA}, Body: &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}}},
		{Header: dnsmessage.ResourceHeader{Type: dnsmessage.TypeCNAME}, Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("cdn.example.com.")}},
	}
	got := summarizeAnswers(answers)
	if !strings.Contains(got, "1.2.3.4") || !strings.Contains(got, "cdn.example.com.") {
		t.Errorf("摘要 = %q", got)
	}
}

// 进程重启后要按上次的开关状态恢复：上次开着就自动起来，点过停止就保持停止
func TestPersistRunStateAcrossRestart(t *testing.T) {
	savedPath := configPath
	t.Cleanup(func() { configPath = savedPath })
	path := filepath.Join(t.TempDir(), "dns.json")
	configPath = path

	// 起一个用完即弃的服务，模拟用户在后台点了「启动 DNS」
	srv, _ := startTestServer(t, Settings{Upstreams: []Upstream{}})
	port := srv.Settings().Port

	if !readPersistedRunning(t, path) {
		t.Fatal("点了启动之后配置里应当记下 running=true")
	}

	// 模拟进程重启：新实例只读文件，就该知道上次是开着的
	reborn := &Server{settings: defaultSettings(), stats: newStats()}
	if !reborn.Load(path) {
		t.Fatal("读取配置失败")
	}
	if !reborn.WasRunning() {
		t.Error("上次是开着的，WasRunning 应当为 true")
	}
	if reborn.Settings().Port != port {
		t.Errorf("端口没恢复: %q, 期望 %q", reborn.Settings().Port, port)
	}

	// 点停止之后，下次启动就不该再自动起来
	srv.Stop()
	if readPersistedRunning(t, path) {
		t.Fatal("点了停止之后配置里应当记下 running=false")
	}
	reborn2 := &Server{settings: defaultSettings(), stats: newStats()}
	reborn2.Load(path)
	if reborn2.WasRunning() {
		t.Error("上次是停着的，WasRunning 应当为 false")
	}

	// 改配置只动配置，不该把开关状态带偏
	s := reborn2.Settings()
	s.TimeoutMS = 1234
	if err := reborn2.SetConfig(s); err != nil {
		t.Fatalf("改配置失败: %v", err)
	}
	if readPersistedRunning(t, path) {
		t.Error("停止状态下保存配置不该把 running 改成 true")
	}
}

func readPersistedRunning(t *testing.T, path string) bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取配置文件失败: %v", err)
	}
	var state configFile
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("配置文件不是合法 JSON: %v", err)
	}
	return state.Running
}
