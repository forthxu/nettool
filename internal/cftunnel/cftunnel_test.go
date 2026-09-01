package cftunnel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------- ingress 规则 ----------

// TestNormalizeIngressAppendsCatchAll 锁住那条最容易漏的要求：Cloudflare 要求
// ingress 的最后一条不带 hostname，缺了它整份配置会被拒收，而拒收信息很难懂。
func TestNormalizeIngressAppendsCatchAll(t *testing.T) {
	out, err := normalizeIngress([]IngressRule{
		{Hostname: "app.example.com", Service: "http://127.0.0.1:8090"},
	})
	if err != nil {
		t.Fatalf("不该报错: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("应当补出兜底规则，得到 %d 条: %+v", len(out), out)
	}
	if out[1].Hostname != "" || out[1].Service != "http_status:404" {
		t.Errorf("补出来的兜底规则不对: %+v", out[1])
	}
}

func TestNormalizeIngressKeepsExistingCatchAll(t *testing.T) {
	out, err := normalizeIngress([]IngressRule{
		{Hostname: "app.example.com", Service: "http://127.0.0.1:8090"},
		{Service: "http_status:503"},
	})
	if err != nil {
		t.Fatalf("不该报错: %v", err)
	}
	if len(out) != 2 || out[1].Service != "http_status:503" {
		t.Errorf("用户自己写的兜底规则被动过了: %+v", out)
	}
}

// 界面上留白的空行不该变成规则
func TestNormalizeIngressDropsBlankRows(t *testing.T) {
	out, err := normalizeIngress([]IngressRule{
		{},
		{Hostname: " App.Example.com ", Service: " http://127.0.0.1:8090 "},
		{Hostname: "", Path: "", Service: ""},
	})
	if err != nil {
		t.Fatalf("不该报错: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("空行没被丢掉: %+v", out)
	}
	if out[0].Hostname != "app.example.com" || out[0].Service != "http://127.0.0.1:8090" {
		t.Errorf("没有去空格/转小写: %+v", out[0])
	}
}

func TestNormalizeIngressRejects(t *testing.T) {
	cases := []struct {
		name  string
		rules []IngressRule
		want  string
	}{
		{"service 写错", []IngressRule{{Hostname: "a.example.com", Service: "127.0.0.1:8090"}}, "不认识"},
		{"service 少地址", []IngressRule{{Hostname: "a.example.com", Service: "http://"}}, "缺少地址"},
		{"域名非法", []IngressRule{{Hostname: "not a domain", Service: "http://127.0.0.1:1"}}, "不合法"},
		{"兜底规则排在中间", []IngressRule{
			{Service: "http_status:404"},
			{Hostname: "a.example.com", Service: "http://127.0.0.1:1"},
		}, "只有最后一条"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := normalizeIngress(c.rules)
			if err == nil {
				t.Fatalf("应当报错")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("错误信息 %q 里没提到 %q", err, c.want)
			}
		})
	}
}

func TestNormalizeIngressAcceptsSpecialServices(t *testing.T) {
	for _, svc := range []string{"tcp://127.0.0.1:3306", "ssh://127.0.0.1:22", "unix:/var/run/app.sock", "hello_world", "bastion"} {
		if _, err := normalizeIngress([]IngressRule{{Hostname: "a.example.com", Service: svc}}); err != nil {
			t.Errorf("service %q 应当被接受: %v", svc, err)
		}
	}
}

// ---------- 域名归属 ----------

// TestZoneForPrefersLongestSuffix 记录只能下到最具体的那个 zone 上，
// 下到父 zone 会被子 zone 的 NS 委派盖掉、根本不生效。
func TestZoneForPrefersLongestSuffix(t *testing.T) {
	zones := []Zone{{ID: "z1", Name: "example.com"}, {ID: "z2", Name: "lab.example.com"}}

	if z, ok := zoneFor(zones, "app.lab.example.com"); !ok || z.ID != "z2" {
		t.Errorf("应当落到 lab.example.com，得到 %+v (%v)", z, ok)
	}
	if z, ok := zoneFor(zones, "app.example.com"); !ok || z.ID != "z1" {
		t.Errorf("应当落到 example.com，得到 %+v (%v)", z, ok)
	}
	if z, ok := zoneFor(zones, "example.com"); !ok || z.ID != "z1" {
		t.Errorf("裸域名也要能匹配上，得到 %+v (%v)", z, ok)
	}
	// notexample.com 以 example.com 结尾，但它不是子域，不能匹配
	if _, ok := zoneFor(zones, "notexample.com"); ok {
		t.Error("notexample.com 不属于 example.com，不该匹配")
	}
	if _, ok := zoneFor(zones, "app.other.com"); ok {
		t.Error("不该匹配到无关域名")
	}
}

// ---------- 下载地址 ----------

func TestAssetName(t *testing.T) {
	cases := []struct {
		goos, goarch, want string
		targz              bool
	}{
		{"linux", "amd64", "cloudflared-linux-amd64", false},
		{"linux", "arm", "cloudflared-linux-arm", false},
		{"darwin", "arm64", "cloudflared-darwin-arm64.tgz", true}, // macOS 只发 tgz
		{"windows", "amd64", "cloudflared-windows-amd64.exe", false},
	}
	for _, c := range cases {
		name, targz, err := assetName(c.goos, c.goarch)
		if err != nil {
			t.Errorf("%s/%s: %v", c.goos, c.goarch, err)
			continue
		}
		if name != c.want || targz != c.targz {
			t.Errorf("%s/%s: 得到 %q(tgz=%v)，想要 %q(tgz=%v)", c.goos, c.goarch, name, targz, c.want, c.targz)
		}
	}
	if _, _, err := assetName("plan9", "amd64"); err == nil {
		t.Error("没有发布包的平台应当明确报错，而不是拼出一个 404 的地址")
	}
}

// 镜像地址少写结尾斜杠是常见笔误，不能让它把文件名吞掉
func TestDownloadURLNormalizesBase(t *testing.T) {
	got, _, err := downloadURL("https://mirror.example.com/cloudflared", "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://mirror.example.com/cloudflared/cloudflared-linux-amd64"
	if got != want {
		t.Errorf("得到 %q，想要 %q", got, want)
	}

	got, _, err = downloadURL("", "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, defaultDownloadBase) {
		t.Errorf("留空时应当用官方地址，得到 %q", got)
	}
}

// 覆盖安装：Windows 上不能直接盖掉正在跑的 exe，走的是"旧的挪开、新的放上"
// 这条路。两边都要保证换完之后 dest 是新内容，且不留下多余的东西。
func TestReplaceBinaryOverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "cloudflared")
	if err := os.WriteFile(dest, []byte("旧版本"), 0o755); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, "new.tmp")
	if err := os.WriteFile(tmp, []byte("新版本"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := replaceBinary(tmp, dest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "新版本" {
		t.Errorf("dest 里是 %q，想要 %q", got, "新版本")
	}
	if fileExists(dest + ".old") {
		t.Error("没被占用时不该留下 .old")
	}
}

// 目标不存在时（第一次安装）就是一次普通改名
func TestReplaceBinaryCreatesWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "cloudflared")
	tmp := filepath.Join(dir, "new.tmp")
	if err := os.WriteFile(tmp, []byte("新版本"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := replaceBinary(tmp, dest); err != nil {
		t.Fatal(err)
	}
	if !fileExists(dest) {
		t.Error("第一次安装应当直接把文件放到位")
	}
}

// 目标目录都不存在这类真错误要照常报出来，不能被"挪开重试"那条路吞掉
func TestReplaceBinarySurfacesRealErrors(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, "new.tmp")
	if err := os.WriteFile(tmp, []byte("新版本"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := replaceBinary(tmp, filepath.Join(dir, "没有这个目录", "cloudflared")); err == nil {
		t.Error("目标目录不存在时应当报错")
	}
}

// 装完之后要能说出"还有几个连接器在用旧版本"；用户自己指定了程序路径时
// 托管目录根本没人用，不该报这个数
func TestRunningOnManagedIgnoresConfiguredPath(t *testing.T) {
	bin := stubBinary(t, "while true; do sleep 0.1; done\n")

	m := NewManager()
	p := &process{label: "测试"}
	if err := p.Start(bin, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	m.procs["t1"] = p
	waitFor(t, func() bool { return p.Running() }, "假进程没起来")

	if n := m.runningOnManaged(); n != 1 {
		t.Errorf("跑着一个连接器时得到 %d，想要 1", n)
	}
	m.settings.BinaryPath = "/somewhere/cloudflared"
	if n := m.runningOnManaged(); n != 0 {
		t.Errorf("指定了绝对路径时得到 %d，想要 0", n)
	}
}

// ---------- 日志环 ----------

func TestLogRingKeepsLastLines(t *testing.T) {
	var r logRing
	for i := 0; i < logCapacity+50; i++ {
		r.add(fmt.Sprintf("line-%d", i))
	}

	all := r.since(0)
	if len(all) != logCapacity {
		t.Fatalf("环里应当只剩 %d 行，得到 %d", logCapacity, len(all))
	}
	if all[0].Text != fmt.Sprintf("line-%d", 50) {
		t.Errorf("丢的应当是最老的那些，第一行是 %q", all[0].Text)
	}

	// 增量取：只要序号比上次大的
	last := all[len(all)-1].Seq
	if got := r.since(last); len(got) != 0 {
		t.Errorf("没有新行时应当返回空，得到 %d 行", len(got))
	}
	r.add("new")
	got := r.since(last)
	if len(got) != 1 || got[0].Text != "new" {
		t.Errorf("增量不对: %+v", got)
	}
}

func TestQuickURLPattern(t *testing.T) {
	line := "2026-08-31T03:00:00Z INF |  https://calm-river-1234.trycloudflare.com  |"
	if got := quickURLPattern.FindString(line); got != "https://calm-river-1234.trycloudflare.com" {
		t.Errorf("没从横幅里抓出临时域名，得到 %q", got)
	}
	if got := quickURLPattern.FindString("INF Registered tunnel connection"); got != "" {
		t.Errorf("不该乱匹配: %q", got)
	}
}

func TestMaskSecret(t *testing.T) {
	if got := maskSecret("abcdefghijklmn"); got != "abcd…klmn" {
		t.Errorf("脱敏结果不对: %q", got)
	}
	if got := maskSecret("short"); got != "****" {
		t.Errorf("太短的应当整个盖掉，得到 %q", got)
	}
	if got := maskSecret(""); got != "" {
		t.Errorf("空值应当还是空，得到 %q", got)
	}
}

// ---------- 配置持久化 ----------

func TestConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cftunnel.json")

	m := NewManager()
	m.path = path
	m.settings = Settings{APIToken: "tok-123", AccountID: "acct", BinaryPath: ""}
	m.addLocked("uuid-1", "隧道一", "acct", "connector-token")
	m.tunnels["t1"] = func() Tunnel { x := m.tunnels["t1"]; x.Running = true; return x }()
	m.persistLocked()

	// 里面有 API Token 和连接器令牌，权限必须是 0600
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("配置文件权限是 %o，机密文件必须是 600", perm)
	}

	got := NewManager()
	if !got.Load(path) {
		t.Fatal("载入失败")
	}
	if got.settings.APIToken != "tok-123" {
		t.Errorf("API Token 没存回来: %q", got.settings.APIToken)
	}
	if len(got.order) != 1 || got.tunnels["t1"].Token != "connector-token" {
		t.Fatalf("隧道没存回来: %+v", got.tunnels)
	}
	if !got.tunnels["t1"].Running {
		t.Error("上次的开关意愿没跟着存盘，重启后不会自动拉起来")
	}
	if got.procs["t1"] == nil {
		t.Error("载入的隧道没有配套的进程壳，启停会 panic")
	}
}

// 配置损坏时宁可这次不持久化，也不能拿空配置把用户存的东西盖掉
func TestLoadCorruptFileDoesNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cftunnel.json")
	if err := os.WriteFile(path, []byte("{ 这不是 JSON"), 0o600); err != nil {
		t.Fatal(err)
	}

	m := NewManager()
	if m.Load(path) {
		t.Error("损坏的文件不该被当成载入成功")
	}
	if m.ConfigPath() != "" {
		t.Error("载入失败后应当停用持久化，否则下一次保存就把原文件盖了")
	}

	m.persistLocked()
	data, _ := os.ReadFile(path)
	if string(data) != "{ 这不是 JSON" {
		t.Error("原文件被覆盖了")
	}
}

// 半截记录（没有隧道 UUID）留着只会在界面上变成一行点不动的东西
func TestLoadSkipsIncompleteRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cftunnel.json")
	data, _ := json.Marshal(configFile{Version: 1, Tunnels: []Tunnel{
		{ID: "t1", CFID: "uuid-1", Name: "好的"},
		{ID: "t2", Name: "没有 UUID"},
		{CFID: "uuid-3", Name: "没有本地 ID"},
	}})
	os.WriteFile(path, data, 0o600)

	m := NewManager()
	m.Load(path)
	if len(m.order) != 1 || m.order[0] != "t1" {
		t.Errorf("只该留下完整的那条，得到 %v", m.order)
	}
}

// ---------- Cloudflare API 客户端 ----------

// cfServer 起一个假的 Cloudflare，把每次请求记下来
type cfServer struct {
	*httptest.Server
	requests []recorded
}

type recorded struct {
	method, path, body string
}

func newCFServer(t *testing.T, routes map[string]string) *cfServer {
	t.Helper()
	s := &cfServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		if r.ContentLength > 0 {
			r.Body.Read(buf)
		}
		s.requests = append(s.requests, recorded{r.Method, r.URL.Path, string(buf)})

		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`))
			return
		}
		body, ok := routes[r.Method+" "+r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"success":false,"errors":[{"code":7003,"message":"Could not route to endpoint"}]}`))
			return
		}
		w.Write([]byte(body))
	}))

	old := APIBase
	APIBase = s.URL
	t.Cleanup(func() { APIBase = old; s.Close() })
	return s
}

func TestAPIClientSurfacesCloudflareErrors(t *testing.T) {
	newCFServer(t, nil)

	// 用错 Token：Cloudflare 回 HTTP 403 + 错误码，两样都要出现在报错里
	err := newAPIClient("wrong").VerifyToken()
	if err == nil {
		t.Fatal("应当报错")
	}
	if !strings.Contains(err.Error(), "10000") || !strings.Contains(err.Error(), "Authentication error") {
		t.Errorf("错误信息里应当带上 Cloudflare 给的错误码原文，得到 %q", err)
	}
}

// Cloudflare 业务失败时也常常回 HTTP 200，成败只在 success 字段里
func TestAPIClientChecksSuccessNotStatusCode(t *testing.T) {
	newCFServer(t, map[string]string{
		"GET /user/tokens/verify": `{"success":false,"errors":[{"code":1001,"message":"内部错误"}],"result":null}`,
	})
	if err := newAPIClient("test-token").VerifyToken(); err == nil {
		t.Error("HTTP 200 但 success=false，必须当成失败")
	}
}

// 按 README 那两项权限建出来的 Token 列不出账号：/accounts 回 success=true 加一个
// 空数组（列账号要的是 Account Settings:Read，那两项都不含）。真机上撞过一次，
// 当时整个页面停在"还没有选账号"，但那个 Token 其实什么都能干。
func TestVerifyFallsBackToAccountFromZones(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"GET /user/tokens/verify": `{"success":true,"errors":[],"result":{"status":"active"}}`,
		"GET /accounts":           `{"success":true,"errors":[],"result":[]}`,
		"GET /zones": `{"success":true,"errors":[],"result":[
			{"id":"zone-1","name":"example.com","account":{"id":"acct-real","name":"演示账号"}},
			{"id":"zone-2","name":"other.dev","account":{"id":"acct-real","name":"演示账号"}}]}`,
	})
	m.settings.AccountID, m.settings.AccountName = "", ""

	accounts, err := m.VerifyToken("test-token")
	if err != nil {
		t.Fatal(err)
	}
	// 同一个账号下的两个域名只该出一条
	if len(accounts) != 1 || accounts[0].ID != "acct-real" {
		t.Fatalf("没从域名里问出账号: %+v", accounts)
	}
	if got := m.Settings(); got.AccountID != "acct-real" || got.AccountName != "演示账号" {
		t.Errorf("账号没自动选上: %+v", got)
	}
}

// 两条路都空的时候要说清楚补哪项权限，而不是留下一个选不了账号的页面
func TestVerifyWithoutAnyAccountSaysWhichPermission(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"GET /user/tokens/verify": `{"success":true,"errors":[],"result":{"status":"active"}}`,
		"GET /accounts":           `{"success":true,"errors":[],"result":[]}`,
		"GET /zones":              `{"success":true,"errors":[],"result":[]}`,
	})
	_, err := m.VerifyToken("test-token")
	if err == nil || !strings.Contains(err.Error(), "Account Settings") {
		t.Errorf("应当指出补哪项权限，得到 %v", err)
	}
}

func TestAPIClientVerifyRejectsInactiveToken(t *testing.T) {
	newCFServer(t, map[string]string{
		"GET /user/tokens/verify": `{"success":true,"errors":[],"result":{"status":"expired"}}`,
	})
	err := newAPIClient("test-token").VerifyToken()
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("过期的 Token 应当被拦下，得到 %v", err)
	}
}

func TestCreateTunnelSendsRemoteConfigSrc(t *testing.T) {
	s := newCFServer(t, map[string]string{
		"POST /accounts/acct/cfd_tunnel": `{"success":true,"errors":[],"result":{"id":"uuid-1","name":"demo","status":"inactive"}}`,
	})

	got, err := newAPIClient("test-token").CreateTunnel("acct", "demo")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "uuid-1" {
		t.Errorf("没解出隧道 ID: %+v", got)
	}

	body := s.requests[0].body
	// 远程托管是整个设计的前提：ingress 规则存云端，本地不用管 config.yml
	if !strings.Contains(body, `"config_src":"cloudflare"`) {
		t.Errorf("建隧道时没有指定远程托管: %s", body)
	}
	if !strings.Contains(body, `"tunnel_secret"`) {
		t.Errorf("没有带上隧道密钥: %s", body)
	}
}

func TestTunnelIngressHandlesEmptyConfig(t *testing.T) {
	newCFServer(t, map[string]string{
		// 刚建出来的隧道还没有配置，Cloudflare 回的 config 是 null
		"GET /accounts/acct/cfd_tunnel/uuid-1/configurations": `{"success":true,"errors":[],"result":{"tunnel_id":"uuid-1","config":null}}`,
	})
	rules, err := newAPIClient("test-token").TunnelIngress("acct", "uuid-1")
	if err != nil {
		t.Fatalf("空配置不该报错: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("应当是空表，得到 %+v", rules)
	}
}

func TestSetTunnelIngressShape(t *testing.T) {
	s := newCFServer(t, map[string]string{
		"PUT /accounts/acct/cfd_tunnel/uuid-1/configurations": `{"success":true,"errors":[],"result":{}}`,
	})
	err := newAPIClient("test-token").SetTunnelIngress("acct", "uuid-1", []IngressRule{
		{Hostname: "app.example.com", Service: "http://127.0.0.1:8090"},
		{Service: "http_status:404"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := s.requests[0].body
	if !strings.Contains(body, `"config":{"ingress":[`) {
		t.Errorf("请求体形状不对: %s", body)
	}
	// 兜底那条没有 hostname，omitempty 要让它整个不出现，否则 Cloudflare 会拒收
	if strings.Contains(body, `"hostname":""`) {
		t.Errorf("空 hostname 不该出现在请求体里: %s", body)
	}
}

func TestUpsertCNAMEIsIdempotent(t *testing.T) {
	newCFServer(t, map[string]string{
		"GET /zones/z1/dns_records": `{"success":true,"errors":[],"result":[{"id":"r1","type":"CNAME","name":"app.example.com","content":"uuid-1.cfargotunnel.com","proxied":true}]}`,
	})
	msg, err := newAPIClient("test-token").UpsertTunnelCNAME("z1", "app.example.com", "uuid-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "无需改动") {
		t.Errorf("已经指对了就不该再改一次: %q", msg)
	}
}

// 同名再加一条 CNAME 会被 Cloudflare 拒收，所以要改而不是加
func TestUpsertCNAMEUpdatesExisting(t *testing.T) {
	s := newCFServer(t, map[string]string{
		"GET /zones/z1/dns_records":    `{"success":true,"errors":[],"result":[{"id":"r1","type":"CNAME","name":"app.example.com","content":"old.cfargotunnel.com"}]}`,
		"PUT /zones/z1/dns_records/r1": `{"success":true,"errors":[],"result":{}}`,
	})
	msg, err := newAPIClient("test-token").UpsertTunnelCNAME("z1", "app.example.com", "uuid-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "改到本隧道") {
		t.Errorf("提示不对: %q", msg)
	}
	if len(s.requests) != 2 || s.requests[1].method != http.MethodPut {
		t.Fatalf("应当是改而不是加: %+v", s.requests)
	}
	// cfargotunnel.com 只有经过 Cloudflare 边缘才解析得到，必须开代理
	if !strings.Contains(s.requests[1].body, `"proxied":true`) {
		t.Errorf("没有开橙云，外面会查到 NXDOMAIN: %s", s.requests[1].body)
	}
}

// 已经有一条 A 记录时不能悄悄改掉，那是用户的别的服务
func TestUpsertCNAMERefusesToClobberOtherTypes(t *testing.T) {
	newCFServer(t, map[string]string{
		"GET /zones/z1/dns_records": `{"success":true,"errors":[],"result":[{"id":"r1","type":"A","name":"app.example.com","content":"1.2.3.4"}]}`,
	})
	_, err := newAPIClient("test-token").UpsertTunnelCNAME("z1", "app.example.com", "uuid-1")
	if err == nil || !strings.Contains(err.Error(), "A 记录") {
		t.Errorf("应当拒绝并说清楚原因，得到 %v", err)
	}
}

func TestDeleteTunnelCNAMERemovesOwnRecord(t *testing.T) {
	s := newCFServer(t, map[string]string{
		"GET /zones/z1/dns_records":       `{"success":true,"errors":[],"result":[{"id":"r1","type":"CNAME","name":"app.example.com","content":"uuid-1.cfargotunnel.com"}]}`,
		"DELETE /zones/z1/dns_records/r1": `{"success":true,"errors":[],"result":{}}`,
	})
	msg, err := newAPIClient("test-token").DeleteTunnelCNAME("z1", "app.example.com", "uuid-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "已删除") {
		t.Errorf("提示不对: %q", msg)
	}
	if len(s.requests) != 2 || s.requests[1].method != http.MethodDelete {
		t.Fatalf("应当查一次再删一次: %+v", s.requests)
	}
}

// 指向别的隧道、或者根本不是 CNAME 的记录，是用户的别的东西，一条都不能删——
// DNS 记录删了没有回收站
func TestDeleteTunnelCNAMERefusesForeignRecords(t *testing.T) {
	for name, result := range map[string]string{
		"指向另一条隧道": `[{"id":"r1","type":"CNAME","name":"app.example.com","content":"uuid-2.cfargotunnel.com"}]`,
		"是 A 记录":  `[{"id":"r1","type":"A","name":"app.example.com","content":"1.2.3.4"}]`,
		"混着一条别的":  `[{"id":"r1","type":"CNAME","name":"app.example.com","content":"uuid-1.cfargotunnel.com"},{"id":"r2","type":"TXT","name":"app.example.com","content":"v=spf1"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			s := newCFServer(t, map[string]string{
				"GET /zones/z1/dns_records": `{"success":true,"errors":[],"result":` + result + `}`,
			})
			_, err := newAPIClient("test-token").DeleteTunnelCNAME("z1", "app.example.com", "uuid-1")
			if err == nil {
				t.Fatal("应当拒绝")
			}
			for _, r := range s.requests {
				if r.method == http.MethodDelete {
					t.Fatalf("不该删任何东西: %+v", s.requests)
				}
			}
		})
	}
}

// 记录本来就不在（比如已经在后台删过了）不算错，直接说一声就行
func TestDeleteTunnelCNAMEIsIdempotent(t *testing.T) {
	newCFServer(t, map[string]string{
		"GET /zones/z1/dns_records": `{"success":true,"errors":[],"result":[]}`,
	})
	msg, err := newAPIClient("test-token").DeleteTunnelCNAME("z1", "app.example.com", "uuid-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "本来就没有") {
		t.Errorf("提示不对: %q", msg)
	}
}

func TestActiveConnectionsIgnoresReconnecting(t *testing.T) {
	var r RemoteTunnel
	json.Unmarshal([]byte(`{"connections":[{"colo_name":"HKG"},{"colo_name":"HKG","is_pending_reconnect":true}]}`), &r)
	if got := r.ActiveConnections(); got != 1 {
		t.Errorf("正在重连的那条不算数，得到 %d", got)
	}
}

// ---------- Manager ----------

func newTestManager(t *testing.T, routes map[string]string) *Manager {
	t.Helper()
	newCFServer(t, routes)
	m := NewManager()
	m.path = filepath.Join(t.TempDir(), "cftunnel.json")
	m.settings = Settings{APIToken: "test-token", AccountID: "acct"}
	// 起过连接器的用例不用各自收尾：假 cloudflared 是个死循环，漏一个就会
	// 一直挂在机器上，测试跑几轮之后满屏都是。
	t.Cleanup(m.StopAll)
	return m
}

func TestManagerCreateStoresTokenButNeverReturnsIt(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"POST /accounts/acct/cfd_tunnel":             `{"success":true,"errors":[],"result":{"id":"uuid-1","name":"demo"}}`,
		"GET /accounts/acct/cfd_tunnel/uuid-1/token": `{"success":true,"errors":[],"result":"connector-token-abc"}`,
	})

	if _, err := m.Create("demo"); err != nil {
		t.Fatal(err)
	}
	if got := m.tunnels["t1"].Token; got != "connector-token-abc" {
		t.Errorf("令牌没存下来: %q", got)
	}

	// 拿到连接器令牌就等于拿到这条隧道，接口一律不返回它
	views := m.Tunnels()
	if len(views) != 1 || !views[0].HasToken {
		t.Fatalf("视图不对: %+v", views)
	}
	blob, _ := json.Marshal(views)
	if strings.Contains(string(blob), "connector-token-abc") {
		t.Errorf("连接器令牌漏进了接口输出: %s", blob)
	}
}

// 隧道已经在云端建出来了，令牌拿不到也要把它记下来，
// 否则云端会多出一条没人认领的隧道
func TestManagerCreateKeepsRecordWhenTokenFetchFails(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"POST /accounts/acct/cfd_tunnel": `{"success":true,"errors":[],"result":{"id":"uuid-1","name":"demo"}}`,
	})
	tn, err := m.Create("demo")
	if err != nil {
		t.Fatalf("取令牌失败不该让整个创建失败: %v", err)
	}
	if tn.Token != "" || tn.CFID != "uuid-1" {
		t.Errorf("记录不对: %+v", tn)
	}
	if m.Tunnels()[0].HasToken {
		t.Error("界面上要看得出这条还没有令牌")
	}
}

func TestManagerAdoptRefusesDuplicate(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"GET /accounts/acct/cfd_tunnel/uuid-1/token": `{"success":true,"errors":[],"result":"tok"}`,
	})
	if _, err := m.Adopt("uuid-1", "已有隧道"); err != nil {
		t.Fatal(err)
	}
	_, err := m.Adopt("uuid-1", "又来一次")
	if err == nil || !strings.Contains(err.Error(), "已经在列表里") {
		t.Errorf("同一条隧道不该被接管两次，得到 %v", err)
	}
}

// 云端那边名字改了，本地跟着走，免得两边对不上
func TestSyncPicksUpRenames(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"GET /accounts/acct/cfd_tunnel": `{"success":true,"errors":[],"result":[{"id":"uuid-1","name":"新名字","status":"healthy"}]}`,
	})
	m.addLocked("uuid-1", "老名字", "acct", "tok")

	if _, err := m.Sync(); err != nil {
		t.Fatal(err)
	}
	if got := m.tunnels["t1"].Name; got != "新名字" {
		t.Errorf("没跟上云端改名，仍是 %q", got)
	}
	if v := m.Tunnels()[0]; v.Remote == nil || v.Remote.Status != "healthy" {
		t.Errorf("云端状态没带到视图里: %+v", v)
	}
}

// 在 Cloudflare 后台被删掉的隧道，本地要显示出来而不是装作还在
func TestSyncMarksMissingTunnels(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"GET /accounts/acct/cfd_tunnel": `{"success":true,"errors":[],"result":[]}`,
	})
	m.addLocked("uuid-gone", "没了的隧道", "acct", "tok")

	if _, err := m.Sync(); err != nil {
		t.Fatal(err)
	}
	if v := m.Tunnels()[0]; !v.RemoteMissing {
		t.Errorf("应当标成云端已删除: %+v", v)
	}
}

// 同步之前不知道云端什么情况，不能把"没同步过"显示成"云端已删除"
func TestTunnelsBeforeSyncAreNotMarkedMissing(t *testing.T) {
	m := NewManager()
	m.addLocked("uuid-1", "隧道", "acct", "tok")
	if v := m.Tunnels()[0]; v.RemoteMissing {
		t.Error("还没同步过就说云端删了，这是在吓唬用户")
	}
}

func TestSetSettingsKeepsTokenWhenBlank(t *testing.T) {
	m := NewManager()
	m.path = filepath.Join(t.TempDir(), "cftunnel.json")
	m.settings = Settings{APIToken: "keep-me", AccountID: "acct"}

	// 界面上显示的是脱敏值，用户没动它的时候不能把存着的 Token 冲掉
	if err := m.SetSettings(Settings{AccountID: "acct2"}, false); err != nil {
		t.Fatal(err)
	}
	if m.settings.APIToken != "keep-me" {
		t.Errorf("Token 被空值冲掉了: %q", m.settings.APIToken)
	}
	if m.settings.AccountID != "acct2" {
		t.Errorf("账号没改过来: %q", m.settings.AccountID)
	}

	if err := m.SetSettings(Settings{}, true); err != nil {
		t.Fatal(err)
	}
	if m.settings.APIToken != "" {
		t.Error("显式清除没生效")
	}
}

// 概览接口只给脱敏值，明文得单独问 RevealToken 要——小眼睛就是这么来的
func TestRevealTokenIsTheOnlyWayOut(t *testing.T) {
	m := NewManager()
	m.path = filepath.Join(t.TempDir(), "cftunnel.json")

	if _, err := m.RevealToken(); err == nil {
		t.Error("没存过 Token 时应当报错，而不是返回空串")
	}

	m.settings = Settings{APIToken: "tok-abcdefghijklmn"}
	view := m.SettingsView()
	if strings.Contains(view.TokenMasked, "efghij") {
		t.Errorf("概览里漏了明文: %q", view.TokenMasked)
	}
	got, err := m.RevealToken()
	if err != nil {
		t.Fatal(err)
	}
	if got != "tok-abcdefghijklmn" {
		t.Errorf("明文不对: %q", got)
	}
}

func TestSetSettingsRejectsBadInput(t *testing.T) {
	m := NewManager()
	if err := m.SetSettings(Settings{BinaryPath: "/no/such/cloudflared"}, false); err == nil {
		t.Error("指了个不存在的路径应当当场报错，而不是等点启动才发现")
	}
	if err := m.SetSettings(Settings{DownloadURL: "mirror.example.com"}, false); err == nil {
		t.Error("下载地址没有协议头应当被拦下")
	}
}

func TestOperationsWithoutTokenSayWhy(t *testing.T) {
	m := NewManager()
	m.addLocked("uuid-1", "隧道", "acct", "tok")
	for name, err := range map[string]error{
		"Create":  func() error { _, e := m.Create("x"); return e }(),
		"Sync":    func() error { _, e := m.Sync(); return e }(),
		"DNS":     func() error { _, e := m.AttachDNS("t1", "a.example.com"); return e }(),
		"删 DNS":   func() error { _, e := m.DetachDNS("t1", "a.example.com"); return e }(),
		"Ingress": func() error { _, e := m.Ingress("t1"); return e }(),
	} {
		if err == nil || !strings.Contains(err.Error(), "API Token") {
			t.Errorf("%s 在没配 Token 时应当直说，得到 %v", name, err)
		}
	}
}

func TestStartWithoutTokenIsRefused(t *testing.T) {
	m := NewManager()
	m.addLocked("uuid-1", "无令牌隧道", "acct", "")
	err := m.Start("t1")
	if err == nil || !strings.Contains(err.Error(), "令牌") {
		t.Errorf("没有连接器令牌时应当拒绝启动并说明原因，得到 %v", err)
	}
	if m.tunnels["t1"].Running {
		t.Error("启动失败不该把开关意愿改成开")
	}
}

func TestQuickRejectsBadTarget(t *testing.T) {
	m := NewManager()
	for _, target := range []string{"", "127.0.0.1:8090", "http_status:404"} {
		if err := m.StartQuick(target); err == nil {
			t.Errorf("target %q 应当被拒绝", target)
		}
	}
}

// ---------- 进程托管 ----------

// stubBinary 造一个假的 cloudflared：打几行输出，然后按参数决定是立刻退出还是挂着
func stubBinary(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("这个用例靠 /bin/sh 造假进程，Windows 上跳过")
	}
	path := filepath.Join(t.TempDir(), "fake-cloudflared")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestProcessCapturesOutputAndExit(t *testing.T) {
	bin := stubBinary(t, "echo 第一行\necho 第二行 >&2\nexit 3\n")

	p := &process{label: "测试"}
	if err := p.Start(bin, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return !p.Running() }, "进程没退出")

	var texts []string
	for _, l := range p.logs.since(0) {
		texts = append(texts, l.Text)
	}
	joined := strings.Join(texts, "\n")
	// stdout 与 stderr 都要收进来：cloudflared 的正经日志走的是 stderr
	for _, want := range []string{"第一行", "第二行"} {
		if !strings.Contains(joined, want) {
			t.Errorf("日志里少了 %q:\n%s", want, joined)
		}
	}
	if st := p.Status(); st.Running || !strings.Contains(st.LastExit, "退出") {
		t.Errorf("退出信息不对: %+v", st)
	}
}

func TestProcessStopTerminates(t *testing.T) {
	bin := stubBinary(t, "trap 'exit 0' TERM\nwhile true; do sleep 0.1; done\n")

	p := &process{label: "测试"}
	if err := p.Start(bin, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, p.Running, "进程没起来")

	p.Stop()
	if p.Running() {
		t.Error("Stop 返回时进程应当已经停了")
	}
	if st := p.Status(); st.StartedAt != nil {
		t.Error("停着的时候不该有启动时刻")
	}
}

// 短命进程多半是令牌或参数不对，重启多少次都一样，不该自动重试
func TestProcessDoesNotRestartShortLivedFailures(t *testing.T) {
	bin := stubBinary(t, "echo 起不来\nexit 1\n")

	restarted := false
	p := &process{label: "测试"}
	p.restartFn = func() (string, []string, []string, bool) {
		restarted = true
		return bin, nil, nil, true
	}
	if err := p.Start(bin, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return !p.Running() }, "进程没退出")

	time.Sleep(200 * time.Millisecond)
	if restarted {
		t.Error("活不过一分钟的进程不该被自动拉起来，那只会刷屏")
	}
}

// 跑了一阵子才挂的是被外力杀掉，重启是对的
func TestProcessRestartsAfterHealthyRun(t *testing.T) {
	shortenRestartTiming(t, 100*time.Millisecond, 50*time.Millisecond)
	bin := stubBinary(t, "sleep 0.3\nexit 1\n")

	var mu sync.Mutex
	restarts := 0
	p := &process{label: "测试"}
	p.restartFn = func() (string, []string, []string, bool) {
		mu.Lock()
		restarts++
		mu.Unlock()
		return stubBinary(t, "trap 'exit 0' TERM\nwhile true; do sleep 0.1; done\n"), nil, nil, true
	}
	if err := p.Start(bin, nil, nil); err != nil {
		t.Fatal(err)
	}

	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return restarts > 0
	}, "活过 minHealthyRun 的进程意外退出后没有被拉起来")
	p.Stop()
}

// 点了停止之后，正在等待中的那次自动重启不能再把它拉起来
func TestStopCancelsPendingRestart(t *testing.T) {
	shortenRestartTiming(t, 100*time.Millisecond, time.Second)
	bin := stubBinary(t, "sleep 0.3\nexit 1\n")

	var mu sync.Mutex
	restarts := 0
	p := &process{label: "测试"}
	p.restartFn = func() (string, []string, []string, bool) {
		mu.Lock()
		restarts++
		mu.Unlock()
		return bin, nil, nil, true
	}
	if err := p.Start(bin, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return !p.Running() }, "进程没退出")

	p.Stop() // 此刻它正卡在重启前的等待里
	time.Sleep(1500 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if restarts != 0 {
		t.Errorf("停掉之后又被自动拉起来了 %d 次", restarts)
	}
	if p.Running() {
		t.Error("进程又活过来了")
	}
}

func shortenRestartTiming(t *testing.T, healthy, delay time.Duration) {
	t.Helper()
	oldHealthy, oldDelay := minHealthyRun, restartDelay
	minHealthyRun, restartDelay = healthy, delay
	t.Cleanup(func() { minHealthyRun, restartDelay = oldHealthy, oldDelay })
}

func TestProcessStartReplacesRunningOne(t *testing.T) {
	bin := stubBinary(t, "trap 'exit 0' TERM\nwhile true; do sleep 0.1; done\n")

	p := &process{label: "测试"}
	if err := p.Start(bin, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, p.Running, "第一个进程没起来")
	first := p.Status().StartedAt

	// 用户点两下不能留下两个连接器
	if err := p.Start(bin, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, p.Running, "第二个进程没起来")
	if second := p.Status().StartedAt; first != nil && second != nil && !second.After(*first) {
		t.Error("第二次启动应当换成新进程")
	}
	p.Stop()
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(msg)
}
