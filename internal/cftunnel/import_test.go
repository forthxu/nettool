package cftunnel

// 导入本机已有隧道的用例：从凭证算令牌、读 cloudflared 的 config.yml、
// 把规则迁到云端，以及扫描配对。

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sampleConfig 是一份典型的手写 cloudflared 配置。
// 拿它当样本是因为手写的配置长这样：有注释、有注释掉的规则、有 originRequest。
const sampleConfig = `tunnel: demo-host
credentials-file: /tmp/creds.json

# cloudflared --config /path/to/demo-host.config tunnel run demo-host

ingress:
  # 强制 HTTPS
  - hostname: app.example.com
    service: http://127.0.0.1:8080
    originRequest:
      noTLSVerify: true
  # 暴露 SSH，通道需要绑定域名
  #- hostname: ssh.example.com
  #  service: ssh://127.0.0.1:22
  # 默认 fallback
  - service: http_status:404
`

// 故意用一个不可能存在的 UUID：Discover 会扫真实的 ~/.cloudflared，
// 跟本机真有的隧道撞上的话用例会时灵时不灵
const fixtureTunnelID = "00000000-1111-2222-3333-444444444444"

// ---------- 凭证 → 令牌 ----------

// TestTokenFromCredentials 锁住整个「导入不需要 API Token」的前提：
// 凭证文件和连接器令牌装的是同一份秘密，令牌算得出来。
func TestTokenFromCredentials(t *testing.T) {
	cred := credentials{
		AccountTag:   "0123456789abcdef0123456789abcdef",
		TunnelID:     "22222222-3333-4444-5555-666666666666",
		TunnelSecret: "c2VjcmV0LWJ5dGVzLWhlcmU=",
	}

	token, err := tokenFromCredentials(cred)
	if err != nil {
		t.Fatal(err)
	}

	// 令牌的内容必须是 cloudflared 认的那三个短键，不是凭证文件的大写键名
	raw, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("令牌不是合法 base64: %v", err)
	}
	var keys map[string]string
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	if keys["a"] != cred.AccountTag || keys["t"] != cred.TunnelID || keys["s"] != cred.TunnelSecret {
		t.Errorf("令牌里的字段不对: %+v", keys)
	}
	if len(keys) != 3 {
		t.Errorf("令牌里只该有 a/t/s 三个键: %+v", keys)
	}
}

// FedRAMP 环境的凭证转不成令牌，要当场说清楚而不是算出一个跑不起来的
func TestCredentialsWithEndpointRejected(t *testing.T) {
	_, err := tokenFromCredentials(credentials{
		AccountTag: "a", TunnelID: "t", TunnelSecret: "s", Endpoint: "fed",
	})
	if err == nil || !strings.Contains(err.Error(), "Endpoint") {
		t.Errorf("应当拒绝并说明原因，得到 %v", err)
	}
}

// 同目录下有别的 json、或凭证缺字段时，要说得出是哪个文件不对
func TestReadCredentialsFileRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"not-json.json": "这不是 json",
		"partial.json":  `{"AccountTag":"acct"}`,
		"empty.json":    `{}`,
	}
	for name, body := range cases {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readCredentialsFile(path); err == nil {
			t.Errorf("%s 应当被拒绝", name)
		} else if !strings.Contains(err.Error(), name) {
			t.Errorf("%s 的错误里应当带上文件名: %v", name, err)
		}
	}
}

// ---------- 读 cloudflared 的 config.yml ----------

func TestParseRealWorldConfig(t *testing.T) {
	cfg, err := parseCFDConfig([]byte(sampleConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tunnel != "demo-host" || cfg.CredentialsFile != "/tmp/creds.json" {
		t.Errorf("头两项没读对: %+v", cfg)
	}
	// 被注释掉的那条 ssh 规则不算数
	if len(cfg.Ingress) != 2 {
		t.Fatalf("应当是 2 条规则（注释掉的不算），得到 %d: %+v", len(cfg.Ingress), cfg.Ingress)
	}
	first := cfg.Ingress[0]
	if first.Hostname != "app.example.com" || first.Service != "http://127.0.0.1:8080" {
		t.Errorf("第一条不对: %+v", first)
	}
	if v, ok := first.OriginRequest["noTLSVerify"].(bool); !ok || !v {
		t.Errorf("noTLSVerify 没读出来: %+v", first.OriginRequest)
	}
	if cfg.Ingress[1].Service != "http_status:404" {
		t.Errorf("兜底规则不对: %+v", cfg.Ingress[1])
	}
}

// 配置里有本工具不认识的顶层项（loglevel、protocol……）是常态，不能因此读不出规则
func TestParseConfigIgnoresUnknownKeys(t *testing.T) {
	src := "tunnel: demo\nloglevel: debug\nprotocol: quic\nmetrics: 127.0.0.1:9090\n" +
		"ingress:\n  - hostname: a.example.com\n    service: http://127.0.0.1:1\n  - service: http_status:404\n"
	cfg, err := parseCFDConfig([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tunnel != "demo" || len(cfg.Ingress) != 2 {
		t.Errorf("没读对: %+v", cfg)
	}
}

// ---------- originRequest ----------

func TestValidateOriginRequest(t *testing.T) {
	ok := []map[string]interface{}{
		{"noTLSVerify": true},
		{"httpHostHeader": "internal.local"},
		{"connectTimeout": "30s"},
		{"proxyType": "socks"}, // 不认识的键原样透传，交给 Cloudflare 校验
	}
	for _, m := range ok {
		if err := validateOriginRequest(m); err != nil {
			t.Errorf("%v 应当通过: %v", m, err)
		}
	}

	bad := []map[string]interface{}{
		{"noTLSVerify": "true"}, // 字符串不是 bool
		{"httpHostHeader": 123},
		{"connectTimeout": "半分钟"},
	}
	for _, m := range bad {
		if err := validateOriginRequest(m); err == nil {
			t.Errorf("%v 应当被拒绝", m)
		}
	}
}

// 空 map 传到云端会变成一个什么都没配的 originRequest，看着像配了其实没配
func TestNormalizeIngressDropsEmptyOriginRequest(t *testing.T) {
	out, err := normalizeIngress([]IngressRule{
		{Hostname: "a.example.com", Service: "http://127.0.0.1:1", OriginRequest: map[string]interface{}{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out[0].OriginRequest != nil {
		t.Errorf("空的 originRequest 应当清成 nil: %+v", out[0])
	}
}

// ---------- 导入 ----------

// importFixture 造一对能用的凭证 + config，返回两个路径
func importFixture(t *testing.T, tunnelName string) (credPath, configPath string) {
	t.Helper()
	dir := t.TempDir()
	credPath = filepath.Join(dir, fixtureTunnelID+".json")
	configPath = filepath.Join(dir, tunnelName+".config")

	cred, err := json.Marshal(credentials{
		AccountTag: "acct-tag", TunnelID: fixtureTunnelID, TunnelSecret: "c2VjcmV0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credPath, cred, 0o600); err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(sampleConfig, "tunnel: demo-host", "tunnel: "+tunnelName, 1)
	body = strings.Replace(body, "/tmp/creds.json", credPath, 1)
	if err := os.WriteFile(configPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return credPath, configPath
}

// TestImportWithoutConfigNeedsNoAPIToken 是这一套的重点：本机已经在跑的隧道，
// 不联网、不配 Token 就能接管——令牌是从凭证文件算出来的。
func TestImportWithoutConfigNeedsNoAPIToken(t *testing.T) {
	credPath, _ := importFixture(t, "demo-host")

	m := NewManager()
	m.path = filepath.Join(t.TempDir(), "cftunnel.json")
	// 故意不设 settings.APIToken，也没起假服务器：这条路径不该联网

	tn, msg, err := m.Import(credPath, "", "")
	if err != nil {
		t.Fatalf("只接管隧道不该需要 Token: %v", err)
	}
	if tn.CFID != fixtureTunnelID {
		t.Errorf("隧道 ID 不对: %q", tn.CFID)
	}
	if tn.Token == "" {
		t.Error("令牌应当从凭证里算出来")
	}
	if tn.AccountID != "acct-tag" {
		t.Errorf("账号应当取自凭证: %q", tn.AccountID)
	}
	if !strings.Contains(msg, "规则还是空的") {
		t.Errorf("应当说清楚规则没搬: %q", msg)
	}
	// 没别的线索时只能拿 UUID 当名字，同步一次云端就更正了
	if tn.Name != fixtureTunnelID {
		t.Errorf("名字应当退回凭证文件名，得到 %q", tn.Name)
	}
}

// 扫描时从 config 认出来的名字要能带过来，不然「只接管」出来的隧道叫一串 UUID
func TestImportUsesPreferredName(t *testing.T) {
	credPath, _ := importFixture(t, "demo-host")
	m := NewManager()
	m.path = filepath.Join(t.TempDir(), "cftunnel.json")

	tn, _, err := m.Import(credPath, "", "demo-host")
	if err != nil {
		t.Fatal(err)
	}
	if tn.Name != "demo-host" {
		t.Errorf("名字没带过来: %q", tn.Name)
	}
}

// 有规则的 config：规则整份推到云端，而那个 config 文件一个字节都不能动——
// 它还被用户的开机脚本引用着，里面的注释也只有这一份
func TestImportMigratesRulesAndLeavesFileUntouched(t *testing.T) {
	credPath, configPath := importFixture(t, "demo-host")
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	stBefore, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}

	s := newCFServer(t, map[string]string{
		"PUT /accounts/acct/cfd_tunnel/" + fixtureTunnelID + "/configurations": `{"success":true,"errors":[],"result":{}}`,
	})
	m := NewManager()
	m.path = filepath.Join(t.TempDir(), "cftunnel.json")
	m.settings = Settings{APIToken: "test-token", AccountID: "acct"}

	tn, msg, err := m.Import(credPath, configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if tn.Name != "demo-host" {
		t.Errorf("名字应当取自 config 的 tunnel 那一行，得到 %q", tn.Name)
	}
	if !strings.Contains(msg, "2 条规则") {
		t.Errorf("应当说清楚搬了几条: %q", msg)
	}

	if len(s.requests) == 0 {
		t.Fatal("规则没推到云端")
	}
	body := s.requests[0].body
	for _, want := range []string{"app.example.com", "noTLSVerify", "http_status:404"} {
		if !strings.Contains(body, want) {
			t.Errorf("推上去的规则里少了 %q: %s", want, body)
		}
	}

	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("用户的 config 文件被改动了")
	}
	if fileExists(configPath + ".bak") {
		t.Error("不该在用户目录里留下 .bak——本工具根本没写那个文件")
	}
	if st, _ := os.Stat(configPath); st.ModTime() != stBefore.ModTime() {
		t.Error("config 文件的修改时间变了，说明被写过")
	}
}

// 有规则要搬却没配 Token：不能默默导进来，那样每个域名都是 404
func TestImportWithRulesNeedsToken(t *testing.T) {
	credPath, configPath := importFixture(t, "demo-host")
	m := NewManager()
	m.path = filepath.Join(t.TempDir(), "cftunnel.json")

	_, _, err := m.Import(credPath, configPath, "")
	if err == nil || !strings.Contains(err.Error(), "API Token") {
		t.Fatalf("应当提示要先配 Token，得到 %v", err)
	}
	if !strings.Contains(err.Error(), "config 路径留空") {
		t.Errorf("要给出下一步怎么办: %v", err)
	}
	if len(m.Tunnels()) != 0 {
		t.Error("失败了不该在台账里留下半条隧道")
	}
}

// 云端拒收规则时同样不能记台账：用户改完再点一次就好，列表里多一条点不动的更烦
func TestImportRollsBackWhenPushFails(t *testing.T) {
	credPath, configPath := importFixture(t, "demo-host")
	newCFServer(t, map[string]string{}) // 什么路由都没有 → 404
	m := NewManager()
	m.path = filepath.Join(t.TempDir(), "cftunnel.json")
	m.settings = Settings{APIToken: "test-token", AccountID: "acct"}

	if _, _, err := m.Import(credPath, configPath, ""); err == nil {
		t.Fatal("推规则失败了却说导入成功")
	}
	if len(m.Tunnels()) != 0 {
		t.Error("推失败了不该在台账里留下半条隧道")
	}
}

func TestImportRefusesDuplicate(t *testing.T) {
	credPath, _ := importFixture(t, "demo-host")
	m := NewManager()
	m.path = filepath.Join(t.TempDir(), "cftunnel.json")

	if _, _, err := m.Import(credPath, "", ""); err != nil {
		t.Fatal(err)
	}
	_, _, err := m.Import(credPath, "", "")
	if err == nil || !strings.Contains(err.Error(), "已经在列表里") {
		t.Errorf("同一条隧道不该导两次，得到 %v", err)
	}
}

// config 里的 tunnel 写着别的 UUID 时，搬过去的就是别人的规则——
// 静默搬错比报错难查得多
func TestImportRejectsMismatchedTunnelID(t *testing.T) {
	credPath, configPath := importFixture(t, "demo-host")
	body, _ := os.ReadFile(configPath)
	os.WriteFile(configPath,
		[]byte(strings.Replace(string(body), "tunnel: demo-host",
			"tunnel: 11111111-2222-3333-4444-555555555555", 1)), 0o644)

	m := NewManager()
	m.path = filepath.Join(t.TempDir(), "cftunnel.json")
	_, _, err := m.Import(credPath, configPath, "")
	if err == nil || !strings.Contains(err.Error(), "对不上") {
		t.Errorf("应当拒绝并说明对不上，得到 %v", err)
	}
}

func TestImportRequiresAbsolutePaths(t *testing.T) {
	m := NewManager()
	if _, _, err := m.Import("cred.json", "", ""); err == nil {
		t.Error("相对路径应当被拒绝：服务进程的工作目录跟着启动方式走")
	}
	if _, _, err := m.Import("", "", ""); err == nil {
		t.Error("凭证文件是必填的")
	}
}

// ---------- 启动参数 ----------

// 只有云端托管一种跑法：令牌走环境变量，命令行上不该出现任何秘密或 --config
func TestRunSpecUsesTokenEnvOnly(t *testing.T) {
	credPath, _ := importFixture(t, "demo-host")
	m := NewManager()
	m.path = filepath.Join(t.TempDir(), "cftunnel.json")
	m.settings.BinaryPath = stubBinary(t, "exit 0\n")

	tn, _, err := m.Import(credPath, "", "")
	if err != nil {
		t.Fatal(err)
	}

	_, args, env, err := m.runSpec(tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--config") {
		t.Errorf("规则在云端，不该带 --config: %q", joined)
	}
	if strings.Contains(joined, tn.Token) {
		t.Error("令牌不能出现在命令行上（ps 是人人可见的）")
	}

	found := false
	for _, e := range env {
		if e == "TUNNEL_TOKEN="+tn.Token {
			found = true
		}
	}
	if !found {
		t.Error("令牌应当走 TUNNEL_TOKEN 环境变量")
	}
}

// ---------- 从本地托管转过来的那一下 ----------

// versionThenHang 是给「经过 Manager 启动」的用例用的假 cloudflared：
// Manager 会先拿 --version 探一次它能不能用，一直挂着的脚本会把那一步卡死。
const versionThenHang = "[ \"$1\" = --version ] && { echo fake; exit 0; }\n" +
	"trap 'exit 0' TERM\nwhile true; do sleep 0.1; done\n"

// 连接器只在启动时决定要不要订阅云端配置：在隧道还归本地托管时起来的进程，
// 之后隧道转成云端托管也收不到下发，手里一条规则都没有、对所有请求回 503。
// 所以推规则把 source 从 local 翻成 cloudflare 时，要顺手重启它。
// 真机上踩过：云端 healthy、连接数 4，只有 cloudflared 日志说了实话。
func TestSetIngressRestartsConnectorAfterFlipFromLocal(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"GET /accounts/acct/cfd_tunnel/uuid-1/configurations": `{"success":true,"errors":[],"result":{"source":"local","config":{"ingress":[{"service":"http_status:404"}]}}}`,
		"PUT /accounts/acct/cfd_tunnel/uuid-1/configurations": `{"success":true,"errors":[],"result":{}}`,
	})
	m.settings.BinaryPath = stubBinary(t, versionThenHang)

	m.mu.Lock()
	tn := m.addLocked("uuid-1", "demo", "acct", "token-abc")
	m.mu.Unlock()
	if err := m.Start(tn.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return m.procRunning(tn.ID) }, "连接器没起来")

	_, note, err := m.SetIngress(tn.ID, []IngressRule{
		{Hostname: "a.example.com", Service: "http://127.0.0.1:1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if note == "" || !strings.Contains(note, "503") {
		t.Errorf("重启了就要说出来，且要点明不重启会 503: %q", note)
	}
	waitFor(t, func() bool { return m.procRunning(tn.ID) }, "重启之后连接器没回来")

	// 日志里应当有两次启动
	lines, err := m.Logs(tn.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	starts := 0
	for _, l := range lines {
		if strings.Contains(l.Text, "[nettool] 启动") {
			starts++
		}
	}
	if starts != 2 {
		t.Errorf("应当重启过一次（共 2 次启动），得到 %d 次:\n%+v", starts, lines)
	}
}

// 本来就是云端托管的，保存规则不该打断连接——那是每天都要点的操作
func TestSetIngressDoesNotRestartWhenAlreadyCloud(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"GET /accounts/acct/cfd_tunnel/uuid-1/configurations": `{"success":true,"errors":[],"result":{"source":"cloudflare","config":{"ingress":[{"service":"http_status:404"}]}}}`,
		"PUT /accounts/acct/cfd_tunnel/uuid-1/configurations": `{"success":true,"errors":[],"result":{}}`,
	})
	m.settings.BinaryPath = stubBinary(t, versionThenHang)

	m.mu.Lock()
	tn := m.addLocked("uuid-1", "demo", "acct", "token-abc")
	m.mu.Unlock()
	if err := m.Start(tn.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return m.procRunning(tn.ID) }, "连接器没起来")
	before := m.Tunnels()[0].Status.StartedAt

	_, note, err := m.SetIngress(tn.ID, []IngressRule{
		{Hostname: "a.example.com", Service: "http://127.0.0.1:1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if note != "" {
		t.Errorf("不该有额外的话: %q", note)
	}
	if after := m.Tunnels()[0].Status.StartedAt; before == nil || after == nil || !before.Equal(*after) {
		t.Error("连接器被重启了，云端托管改规则本来就不用重启")
	}
}

// 连上了却一条规则都没有，是个从外面完全看不出来的状态（云端 healthy、
// 连接数也对，只是每个请求都 503）。把它捞到状态里，界面上才有得说。
func TestStatusFlagsMissingIngress(t *testing.T) {
	p := &process{label: "测试"}
	bin := stubBinary(t, "echo '"+noIngressMarker+", cloudflared will return 503'\ntrap 'exit 0' TERM\nwhile true; do sleep 0.1; done\n")
	if err := p.Start(bin, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	waitFor(t, func() bool { return p.Status().NoIngress }, "没认出「手里没有规则」这个状态")
}

// ---------- 台账 ----------

// 上一版台账里有 mode/config_path 这些已经取消的字段，载入时应当忽略掉、
// 而不是整个文件当损坏处理
func TestLoadIgnoresRetiredFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cftunnel.json")
	os.WriteFile(path, []byte(`{"version":1,"tunnels":[
		{"id":"t1","cf_id":"uuid-1","name":"老隧道","token":"tok",
		 "mode":"local","config_path":"/etc/x.yml","credentials_path":"/etc/x.json"}]}`), 0o600)

	m := NewManager()
	if !m.Load(path) {
		t.Fatal("载入失败")
	}
	if got := m.tunnels["t1"]; got.Name != "老隧道" || got.Token != "tok" {
		t.Errorf("旧记录没读对: %+v", got)
	}
}

// ---------- 扫描 ----------

func TestDiscoverPairsConfigWithCredentials(t *testing.T) {
	credPath, configPath := importFixture(t, "demo-host")

	// 凭证目录不在标准位置，Discover 扫不到它，所以这里直接验配对逻辑
	configs := scanConfigs([]string{filepath.Dir(configPath)})
	if len(configs) == 0 {
		t.Fatal("额外目录里的 config 没扫到")
	}
	sc, ok := matchConfig(configs, credPath, fixtureTunnelID)
	if !ok {
		t.Fatal("没能按 credentials-file 把 config 配上")
	}
	if len(sc.cfg.Ingress) != 2 {
		t.Errorf("配上的 config 不对: %+v", sc.cfg)
	}
	if got := joinHostnames(sc.cfg.Ingress); got != "app.example.com" {
		t.Errorf("域名摘要不对: %q", got)
	}
}

// 没写 credentials-file 的 config 靠隧道 ID 配对
func TestMatchConfigFallsBackToTunnelID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.yml")
	os.WriteFile(path, []byte("tunnel: uuid-9\ningress:\n  - service: http_status:404\n"), 0o644)

	configs := scanConfigs([]string{dir})
	if _, ok := matchConfig(configs, "/nowhere/cred.json", "uuid-9"); !ok {
		t.Error("应当退回按隧道 ID 配对")
	}
	if _, ok := matchConfig(configs, "/nowhere/cred.json", "uuid-other"); ok {
		t.Error("不该配到别的隧道上")
	}
}

// 同一条隧道的凭证被拷到两个目录时只列一行，且留住配着 config 的那份——
// 点错没 config 的那行，规则就迁不过来了
func TestDedupeCandidatesKeepsTheOneWithConfig(t *testing.T) {
	got := dedupeCandidates([]Candidate{
		{TunnelID: "u1", Name: "u1", CredentialsPath: "/a/u1.json"},
		{TunnelID: "u1", Name: "好名字", CredentialsPath: "/b/u1.json", ConfigPath: "/b/x.yml", IngressCount: 2},
		{TunnelID: "u2", CredentialsPath: "/a/u2.json"},
	})
	if len(got) != 2 {
		t.Fatalf("应当收成 2 条: %+v", got)
	}
	if got[0].ConfigPath != "/b/x.yml" || got[0].IngressCount != 2 {
		t.Errorf("留下的不是配着 config 的那份: %+v", got[0])
	}
	if got[1].TunnelID != "u2" {
		t.Errorf("顺序不该乱: %+v", got)
	}
}

// 只有 loglevel 之类的全局 config 不是隧道配置，别混进候选里
func TestScanConfigsSkipsNonTunnelFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config.yml"), []byte("loglevel: debug\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("tunnel: x\n"), 0o644)

	if got := scanConfigs([]string{dir}); len(got) != 0 {
		t.Errorf("不该扫进来: %+v", got)
	}
}

// Discover 认得出哪些已经接管过：界面上那些按钮要变灰
func TestDiscoverMarksAdopted(t *testing.T) {
	credPath, _ := importFixture(t, "demo-host")
	m := NewManager()
	m.path = filepath.Join(t.TempDir(), "cftunnel.json")
	if _, _, err := m.Import(credPath, "", ""); err != nil {
		t.Fatal(err)
	}

	m.mu.Lock()
	adopted := m.tunnels["t1"].CFID
	m.mu.Unlock()
	if adopted != fixtureTunnelID {
		t.Fatalf("台账里的 UUID 不对: %q", adopted)
	}

	// 手填的目录里凭证和 config 都要扫得到
	found := false
	for _, c := range m.Discover([]string{filepath.Dir(credPath)}) {
		if c.TunnelID != fixtureTunnelID {
			continue
		}
		found = true
		if !c.Adopted {
			t.Error("已经接管过的候选没标上")
		}
		if c.ConfigPath == "" || c.Hostnames != "app.example.com" {
			t.Errorf("同一个目录里的 config 没配上: %+v", c)
		}
	}
	if !found {
		t.Error("手填目录里的凭证没扫到")
	}
}
