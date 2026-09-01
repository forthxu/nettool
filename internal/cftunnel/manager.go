package cftunnel

// 多隧道管理：本地台账的增删改、连接器进程的启停，以及和云端的对账。
//
// 加锁的纪律：Manager.mu 只护住台账与设置这些内存数据，绝不在持有它的时候去
// 碰进程——Stop 最多要等 8 秒（等 cloudflared 优雅退出），端着锁等下去会让整个
// 界面卡住。所以所有方法都是「拿锁读出要用的东西 → 放锁 → 动进程 → 再拿锁记结果」。

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Manager 持有全部隧道
type Manager struct {
	mu       sync.Mutex
	path     string // 配置文件，空表示本次运行不持久化
	settings Settings
	order    []string // 稳定的展示顺序
	tunnels  map[string]Tunnel
	procs    map[string]*process
	// remote 是最近一次同步拿到的云端状态，键是隧道 UUID。
	// 它只是给界面看的快照，不参与任何判断。
	remote    map[string]RemoteTunnel
	remoteAt  time.Time
	zones     []Zone
	install   installer
	quickProc *process
	quickURL  string
	quickAddr string
}

func NewManager() *Manager {
	return &Manager{
		tunnels: make(map[string]Tunnel),
		procs:   make(map[string]*process),
		remote:  make(map[string]RemoteTunnel),
	}
}

// Default 是本进程的隧道集合
var Default = NewManager()

// Settings 返回账号级配置（含明文 Token，只给内部用）
func (m *Manager) Settings() Settings {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.settings
}

// SettingsView 是给接口用的脱敏版本
type SettingsView struct {
	TokenSet    bool   `json:"token_set"`
	TokenMasked string `json:"token_masked,omitempty"`
	AccountID   string `json:"account_id,omitempty"`
	AccountName string `json:"account_name,omitempty"`
	BinaryPath  string `json:"binary_path,omitempty"`
	DownloadURL string `json:"download_url,omitempty"`
}

func (m *Manager) SettingsView() SettingsView {
	s := m.Settings()
	return SettingsView{
		TokenSet:    s.APIToken != "",
		TokenMasked: maskSecret(s.APIToken),
		AccountID:   s.AccountID,
		AccountName: s.AccountName,
		BinaryPath:  s.BinaryPath,
		DownloadURL: s.DownloadURL,
	}
}

// RevealToken 返回明文 API Token，给界面上那个「小眼睛」用：换机器、去 Cloudflare
// 后台对一下是哪一个的时候要把它抄出来。
//
// 这是唯一一个把明文机密送出本进程的地方（连接器令牌仍然一律不返回），所以每次
// 都记一行日志——没配 -user/-pass 时这个界面本来就没有门，日志至少让这件事留下痕迹。
func (m *Manager) RevealToken() (string, error) {
	s := m.Settings()
	if s.APIToken == "" {
		return "", fmt.Errorf("还没保存过 API Token")
	}
	log.Printf("[CFTunnel] 界面读走了一次明文 API Token（%s）", maskSecret(s.APIToken))
	return s.APIToken, nil
}

// SetSettings 保存账号级配置。APIToken 为空表示「不改」——界面上显示的是脱敏值，
// 用户没动它的时候不该把存着的 Token 冲掉。要清空得显式传 clearToken。
func (m *Manager) SetSettings(in Settings, clearToken bool) error {
	in = in.normalized()
	if in.BinaryPath != "" {
		if !fileExists(in.BinaryPath) {
			return fmt.Errorf("cloudflared 路径 %s 不存在", in.BinaryPath)
		}
	}
	if in.DownloadURL != "" && !strings.HasPrefix(in.DownloadURL, "http://") && !strings.HasPrefix(in.DownloadURL, "https://") {
		return fmt.Errorf("下载地址要以 http:// 或 https:// 开头")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case clearToken:
		m.settings.APIToken = ""
	case in.APIToken != "":
		m.settings.APIToken = in.APIToken
	}
	if in.APIToken != "" || clearToken {
		m.remote = make(map[string]RemoteTunnel) // 换账号了，旧快照别再显示
		m.zones = nil
	}
	m.settings.AccountID = in.AccountID
	m.settings.AccountName = in.AccountName
	m.settings.BinaryPath = in.BinaryPath
	m.settings.DownloadURL = in.DownloadURL
	m.persistLocked()
	return nil
}

// api 造一个客户端；没配 Token 时直接说清楚
func (m *Manager) api() (*apiClient, string, error) {
	m.mu.Lock()
	token, account := m.settings.APIToken, m.settings.AccountID
	m.mu.Unlock()
	if token == "" {
		return nil, "", fmt.Errorf("还没有填 Cloudflare API Token")
	}
	return newAPIClient(token), account, nil
}

func (m *Manager) apiWithAccount() (*apiClient, string, error) {
	c, account, err := m.api()
	if err != nil {
		return nil, "", err
	}
	if account == "" {
		return nil, "", fmt.Errorf("还没有选账号，请先点「验证并读取账号」")
	}
	return c, account, nil
}

// VerifyToken 验证 Token 并列出它能访问的账号。
// 只有一个账号时顺手选上——绝大多数人就是这种情况。
func (m *Manager) VerifyToken(token string) ([]Account, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		token = m.Settings().APIToken
	}
	if token == "" {
		return nil, fmt.Errorf("还没有填 Cloudflare API Token")
	}

	c := newAPIClient(token)
	if err := c.VerifyToken(); err != nil {
		return nil, err
	}
	accounts, err := c.AccountsOrFromZones()
	if err != nil {
		return nil, fmt.Errorf("Token 有效，但读不到账号列表: %v", err)
	}
	if len(accounts) == 0 {
		return nil, fmt.Errorf("Token 有效，但读不出任何账号：/accounts 是空的（缺 Account Settings:Read），" +
			"名下也没有可见的域名。补一项 Account · Account Settings : Read 再试")
	}

	m.mu.Lock()
	m.settings.APIToken = token
	if len(accounts) == 1 || m.settings.AccountID == "" {
		if len(accounts) > 0 {
			m.settings.AccountID, m.settings.AccountName = accounts[0].ID, accounts[0].Name
		}
	}
	m.persistLocked()
	m.mu.Unlock()
	return accounts, nil
}

// TunnelView 是一条隧道对外的样子：不带令牌，带上本地进程实况与云端快照
type TunnelView struct {
	ID          string        `json:"id"`
	CFID        string        `json:"cf_id"`
	Name        string        `json:"name"`
	AccountID   string        `json:"account_id,omitempty"`
	HasToken    bool          `json:"has_token"`
	WantRunning bool          `json:"want_running"`
	CreatedAt   time.Time     `json:"created_at"`
	Status      Status        `json:"status"`
	Remote      *RemoteTunnel `json:"remote,omitempty"`
	// RemoteMissing 表示上次同步时云端已经没有这条隧道了（在 Cloudflare 后台
	// 被删掉的情况），本地记录还留着但启动它没有意义。
	RemoteMissing bool `json:"remote_missing,omitempty"`
}

// Tunnels 返回全部隧道，按创建顺序
func (m *Manager) Tunnels() []TunnelView {
	m.mu.Lock()
	ids := append([]string(nil), m.order...)
	views := make([]TunnelView, 0, len(ids))
	synced := !m.remoteAt.IsZero()
	for _, id := range ids {
		t, ok := m.tunnels[id]
		if !ok {
			continue
		}
		v := TunnelView{
			ID: t.ID, CFID: t.CFID, Name: t.Name, AccountID: t.AccountID,
			HasToken: t.Token != "", WantRunning: t.Running, CreatedAt: t.CreatedAt,
		}
		if r, ok := m.remote[t.CFID]; ok {
			rc := r
			v.Remote = &rc
		} else if synced {
			v.RemoteMissing = true
		}
		views = append(views, v)
	}
	procs := make([]*process, len(views))
	for i, v := range views {
		procs[i] = m.procs[v.ID]
	}
	m.mu.Unlock()

	// 进程状态在锁外取：Status 自己有锁，别把两把锁叠起来
	for i, p := range procs {
		if p != nil {
			views[i].Status = p.Status()
		}
	}
	return views
}

func (m *Manager) get(id string) (Tunnel, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tunnels[id]
	return t, ok
}

// nextIDLocked 生成不与现有隧道冲突的本地编号。需持有 m.mu。
func (m *Manager) nextIDLocked() string {
	maxN := 0
	for id := range m.tunnels {
		if n, err := strconv.Atoi(strings.TrimPrefix(id, "t")); err == nil && n > maxN {
			maxN = n
		}
	}
	return "t" + strconv.Itoa(maxN+1)
}

// addLocked 把一条隧道记进台账并落盘。需持有 m.mu。
func (m *Manager) addLocked(cfID, name, account, token string) Tunnel {
	t := Tunnel{CFID: cfID, Name: name, AccountID: account, Token: token}
	t.ID = m.nextIDLocked()
	t.CreatedAt = time.Now()
	t.Running = false
	m.tunnels[t.ID] = t
	m.order = append(m.order, t.ID)
	m.procs[t.ID] = &process{label: "隧道「" + t.Name + "」"}
	m.persistLocked()
	return t
}

// duplicateLocked 找出已经接管过同一条云端隧道的记录。需持有 m.mu。
func (m *Manager) duplicateLocked(cfID string) (Tunnel, bool) {
	for _, t := range m.tunnels {
		if t.CFID == cfID {
			return t, true
		}
	}
	return Tunnel{}, false
}

// Create 在云端建一条隧道并接管它
func (m *Manager) Create(name string) (Tunnel, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Tunnel{}, fmt.Errorf("隧道名不能为空")
	}

	c, account, err := m.apiWithAccount()
	if err != nil {
		return Tunnel{}, err
	}
	remote, err := c.CreateTunnel(account, name)
	if err != nil {
		return Tunnel{}, err
	}
	token, err := c.TunnelToken(account, remote.ID)
	if err != nil {
		// 隧道已经建出来了，令牌拿不到只是跑不起来；记进台账让用户看得见，
		// 免得云端多出一条没人认领的隧道
		log.Printf("[CFTunnel] 隧道「%s」已创建，但取连接器令牌失败: %v", name, err)
	}

	m.mu.Lock()
	t := m.addLocked(remote.ID, name, account, token)
	m.remote[remote.ID] = remote
	m.mu.Unlock()

	log.Printf("[CFTunnel] 已创建隧道「%s」(%s)", name, remote.ID)
	return t, nil
}

// Adopt 接管一条云端已经有的隧道：拉它的连接器令牌记到本地
func (m *Manager) Adopt(cfID, name string) (Tunnel, error) {
	cfID = strings.TrimSpace(cfID)
	if cfID == "" {
		return Tunnel{}, fmt.Errorf("缺少隧道 ID")
	}

	m.mu.Lock()
	dup, exists := m.duplicateLocked(cfID)
	m.mu.Unlock()
	if exists {
		return Tunnel{}, fmt.Errorf("隧道「%s」已经在列表里了", dup.Name)
	}

	c, account, err := m.apiWithAccount()
	if err != nil {
		return Tunnel{}, err
	}
	token, err := c.TunnelToken(account, cfID)
	if err != nil {
		return Tunnel{}, fmt.Errorf("取连接器令牌失败: %v", err)
	}
	if strings.TrimSpace(name) == "" {
		name = cfID
	}

	m.mu.Lock()
	t := m.addLocked(cfID, strings.TrimSpace(name), account, token)
	m.mu.Unlock()

	log.Printf("[CFTunnel] 已接管隧道「%s」(%s)", t.Name, cfID)
	return t, nil
}

// Delete 删掉一条隧道：先停连接器，再删本地记录；deleteRemote 为真时连云端一起删。
//
// 云端的删除要求隧道上没有活着的连接，所以顺序不能反——先删云端会得到
// "tunnel has active connections" 而不是把它删掉。
func (m *Manager) Delete(id string, deleteRemote bool) error {
	t, ok := m.get(id)
	if !ok {
		return fmt.Errorf("隧道 %s 不存在", id)
	}
	m.stopProc(id)

	if deleteRemote {
		c, account, err := m.apiWithAccount()
		if err != nil {
			return fmt.Errorf("云端隧道没有删除（%v），本地记录也保留着", err)
		}
		if err := c.DeleteTunnel(account, t.CFID); err != nil {
			return fmt.Errorf("删除云端隧道失败: %v，本地记录保留着", err)
		}
	}

	m.mu.Lock()
	delete(m.tunnels, id)
	delete(m.procs, id)
	delete(m.remote, t.CFID)
	for i, x := range m.order {
		if x == id {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	m.persistLocked()
	m.mu.Unlock()

	log.Printf("[CFTunnel] 已删除隧道「%s」（云端: %v）", t.Name, deleteRemote)
	return nil
}

// runSpec 算出启动一条隧道要用的程序、参数和环境变量：
//
//	cloudflared --no-autoupdate tunnel run     + TUNNEL_TOKEN 环境变量
//
// 令牌走环境变量而不是命令行：命令行参数在同一台机器上是人人可见的
// （ps、/proc/*/cmdline），而连接器令牌等价于这条隧道的密码。
//
// 不带 --config：规则的真源在云端，连接器连上之后自己就把配置拉下来了。
func (m *Manager) runSpec(id string) (bin string, args, env []string, err error) {
	t, ok := m.get(id)
	if !ok {
		return "", nil, nil, fmt.Errorf("隧道 %s 不存在", id)
	}
	bin, err = m.binaryPath()
	if err != nil {
		return "", nil, nil, err
	}

	if t.Token == "" {
		return "", nil, nil, fmt.Errorf("隧道「%s」还没有连接器令牌，点「重新拉取令牌」试试", t.Name)
	}
	return bin, []string{"--no-autoupdate", "tunnel", "run"}, append(os.Environ(), "TUNNEL_TOKEN="+t.Token), nil
}

// Start 拉起一条隧道的连接器
func (m *Manager) Start(id string) error {
	bin, args, env, err := m.runSpec(id)
	if err != nil {
		return err
	}

	m.mu.Lock()
	p := m.procs[id]
	m.mu.Unlock()
	if p == nil {
		return fmt.Errorf("隧道 %s 不存在", id)
	}

	// 意外退出后重新算一遍参数：令牌可能已经换过，二进制也可能刚装好
	p.mu.Lock()
	p.restartFn = func() (string, []string, []string, bool) {
		b, a, e, err := m.runSpec(id)
		if err != nil {
			return "", nil, nil, false
		}
		return b, a, e, true
	}
	p.restarts = 0
	p.mu.Unlock()

	if err := p.Start(bin, args, env); err != nil {
		return err
	}
	m.setWantRunning(id, true)
	return nil
}

// Stop 停掉一条隧道的连接器
func (m *Manager) Stop(id string) error {
	if _, ok := m.get(id); !ok {
		return fmt.Errorf("隧道 %s 不存在", id)
	}
	m.stopProc(id)
	m.setWantRunning(id, false)
	return nil
}

func (m *Manager) stopProc(id string) {
	m.mu.Lock()
	p := m.procs[id]
	m.mu.Unlock()
	if p != nil {
		p.Stop() // 会等最多 stopGrace，所以一定要在锁外
	}
}

func (m *Manager) setWantRunning(id string, want bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tunnels[id]
	if !ok || t.Running == want {
		return
	}
	t.Running = want
	m.tunnels[id] = t
	m.persistLocked()
}

// Logs 返回某条隧道的连接器输出，after 之后的部分
func (m *Manager) Logs(id string, after int64) ([]LogLine, error) {
	m.mu.Lock()
	p := m.procs[id]
	m.mu.Unlock()
	if p == nil {
		return nil, fmt.Errorf("隧道 %s 不存在", id)
	}
	return p.logs.since(after), nil
}

// RefreshToken 重新从云端拉连接器令牌（在 Cloudflare 后台轮换过令牌时用）
func (m *Manager) RefreshToken(id string) error {
	t, ok := m.get(id)
	if !ok {
		return fmt.Errorf("隧道 %s 不存在", id)
	}
	c, account, err := m.apiWithAccount()
	if err != nil {
		return err
	}
	token, err := c.TunnelToken(account, t.CFID)
	if err != nil {
		return err
	}

	m.mu.Lock()
	t = m.tunnels[id]
	t.Token, t.AccountID = token, account
	m.tunnels[id] = t
	m.persistLocked()
	m.mu.Unlock()
	return nil
}

// Sync 拉一遍云端隧道列表，更新快照并返回它。
// 本地没接管的那些也在里面，界面上给个「接管」按钮。
func (m *Manager) Sync() ([]RemoteTunnel, error) {
	c, account, err := m.apiWithAccount()
	if err != nil {
		return nil, err
	}
	list, err := c.Tunnels(account)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.remote = make(map[string]RemoteTunnel, len(list))
	for _, r := range list {
		if r.DeletedAt != nil {
			continue
		}
		m.remote[r.ID] = r
	}
	m.remoteAt = time.Now()
	// 云端改过名字的，本地跟着走一遍，免得两边对不上
	changed := false
	for id, t := range m.tunnels {
		if r, ok := m.remote[t.CFID]; ok && r.Name != "" && r.Name != t.Name {
			t.Name = r.Name
			m.tunnels[id] = t
			changed = true
		}
	}
	if changed {
		m.persistLocked()
	}
	m.mu.Unlock()
	return list, nil
}

// SyncedAt 是最近一次同步的时刻
func (m *Manager) SyncedAt() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.remoteAt
}

// Ingress 读某条隧道的 ingress 规则。
//
// 每次都现从云端拉：规则在 Cloudflare 后台也能改，本地缓存一份只会显示成
// 「保存了却没生效」的样子。
func (m *Manager) Ingress(id string) ([]IngressRule, error) {
	t, ok := m.get(id)
	if !ok {
		return nil, fmt.Errorf("隧道 %s 不存在", id)
	}
	c, account, err := m.apiWithAccount()
	if err != nil {
		return nil, err
	}
	return c.TunnelIngress(account, t.CFID)
}

// SetIngress 覆盖 ingress 规则：整份推到云端，连接器几秒内自己就拉到新配置，
// 不用重启。返回的第二个值是要额外告诉用户的话，没有就是空串。
//
// 有一种情况要重启：这次推送把隧道从 local 转成了 cloudflare 托管。**连接器只在
// 启动时决定要不要订阅云端配置**——在隧道还是 local 的时候起来的进程，之后就算
// 隧道转成了 cloudflare，它也再收不到下发，手里一条规则都没有，对所有请求回 503。
// 踩过一次：界面、云端、连接数全是正常的，只有 cloudflared 日志里那句
// "No ingress rules were defined" 说了实话。
func (m *Manager) SetIngress(id string, rules []IngressRule) ([]IngressRule, string, error) {
	t, ok := m.get(id)
	if !ok {
		return nil, "", fmt.Errorf("隧道 %s 不存在", id)
	}
	cleaned, err := normalizeIngress(rules)
	if err != nil {
		return nil, "", err
	}

	c, account, err := m.apiWithAccount()
	if err != nil {
		return nil, "", err
	}
	// 推之前先问一句它现在归谁管，推完就问不出来了
	wasLocal := false
	if cfg, err := c.TunnelConfig(account, t.CFID); err == nil && cfg.Source == "local" {
		wasLocal = true
	}

	if err := c.SetTunnelIngress(account, t.CFID, cleaned); err != nil {
		return nil, "", err
	}
	log.Printf("[CFTunnel] 隧道「%s」的 ingress 规则已更新为 %d 条", t.Name, len(cleaned))

	if !wasLocal || !m.procRunning(id) {
		return cleaned, "", nil
	}
	if err := m.Start(id); err != nil {
		return cleaned, "", fmt.Errorf("规则已保存，但连接器要重启一次才收得到（这条隧道刚从本地托管转过来），"+
			"重启失败: %v，请手动启动", err)
	}
	log.Printf("[CFTunnel] 隧道「%s」刚从本地托管转成云端，已重启连接器让它订阅云端配置", t.Name)
	return cleaned, "这条隧道刚从本地托管转成云端托管，连接器已经重启一次——" +
		"在本地托管时起来的进程收不到云端下发的配置，会对所有请求回 503。", nil
}

func (m *Manager) procRunning(id string) bool {
	m.mu.Lock()
	p := m.procs[id]
	m.mu.Unlock()
	return p != nil && p.Running()
}

// Zones 返回账号下的域名列表，下 DNS 记录时要用。结果缓存起来，界面每开一次
// 编辑框就查一遍太浪费；force 为真时强制重拉。
func (m *Manager) Zones(force bool) ([]Zone, error) {
	m.mu.Lock()
	cached := m.zones
	m.mu.Unlock()
	if len(cached) > 0 && !force {
		return cached, nil
	}

	c, _, err := m.api()
	if err != nil {
		return nil, err
	}
	zones, err := c.Zones()
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.zones = zones
	m.mu.Unlock()
	return zones, nil
}

// dnsTarget 是改一条 DNS 记录要先凑齐的东西：规范化后的域名、它落在哪个 zone、
// 哪条隧道，以及一个能用的 API 客户端。Attach / Detach 两条路径完全一样。
type dnsTarget struct {
	client   *apiClient
	tunnel   Tunnel
	zoneID   string
	hostname string
}

func (m *Manager) dnsTargetFor(id, hostname string) (dnsTarget, error) {
	hostname = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(hostname, ".")))
	if hostname == "" {
		return dnsTarget{}, fmt.Errorf("域名不能为空")
	}
	t, ok := m.get(id)
	if !ok {
		return dnsTarget{}, fmt.Errorf("隧道 %s 不存在", id)
	}

	zones, err := m.Zones(false)
	if err != nil {
		return dnsTarget{}, err
	}
	zone, ok := zoneFor(zones, hostname)
	if !ok {
		return dnsTarget{}, fmt.Errorf("%s 不属于这个账号下的任何域名（%d 个可用），DNS 记录只能下到 Cloudflare 托管的域名上",
			hostname, len(zones))
	}

	c, _, err := m.api()
	if err != nil {
		return dnsTarget{}, err
	}
	return dnsTarget{client: c, tunnel: t, zoneID: zone.ID, hostname: hostname}, nil
}

// AttachDNS 把 hostname 的 CNAME 指到这条隧道上，返回一句人话说明做了什么
func (m *Manager) AttachDNS(id, hostname string) (string, error) {
	d, err := m.dnsTargetFor(id, hostname)
	if err != nil {
		return "", err
	}
	msg, err := d.client.UpsertTunnelCNAME(d.zoneID, d.hostname, d.tunnel.CFID)
	if err != nil {
		return "", err
	}
	log.Printf("[CFTunnel] %s → 隧道「%s」: %s", d.hostname, d.tunnel.Name, msg)
	return msg, nil
}

// DetachDNS 删掉 hostname 那条指向本隧道的 CNAME，是 AttachDNS 的逆操作。
//
// 删规则本身**不会**动 DNS：ingress 规则存在隧道的配置里，CNAME 存在 zone 里，
// 两边互不知情。规则删了而 CNAME 还在，请求照样进隧道，只是没规则匹配，落到兜底的
// 404；隧道整条删掉的话那条 CNAME 就成了悬空记录，Cloudflare 报 1016。所以这个
// 收尾动作要单独做一次。
//
// 只删确认指向本隧道的那条，别的一律不碰——见 DeleteTunnelCNAME。
func (m *Manager) DetachDNS(id, hostname string) (string, error) {
	d, err := m.dnsTargetFor(id, hostname)
	if err != nil {
		return "", err
	}
	msg, err := d.client.DeleteTunnelCNAME(d.zoneID, d.hostname, d.tunnel.CFID)
	if err != nil {
		return "", err
	}
	log.Printf("[CFTunnel] %s ✗ 隧道「%s」: %s", d.hostname, d.tunnel.Name, msg)
	return msg, nil
}

// Import 接管一条本机已经在用的隧道（`cloudflared tunnel create` + 手写 config
// 那一套），并把它的规则搬到云端。返回一句人话说明搬了什么。
//
// 隧道本身的接管不联网也不要 API Token：连接器令牌是从凭证文件里算出来的
// （见 credentials.go）。要 Token 的只有搬规则那一步——规则的真源从此在云端。
//
// configPath 留空表示只接管隧道、不搬规则（规则之后在界面上或 Cloudflare 后台
// 重新填）。preferredName 也可以留空，那就用凭证文件名（即隧道 UUID）——
// 之后点一次「同步云端」名字会跟着云端更正过来。
//
// 用户原来那个 config 文件本工具一个字都不改，但**他原来那条命令必须停掉**：
// config_src=cloudflare 并不覆盖本地文件，带 --config 启动的 cloudflared 用的
// 仍然是文件里的规则（实测过）。两个连接器挂同一条隧道、规则还不一样时，请求
// 走哪个是边缘定的，表现成"改了规则没生效"，而云端和界面看起来全是对的。
func (m *Manager) Import(credentialsPath, configPath, preferredName string) (Tunnel, string, error) {
	credentialsPath = strings.TrimSpace(credentialsPath)
	configPath = strings.TrimSpace(configPath)
	if err := validateImportPaths(credentialsPath, configPath); err != nil {
		return Tunnel{}, "", err
	}

	cred, err := readCredentialsFile(credentialsPath)
	if err != nil {
		return Tunnel{}, "", err
	}
	token, err := tokenFromCredentials(cred)
	if err != nil {
		return Tunnel{}, "", err
	}

	name := strings.TrimSpace(preferredName)
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(credentialsPath), filepath.Ext(credentialsPath))
	}
	var rules []IngressRule
	if configPath != "" {
		cfg, err := readCFDConfig(configPath)
		if err != nil {
			return Tunnel{}, "", err
		}
		// config 里的 tunnel 指的是别的隧道时，搬过去的就是别人的规则，
		// 静默搬错比报错难查得多
		if cfg.Tunnel != "" && cfg.Tunnel != cred.TunnelID && !looksLikeTunnelName(cfg.Tunnel) {
			return Tunnel{}, "", fmt.Errorf("config 里写的隧道是 %s，和凭证文件里的 %s 对不上",
				cfg.Tunnel, cred.TunnelID)
		}
		// 写的是名字（`tunnel: demo-host`）而不是 UUID 时，那就是隧道名
		if looksLikeTunnelName(cfg.Tunnel) {
			name = cfg.Tunnel
		}
		if rules, err = normalizeIngress(cfg.Ingress); err != nil {
			return Tunnel{}, "", fmt.Errorf("%s 里的规则有问题: %v", configPath, err)
		}
	}

	// 有规则要搬就得先有 Token，不然会落得「隧道导进来了、规则一条没有」——
	// 那样每个域名都是 404，比不让导更难查
	var (
		c       *apiClient
		account string
	)
	if hasRules(rules) {
		if c, account, err = m.apiWithAccount(); err != nil {
			return Tunnel{}, "", fmt.Errorf("%s 里有 %d 条规则要迁到云端，这一步需要 API Token: %v"+
				"；只想先把隧道接管过来的话，把 config 路径留空",
				configPath, len(rules), err)
		}
	}

	m.mu.Lock()
	if dup, exists := m.duplicateLocked(cred.TunnelID); exists {
		m.mu.Unlock()
		return Tunnel{}, "", fmt.Errorf("隧道「%s」已经在列表里了", dup.Name)
	}
	m.mu.Unlock()

	// 规则先推、台账后记：推失败就当没导过，用户改完再点一次即可
	msg := "已接管隧道「" + name + "」。规则还是空的，在下面加或者到 Cloudflare 后台加。"
	if c != nil {
		if err := c.SetTunnelIngress(account, cred.TunnelID, rules); err != nil {
			return Tunnel{}, "", fmt.Errorf("把 %s 里的规则迁到云端失败: %v（隧道没有导入）", configPath, err)
		}
		msg = fmt.Sprintf("已接管隧道「%s」，%s 里的 %d 条规则已迁到云端（那个文件本工具没有改动）。"+
			"⚠️ 现在要把原来那条 cloudflared --config … 停掉：它读的还是文件，"+
			"不停的话两个连接器挂同一条隧道、规则还不一样，改规则会像没生效。",
			name, configPath, len(rules))
	}

	m.mu.Lock()
	t := m.addLocked(cred.TunnelID, name, cred.AccountTag, token)
	m.mu.Unlock()

	log.Printf("[CFTunnel] 已导入隧道「%s」(%s)，迁移 %d 条规则", name, cred.TunnelID, len(rules))
	return t, msg, nil
}

// hasRules 判断这批规则里有没有真东西。normalizeIngress 一定会补一条兜底的
// http_status:404，只有它的话等于没规则，不值得为此要求用户去配 Token。
func hasRules(rules []IngressRule) bool {
	for _, r := range rules {
		if r.Hostname != "" {
			return true
		}
	}
	return false
}

// validateImportPaths 检查导入用的两个路径。凭证必填，config 可以留空。
//
// 都要绝对路径：这两个路径是用户在界面上填的，相对路径会跟着服务进程的工作目录
// 走，换个方式启动服务就指到别处去了。
func validateImportPaths(credentialsPath, configPath string) error {
	if credentialsPath == "" {
		return fmt.Errorf("要指定凭证文件（~/.cloudflared/<UUID>.json）")
	}
	for _, f := range []struct{ name, path string }{
		{"凭证文件", credentialsPath},
		{"config 文件", configPath},
	} {
		if f.path != "" && !filepath.IsAbs(f.path) {
			return fmt.Errorf("%s要填绝对路径，%q 不是", f.name, f.path)
		}
	}
	return nil
}

// looksLikeTunnelName 判断 config 里 `tunnel:` 那一行写的是名字还是 UUID
func looksLikeTunnelName(s string) bool {
	return s != "" && (len(s) != 36 || strings.Count(s, "-") != 4)
}

// StartSaved 按各隧道保存下来的开关意愿把连接器拉起来，供进程启动时调用。
// force 为真时无条件启动全部（对应 -start-cftunnel）。
func (m *Manager) StartSaved(force bool) {
	for _, v := range m.Tunnels() {
		if !force && !v.WantRunning {
			log.Printf("[CFTunnel] 隧道「%s」上次退出时是停止的，本次不自动启动，可在 Web 后台点击启动", v.Name)
			continue
		}
		if err := m.Start(v.ID); err != nil {
			// 一条起不来不该拖垮整个进程：Web 后台还要进得去，用户得能改配置
			log.Printf("[CFTunnel] 启动隧道「%s」失败: %v，该隧道保持停止", v.Name, err)
		}
	}
}

// StopAll 停掉全部连接器，供进程退出前调用
func (m *Manager) StopAll() {
	m.mu.Lock()
	ids := append([]string(nil), m.order...)
	m.mu.Unlock()
	for _, id := range ids {
		m.stopProc(id)
	}
	m.StopQuick()
}

// ---------- 快速隧道（TryCloudflare）----------

// quickURLPattern 匹配 cloudflared 打在横幅里的那个临时域名
var quickURLPattern = regexp.MustCompile(`https://[a-z0-9][-a-z0-9]*\.trycloudflare\.com`)

// QuickStatus 是快速隧道的实况
type QuickStatus struct {
	Status
	URL    string `json:"url,omitempty"`
	Target string `json:"target,omitempty"`
}

// StartQuick 起一条临时隧道：不需要账号也不需要 Token，Cloudflare 现分一个
// xxx.trycloudflare.com 给你，进程一停域名就没了。适合临时把内网服务给别人看一眼。
func (m *Manager) StartQuick(target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("要暴露的本地服务不能为空，如 http://127.0.0.1:8090")
	}
	if err := validateService(target); err != nil {
		return err
	}
	if isBareService(target) {
		return fmt.Errorf("快速隧道要指向一个真实的本地服务，如 http://127.0.0.1:8090")
	}
	bin, err := m.binaryPath()
	if err != nil {
		return err
	}

	m.mu.Lock()
	if m.quickProc == nil {
		m.quickProc = &process{label: "快速隧道"}
	}
	p := m.quickProc
	m.quickURL, m.quickAddr = "", target
	m.mu.Unlock()

	// 临时域名只出现在启动横幅里，只能从输出里捞。
	// onLine 由读输出的 goroutine 调用，改它要拿 p.mu。
	p.mu.Lock()
	p.onLine = func(line string) {
		if u := quickURLPattern.FindString(line); u != "" {
			m.mu.Lock()
			m.quickURL = u
			m.mu.Unlock()
			log.Printf("[CFTunnel] 快速隧道已就绪: %s → %s", u, target)
		}
	}
	p.mu.Unlock()

	p.logs.reset() // 上一条隧道的域名留着会看错
	return p.Start(bin, []string{"--no-autoupdate", "tunnel", "--url", target}, os.Environ())
}

func (m *Manager) StopQuick() {
	m.mu.Lock()
	p := m.quickProc
	m.mu.Unlock()
	if p != nil {
		p.Stop()
	}
	m.mu.Lock()
	m.quickURL = ""
	m.mu.Unlock()
}

func (m *Manager) QuickStatus() QuickStatus {
	m.mu.Lock()
	p, url, target := m.quickProc, m.quickURL, m.quickAddr
	m.mu.Unlock()

	st := QuickStatus{URL: url, Target: target}
	if p != nil {
		st.Status = p.Status()
	}
	return st
}

// QuickLogs 返回快速隧道的输出
func (m *Manager) QuickLogs(after int64) []LogLine {
	m.mu.Lock()
	p := m.quickProc
	m.mu.Unlock()
	if p == nil {
		return nil
	}
	return p.logs.since(after)
}
