package cftunnel

// Cloudflare REST API 客户端，只覆盖隧道这条线用得到的那几个接口。
//
// 两件事值得先说：
//
//   - Cloudflare 的接口即使业务失败也常常回 HTTP 200，真正的成败在响应体的
//     success 字段里，所以每次都要把整个信封解出来看，不能只看状态码。
//   - 错误信息一律带上 Cloudflare 给的错误码原文。它们是可查的（10000 是鉴权、
//     1004 是权限不够），比翻译一遍更有用。

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// APIBase 是 Cloudflare 接口地址，测试里替换成 httptest 服务器
var APIBase = "https://api.cloudflare.com/client/v4"

type apiClient struct {
	token string
	http  *http.Client
}

func newAPIClient(token string) *apiClient {
	return &apiClient{token: token, http: &http.Client{Timeout: 25 * time.Second}}
}

// envelope 是 Cloudflare 所有响应的统一外壳
type envelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (e envelope) err(status int) error {
	if len(e.Errors) == 0 {
		return fmt.Errorf("Cloudflare 拒绝了请求（HTTP %d），但没说原因", status)
	}
	parts := make([]string, 0, len(e.Errors))
	for _, x := range e.Errors {
		parts = append(parts, fmt.Sprintf("%d %s", x.Code, x.Message))
	}
	return fmt.Errorf("Cloudflare: %s", strings.Join(parts, "; "))
}

// do 发一次请求并把 result 解到 out（out 为 nil 时丢弃）
func (c *apiClient) do(method, path string, body, out interface{}) error {
	if c.token == "" {
		return fmt.Errorf("还没有填 Cloudflare API Token")
	}

	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, APIBase+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("连不上 Cloudflare: %v", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("读取 Cloudflare 响应失败: %v", err)
	}

	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		// 网关挡在前面时回的是 HTML，把状态码带出来比抛 JSON 解析错误有用
		return fmt.Errorf("Cloudflare 返回了看不懂的内容（HTTP %d）", resp.StatusCode)
	}
	if !env.Success {
		return env.err(resp.StatusCode)
	}
	if out == nil || len(env.Result) == 0 {
		return nil
	}
	return json.Unmarshal(env.Result, out)
}

// Account 是隧道所属的账号
type Account struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Zone 是一个托管在 Cloudflare 的域名，下 CNAME 记录时要用它的 ID
type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Account 是这个域名所属的账号。Token 只有 Zone 级权限时 /accounts 会返回
	// 空列表，这里就是唯一能问出账号 ID 的地方（见 apiClient.AccountsOrFromZones）。
	Account Account `json:"account"`
}

// RemoteTunnel 是云端看到的隧道，比本地台账多了健康状态与连接情况
type RemoteTunnel struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	DeletedAt *time.Time `json:"deleted_at"`
	// Status 是 healthy / degraded / down / inactive，inactive 表示从来没连上过
	Status      string `json:"status"`
	ConfigSrc   string `json:"config_src"`
	Connections []struct {
		ColoName           string `json:"colo_name"`
		IsPendingReconnect bool   `json:"is_pending_reconnect"`
	} `json:"connections"`
}

// ActiveConnections 数的是真的连上的那些。cloudflared 断线重连期间连接条目还在，
// 直接数长度会把"正在掉线"显示成"连着 4 条"。
func (t RemoteTunnel) ActiveConnections() int {
	n := 0
	for _, c := range t.Connections {
		if !c.IsPendingReconnect {
			n++
		}
	}
	return n
}

// VerifyToken 确认 Token 有效（顺便探出它是不是被吊销/过期了）
func (c *apiClient) VerifyToken() error {
	var out struct {
		Status string `json:"status"`
	}
	if err := c.do(http.MethodGet, "/user/tokens/verify", nil, &out); err != nil {
		return err
	}
	if out.Status != "" && out.Status != "active" {
		return fmt.Errorf("这个 API Token 的状态是 %s，不能用", out.Status)
	}
	return nil
}

func (c *apiClient) Accounts() ([]Account, error) {
	var out []Account
	err := c.do(http.MethodGet, "/accounts?per_page=50", nil, &out)
	return out, err
}

func (c *apiClient) Zones() ([]Zone, error) {
	var out []Zone
	err := c.do(http.MethodGet, "/zones?per_page=200&status=active", nil, &out)
	return out, err
}

// AccountsOrFromZones 拿账号列表，/accounts 空手而归时从域名里问出来。
//
// 按文档建的 Token（Account·Cloudflare Tunnel:Edit + Zone·DNS:Edit）**列不出账号**：
// /accounts 要的是 Account Settings:Read，那两项都不含它，于是接口返回
// success=true 加一个空数组。但 /zones 的每条记录里带着 account.id，而且隧道
// 接口拿这个 ID 是好使的——账号权限和"能不能列出账号"是两回事。
//
// 不为此要求用户多授一项权限：多给的权限撤不回来，而这里本来就问得到。
func (c *apiClient) AccountsOrFromZones() ([]Account, error) {
	accounts, err := c.Accounts()
	if err != nil {
		return nil, err
	}
	if len(accounts) > 0 {
		return accounts, nil
	}

	zones, err := c.Zones()
	if err != nil {
		// 两条路都不通，说的是第一条的问题——用户要配的是账号
		return nil, fmt.Errorf("读不到账号列表，也读不到域名列表: %v", err)
	}
	seen := make(map[string]bool, len(zones))
	for _, z := range zones {
		if z.Account.ID == "" || seen[z.Account.ID] {
			continue
		}
		seen[z.Account.ID] = true
		accounts = append(accounts, z.Account)
	}
	return accounts, nil
}

func (c *apiClient) Tunnels(accountID string) ([]RemoteTunnel, error) {
	var out []RemoteTunnel
	err := c.do(http.MethodGet, "/accounts/"+url.PathEscape(accountID)+"/cfd_tunnel?is_deleted=false&per_page=200", nil, &out)
	return out, err
}

// CreateTunnel 建一条远程托管的隧道。
//
// config_src=cloudflare 表示 ingress 规则存在 Cloudflare 那边，连接器凭 Token 自己
// 拉——本地就不用管 config.yml 了。tunnel_secret 是隧道的对称密钥，接口允许留空由
// 服务端生成，但各版本行为不一，自己给一个 32 字节的随机值最省事。
func (c *apiClient) CreateTunnel(accountID, name string) (RemoteTunnel, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return RemoteTunnel{}, fmt.Errorf("生成隧道密钥失败: %v", err)
	}
	body := map[string]string{
		"name":          name,
		"config_src":    "cloudflare",
		"tunnel_secret": base64.StdEncoding.EncodeToString(secret),
	}
	var out RemoteTunnel
	err := c.do(http.MethodPost, "/accounts/"+url.PathEscape(accountID)+"/cfd_tunnel", body, &out)
	return out, err
}

func (c *apiClient) DeleteTunnel(accountID, tunnelID string) error {
	return c.do(http.MethodDelete,
		"/accounts/"+url.PathEscape(accountID)+"/cfd_tunnel/"+url.PathEscape(tunnelID), nil, nil)
}

// TunnelToken 取连接器令牌。它不随隧道列表返回，只能单独要一次。
func (c *apiClient) TunnelToken(accountID, tunnelID string) (string, error) {
	var token string
	err := c.do(http.MethodGet,
		"/accounts/"+url.PathEscape(accountID)+"/cfd_tunnel/"+url.PathEscape(tunnelID)+"/token", nil, &token)
	return token, err
}

// tunnelConfig 是 configurations 接口的形状。
//
// Source 是 cloudflare / local，表示云端存的这份算不算数。注意它**不表示**
// 云端会覆盖本地：带 --config 启动的连接器照样用文件里的规则。
type tunnelConfig struct {
	Source string `json:"source,omitempty"`
	Config struct {
		Ingress []IngressRule `json:"ingress"`
	} `json:"config"`
}

// TunnelIngress 拉云端的 ingress 规则。隧道刚建出来时还没有配置，
// 这时 config 是 null，返回空表而不是报错。
func (c *apiClient) TunnelIngress(accountID, tunnelID string) ([]IngressRule, error) {
	cfg, err := c.TunnelConfig(accountID, tunnelID)
	if err != nil {
		return nil, err
	}
	return cfg.Config.Ingress, nil
}

// TunnelConfig 比 TunnelIngress 多带一个 source，推规则前要看它一眼
func (c *apiClient) TunnelConfig(accountID, tunnelID string) (tunnelConfig, error) {
	var out tunnelConfig
	err := c.do(http.MethodGet,
		"/accounts/"+url.PathEscape(accountID)+"/cfd_tunnel/"+url.PathEscape(tunnelID)+"/configurations", nil, &out)
	return out, err
}

// SetTunnelIngress 整份覆盖云端的 ingress 规则；连接器会在几秒内自己拉到新配置，
// 不用重启。
func (c *apiClient) SetTunnelIngress(accountID, tunnelID string, rules []IngressRule) error {
	var body tunnelConfig
	body.Config.Ingress = rules
	return c.do(http.MethodPut,
		"/accounts/"+url.PathEscape(accountID)+"/cfd_tunnel/"+url.PathEscape(tunnelID)+"/configurations", body, nil)
}

// DNSRecord 是一条 DNS 记录，这里只用到 CNAME
type DNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
}

func (c *apiClient) DNSRecordsByName(zoneID, name string) ([]DNSRecord, error) {
	var out []DNSRecord
	err := c.do(http.MethodGet,
		"/zones/"+url.PathEscape(zoneID)+"/dns_records?name="+url.QueryEscape(name), nil, &out)
	return out, err
}

// UpsertTunnelCNAME 把 hostname 指到隧道上。已经存在同名记录就改它，
// 而不是再加一条——同名多条 CNAME 会让 Cloudflare 直接拒收。
func (c *apiClient) UpsertTunnelCNAME(zoneID, hostname, tunnelID string) (string, error) {
	target := tunnelID + ".cfargotunnel.com"
	body := map[string]interface{}{
		"type": "CNAME", "name": hostname, "content": target,
		// 必须走橙云：cfargotunnel.com 只有经过 Cloudflare 边缘才解析得到
		"proxied": true, "ttl": 1,
	}

	existing, err := c.DNSRecordsByName(zoneID, hostname)
	if err != nil {
		return "", err
	}
	for _, r := range existing {
		if r.Type != "CNAME" {
			return "", fmt.Errorf("%s 上已经有一条 %s 记录（%s），请先在 Cloudflare 后台删掉", hostname, r.Type, r.Content)
		}
		if r.Content == target {
			return "已经指向本隧道，无需改动", nil
		}
		err := c.do(http.MethodPut, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(r.ID), body, nil)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("已把原先指向 %s 的记录改到本隧道", r.Content), nil
	}

	if err := c.do(http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records", body, nil); err != nil {
		return "", err
	}
	return "已新增 CNAME 记录", nil
}

func (c *apiClient) DeleteDNSRecord(zoneID, recordID string) error {
	return c.do(http.MethodDelete,
		"/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(recordID), nil, nil)
}

// DeleteTunnelCNAME 删掉 hostname 上那条指向本隧道的 CNAME，是 UpsertTunnelCNAME 的逆操作。
//
// 删之前一定要比对 content：同名记录可能是用户自己建的 A 记录、指向别处的 CNAME，
// 或者指向**另一条**隧道。这些一律不碰，报错让用户自己去后台确认——DNS 记录删了
// 没有回收站，宁可少删一条。同理，先把所有记录检查一遍再动手，免得混着几条时
// 删一半剩一半。
func (c *apiClient) DeleteTunnelCNAME(zoneID, hostname, tunnelID string) (string, error) {
	target := tunnelID + ".cfargotunnel.com"
	existing, err := c.DNSRecordsByName(zoneID, hostname)
	if err != nil {
		return "", err
	}
	if len(existing) == 0 {
		return "本来就没有这个域名的 DNS 记录，不用删", nil
	}
	for _, r := range existing {
		if r.Type != "CNAME" || r.Content != target {
			return "", fmt.Errorf("%s 上是一条 %s 记录（%s），并不指向本隧道（应为 CNAME → %s），"+
				"没有动它；确实要删请去 Cloudflare 后台", hostname, r.Type, r.Content, target)
		}
	}
	for _, r := range existing {
		if err := c.DeleteDNSRecord(zoneID, r.ID); err != nil {
			return "", err
		}
	}
	return "已删除 CNAME 记录", nil
}

// zoneFor 从 zone 列表里挑出 hostname 该落在哪个域名下。
// 按最长后缀匹配：a.b.example.com 同时有 example.com 和 b.example.com 两个 zone 时，
// 记录要下到更具体的那个上。
func zoneFor(zones []Zone, hostname string) (Zone, bool) {
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	best, ok := Zone{}, false
	for _, z := range zones {
		name := strings.ToLower(z.Name)
		if hostname != name && !strings.HasSuffix(hostname, "."+name) {
			continue
		}
		if !ok || len(name) > len(best.Name) {
			best, ok = z, true
		}
	}
	return best, ok
}
