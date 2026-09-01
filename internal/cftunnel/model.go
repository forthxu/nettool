// Package cftunnel 管理 Cloudflare Tunnel。两头都归它管：
//
//   - 云端：拿用户的 API Token 调 Cloudflare 的 REST 接口，建/删隧道、改 ingress
//     规则（hostname → 本机服务）、给 hostname 下 CNAME 记录。
//   - 本地：托管 cloudflared 连接器进程，启停、日志、按上次的开关状态恢复。
//
// 只支持云端托管（cloudflared 那边叫 config_src=cloudflare）：ingress 规则的真源
// 在 Cloudflare，连接器只拿一个令牌，规则顺着隧道自己下发，改完几秒生效、不用重启，
// 本地不需要 config.yml 也不需要凭证文件。
//
// 已经在用「`cloudflared tunnel create` + 手写 config.yml」那一套的，用 Import
// 一次性搬过来：从凭证文件算出令牌接管隧道，再把 config 里的规则推到云端。
// 见 discover.go 与 cfdconfig.go。
package cftunnel

import (
	"fmt"
	"strings"
	"time"

	"nettool/internal/netutil"
)

// Settings 是账号级配置，全部隧道共用
type Settings struct {
	// APIToken 是 Cloudflare 的 API Token（不是 Global API Key）。需要
	// Account.Cloudflare Tunnel:Edit 与 Zone.DNS:Edit 两项权限。
	APIToken    string `json:"api_token,omitempty"`
	AccountID   string `json:"account_id,omitempty"`
	AccountName string `json:"account_name,omitempty"`
	// BinaryPath 留空表示先看托管目录、再在 PATH 里找 cloudflared
	BinaryPath string `json:"binary_path,omitempty"`
	// DownloadURL 留空表示用 GitHub 官方地址。国内机器直连 GitHub 常常拉不动，
	// 允许换成镜像：填到目录一级（以 / 结尾），文件名由平台决定。
	DownloadURL string `json:"download_url,omitempty"`
}

func (s Settings) normalized() Settings {
	s.APIToken = strings.TrimSpace(s.APIToken)
	s.AccountID = strings.TrimSpace(s.AccountID)
	s.AccountName = strings.TrimSpace(s.AccountName)
	s.BinaryPath = strings.TrimSpace(s.BinaryPath)
	s.DownloadURL = strings.TrimSpace(s.DownloadURL)
	return s
}

// Tunnel 是一条隧道的本地台账。
//
// ingress 规则不在这里：它们的真源在 Cloudflare 那边。本地再留一份副本只会和真源
// 对不上（在 Cloudflare 后台改一下就错位了），要看就现读。
type Tunnel struct {
	ID        string `json:"id"`         // 本地编号 t1、t2……
	CFID      string `json:"cf_id"`      // Cloudflare 那边的隧道 UUID
	Name      string `json:"name"`       // 隧道名，和云端一致
	AccountID string `json:"account_id"` // 建它时用的账号，换账号后能认出哪些是别家的
	// Token 是连接器令牌（一段 base64），等价于这条隧道的密码。
	// 它不出接口：对外只说有没有，见 Manager.publicTunnel。
	Token string `json:"token,omitempty"`
	// Running 记的是用户的开关意愿而不是此刻的实况：点了启动为 true，点了停止为
	// false。启动失败不会把它改掉，下次进程起来还会再试一次。
	Running   bool      `json:"running"`
	CreatedAt time.Time `json:"created_at"`
}

// IngressRule 是一条「什么样的请求交给本机哪个服务」的规则。
// 顺序有意义：Cloudflare 从上往下匹配，第一条命中的生效。
//
// yaml 标签是给导入时读 config.yml 用的：cloudflared 配置文件里的键名和
// Cloudflare API 那边一模一样，所以同一个结构体两处通用。
type IngressRule struct {
	Hostname string `json:"hostname,omitempty" yaml:"hostname,omitempty"` // 留空表示兜底规则，只能放在最后
	Path     string `json:"path,omitempty" yaml:"path,omitempty"`         // 正则，如 ^/api/.*
	Service  string `json:"service" yaml:"service"`                       // http://127.0.0.1:8090、ssh://127.0.0.1:22、http_status:404
	// OriginRequest 是这条规则连本机服务时的额外参数（noTLSVerify、httpHostHeader
	// 等）。故意用松散的 map 而不是结构体：cloudflared 的参数几十个还在加，
	// 写死一份就得跟着它升级，认识的做校验、不认识的原样透传更省事。
	OriginRequest map[string]interface{} `json:"originRequest,omitempty" yaml:"originRequest,omitempty"`
}

// originRequestTypes 是界面上做成表单的那几项，校验类型用。
// 不在表里的键不校验、原样交给 Cloudflare。
var originRequestTypes = map[string]string{
	"noTLSVerify":            "bool",
	"disableChunkedEncoding": "bool",
	"http2Origin":            "bool",
	"httpHostHeader":         "string",
	"originServerName":       "string",
	"connectTimeout":         "duration",
	"tlsTimeout":             "duration",
	"keepAliveTimeout":       "duration",
}

// validateOriginRequest 检查认识的那几项类型对不对。
//
// 值得单独校验是因为写错了不会当场报错：Cloudflare 会收下，然后这条规则的每个
// 请求都失败，从界面上完全看不出是参数写错了。
func validateOriginRequest(m map[string]interface{}) error {
	for k, v := range m {
		switch originRequestTypes[k] {
		case "bool":
			if _, ok := v.(bool); !ok {
				return fmt.Errorf("originRequest.%s 要填 true 或 false，不是 %v", k, v)
			}
		case "string":
			if _, ok := v.(string); !ok {
				return fmt.Errorf("originRequest.%s 要填一段文本，不是 %v", k, v)
			}
		case "duration":
			s, ok := v.(string)
			if !ok {
				return fmt.Errorf("originRequest.%s 要填时长（如 30s），不是 %v", k, v)
			}
			if _, err := time.ParseDuration(s); err != nil {
				return fmt.Errorf("originRequest.%s 的 %q 不是合法时长，应形如 30s、1m", k, s)
			}
		}
	}
	return nil
}

// ingressSchemes 是 cloudflared 认得的 service 前缀。写错了要在保存时就说出来，
// 不然规则会被 Cloudflare 收下、然后每个请求都 502，从界面上看不出原因。
var ingressSchemes = []string{
	"http://", "https://", "tcp://", "ssh://", "rdp://", "smb://", "unix:/", "unix+tls:/",
}

// 不带地址的几种特殊 service
func isBareService(s string) bool {
	return s == "hello_world" || s == "bastion" || strings.HasPrefix(s, "http_status:")
}

func validateService(service string) error {
	if service == "" {
		return fmt.Errorf("service 不能为空")
	}
	if isBareService(service) {
		return nil
	}
	for _, scheme := range ingressSchemes {
		if !strings.HasPrefix(service, scheme) {
			continue
		}
		if strings.TrimPrefix(service, scheme) == "" {
			return fmt.Errorf("service %q 缺少地址", service)
		}
		return nil
	}
	return fmt.Errorf("service %q 不认识，应形如 http://127.0.0.1:8090、tcp://127.0.0.1:3306 或 http_status:404", service)
}

// normalizeIngress 校验并补齐规则表：去空行、检查每条的域名与 service，
// 最后保证结尾是一条兜底规则——Cloudflare 要求最后一条不带 hostname，
// 缺了它整份配置会被拒收。
func normalizeIngress(rules []IngressRule) ([]IngressRule, error) {
	out := make([]IngressRule, 0, len(rules)+1)
	for _, r := range rules {
		r.Hostname = strings.TrimSpace(strings.ToLower(r.Hostname))
		r.Path = strings.TrimSpace(r.Path)
		r.Service = strings.TrimSpace(r.Service)
		if len(r.OriginRequest) == 0 {
			r.OriginRequest = nil // 空 map 会在 YAML 里留下一行 `originRequest: {}`
		}
		if r.Hostname == "" && r.Path == "" && r.Service == "" && r.OriginRequest == nil {
			continue // 界面上留白的那一行
		}
		if err := validateService(r.Service); err != nil {
			return nil, err
		}
		if r.Hostname != "" && !netutil.IsValidDomain(r.Hostname) {
			return nil, fmt.Errorf("域名 %q 不合法", r.Hostname)
		}
		if err := validateOriginRequest(r.OriginRequest); err != nil {
			return nil, err
		}
		out = append(out, r)
	}

	// 中间冒出来的兜底规则会把它后面的全挡掉，与其静默吞掉不如直接报错
	for i, r := range out {
		if r.Hostname == "" && i != len(out)-1 {
			return nil, fmt.Errorf("第 %d 条没填域名，只有最后一条兜底规则可以不填", i+1)
		}
	}

	if len(out) == 0 || out[len(out)-1].Hostname != "" {
		out = append(out, IngressRule{Service: "http_status:404"})
	}
	return out, nil
}

// maskSecret 把机密裁成"看得出是哪一个、但抄不走"的样子
func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "…" + s[len(s)-4:]
}
