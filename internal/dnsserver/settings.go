// Package dnsserver 是一个本地 DNS 解析服务：在局域网里当解析器用，把查询按域名规则
// 分发到不同形式的上游（普通 UDP/TCP、DoT、DoH），并带一层内存缓存和静态 hosts 记录。
//
// 之所以自己实现而不是引第三方库：转发只需要读懂请求的问题段和应答的 TTL，
// golang.org/x/net/dns/dnsmessage（已经是本项目的间接依赖）就够用了。
package dnsserver

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"nettool/internal/netutil"
)

// 上游 DNS 的四种形态
const (
	upstreamUDP   = "udp"   // 传统 53 端口明文
	upstreamTCP   = "tcp"   // 53 端口 TCP，应答大或被 UDP 干扰时有用
	upstreamTLS   = "tls"   // DoT，RFC 7858，默认 853
	upstreamHTTPS = "https" // DoH，RFC 8484
)

// 查询策略
const (
	strategySequential = "sequential" // 按顺序试，前一个失败才轮到下一个
	strategyRace       = "race"       // 一起发，谁先回用谁
)

const (
	configVersion = 1
	// 应答里没有可用 TTL（NXDOMAIN、空应答）时按这个时长做负缓存
	negativeTTL = 30 * time.Second
	// 最近查询日志保留条数，够在界面上看清刚发生了什么就行
	recentLimit = 60
	udpBufSize  = 4096
)

// Upstream 描述一个上游解析器。Domains 为空表示兜底上游，
// 非空则只接管这些域名及其子域——这样能把国内域名留给运营商 DNS，
// 其他的走 DoH/DoT，跟「路由管理」里按域名分流的思路一致。
type Upstream struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Address   string   `json:"address"`
	Hostname  string   `json:"hostname"`  // DoT/DoH 校验证书用的域名
	Bootstrap string   `json:"bootstrap"` // 解析上面这个域名用的普通 DNS，避免自举死循环
	Domains   []string `json:"domains"`
	Enabled   bool     `json:"enabled"`
}

// HostRecord 是本地静态解析，域名支持 *.example.com 这种通配写法
type HostRecord struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
}

// Settings 是 DNS 服务的完整配置，也是持久化到 dns.json 里的内容
type Settings struct {
	Listen    string       `json:"listen"`
	Port      string       `json:"port"`
	Strategy  string       `json:"strategy"`
	TimeoutMS int          `json:"timeout_ms"`
	Cache     bool         `json:"cache"`
	CacheSize int          `json:"cache_size"`
	MinTTL    int          `json:"min_ttl"`
	MaxTTL    int          `json:"max_ttl"`
	Upstreams []Upstream   `json:"upstreams"`
	Hosts     []HostRecord `json:"hosts"`
}

func defaultSettings() Settings {
	return Settings{
		Listen:    "0.0.0.0",
		Port:      "53",
		Strategy:  strategySequential,
		TimeoutMS: 5000,
		Cache:     true,
		CacheSize: 4096,
		MinTTL:    10,
		MaxTTL:    3600,
		Upstreams: []Upstream{},
		Hosts:     []HostRecord{},
	}
}

// normalizeUpstream 把用户填的各种写法收敛成统一结构。
// 支持：8.8.8.8 / 8.8.8.8:53 / udp://8.8.8.8 / tcp://8.8.8.8 /
// tls://1.1.1.1 / tls://1.1.1.1@one.one.one.one / https://dns.google/dns-query
func normalizeUpstream(u Upstream) (Upstream, error) {
	addr := strings.TrimSpace(u.Address)
	u.Type = strings.ToLower(strings.TrimSpace(u.Type))
	u.Hostname = strings.TrimSpace(u.Hostname)
	u.Bootstrap = strings.TrimSpace(u.Bootstrap)
	if addr == "" {
		return u, fmt.Errorf("上游地址不能为空")
	}

	// 地址里带 scheme 时以 scheme 为准：用户多半是从别处直接粘过来的
	lower := strings.ToLower(addr)
	switch {
	case strings.HasPrefix(lower, "https://"):
		u.Type = upstreamHTTPS
	case strings.HasPrefix(lower, "tls://"), strings.HasPrefix(lower, "dot://"):
		u.Type = upstreamTLS
		addr = addr[strings.Index(addr, "//")+2:]
	case strings.HasPrefix(lower, "udp://"), strings.HasPrefix(lower, "dns://"):
		u.Type = upstreamUDP
		addr = addr[strings.Index(addr, "//")+2:]
	case strings.HasPrefix(lower, "tcp://"):
		u.Type = upstreamTCP
		addr = addr[strings.Index(addr, "//")+2:]
	case strings.HasPrefix(lower, "http://"):
		return u, fmt.Errorf("DoH 必须用 https://，明文 http 起不到加密作用")
	}
	if u.Type == "" {
		u.Type = upstreamUDP
	}

	// ip@hostname 是 DoT 常见写法：连 IP、但按 hostname 校验证书
	if at := strings.LastIndex(addr, "@"); at >= 0 && u.Type != upstreamHTTPS {
		if u.Hostname == "" {
			u.Hostname = strings.TrimSpace(addr[at+1:])
		}
		addr = strings.TrimSpace(addr[:at])
	}

	if err := validateBootstrap(&u); err != nil {
		return u, err
	}

	switch u.Type {
	case upstreamHTTPS:
		parsed, err := url.Parse(addr)
		if err != nil {
			return u, fmt.Errorf("DoH 地址 %q 不是合法 URL: %v", addr, err)
		}
		if parsed.Scheme != "https" || parsed.Host == "" {
			return u, fmt.Errorf("DoH 地址 %q 必须形如 https://host/dns-query", addr)
		}
		if parsed.Path == "" || parsed.Path == "/" {
			parsed.Path = "/dns-query" // RFC 8484 的惯例路径，少填一截也能用
		}
		u.Address = parsed.String()
		if u.Hostname == "" {
			u.Hostname = parsed.Hostname()
		}
	case upstreamUDP, upstreamTCP, upstreamTLS:
		defPort := "53"
		if u.Type == upstreamTLS {
			defPort = "853"
		}
		full, host, err := normalizeHostPort(addr, defPort)
		if err != nil {
			return u, err
		}
		u.Address = full
		// DoT 连的是 IP 时必须另外给个域名才能校验证书；连域名时默认拿它自己校验
		if u.Type == upstreamTLS && u.Hostname == "" {
			if net.ParseIP(host) != nil {
				return u, fmt.Errorf("DoT 上游 %q 是 IP，请另外填证书域名（或写成 %s@dns.example.com）", addr, host)
			}
			u.Hostname = host
		}
	default:
		return u, fmt.Errorf("不支持的上游类型 %q，可选 udp/tcp/tls/https", u.Type)
	}

	u.Name = strings.TrimSpace(u.Name)
	if u.Name == "" {
		u.Name = u.Address
	}

	domains := make([]string, 0, len(u.Domains))
	seen := make(map[string]bool, len(u.Domains))
	for _, d := range u.Domains {
		d = strings.ToLower(strings.Trim(strings.TrimSpace(d), "."))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		domains = append(domains, d)
	}
	u.Domains = domains
	return u, nil
}

// validateBootstrap 校验并补全 bootstrap（只对需要连域名的 DoT/DoH 有意义）
func validateBootstrap(u *Upstream) error {
	if u.Bootstrap == "" {
		return nil
	}
	full, _, err := normalizeHostPort(u.Bootstrap, "53")
	if err != nil {
		return fmt.Errorf("bootstrap DNS 无效: %v", err)
	}
	if host, _, _ := net.SplitHostPort(full); net.ParseIP(host) == nil {
		return fmt.Errorf("bootstrap DNS 必须填 IP，否则它自己也需要解析")
	}
	u.Bootstrap = full
	return nil
}

// normalizeHostPort 缺端口时补上默认端口，返回 host:port 和其中的 host
func normalizeHostPort(addr, defPort string) (full, host string, err error) {
	addr = strings.TrimSpace(strings.Trim(addr, "/"))
	if addr == "" {
		return "", "", fmt.Errorf("地址不能为空")
	}
	if h, p, splitErr := net.SplitHostPort(addr); splitErr == nil {
		if h == "" {
			return "", "", fmt.Errorf("地址 %q 缺少主机名", addr)
		}
		if n, convErr := strconv.Atoi(p); convErr != nil || n < 1 || n > 65535 {
			return "", "", fmt.Errorf("地址 %q 的端口不合法", addr)
		}
		return net.JoinHostPort(h, p), h, nil
	}
	// 裸 IPv6 会被 SplitHostPort 当成 host:port 拆坏，这里单独兜住
	if ip := net.ParseIP(addr); ip != nil {
		return net.JoinHostPort(addr, defPort), addr, nil
	}
	if strings.Contains(addr, ":") || strings.ContainsAny(addr, " /\\") {
		return "", "", fmt.Errorf("地址 %q 格式不对", addr)
	}
	if !netutil.IsValidDomain(addr) {
		return "", "", fmt.Errorf("地址 %q 既不是 IP 也不是合法域名", addr)
	}
	return net.JoinHostPort(addr, defPort), addr, nil
}

// validateSettings 校验整份配置并回填默认值，返回规整后的副本
func validateSettings(s Settings) (Settings, error) {
	def := defaultSettings()

	s.Listen = strings.TrimSpace(s.Listen)
	if s.Listen == "" {
		s.Listen = def.Listen
	}
	if net.ParseIP(s.Listen) == nil {
		return s, fmt.Errorf("监听地址 %q 不是合法 IP", s.Listen)
	}

	s.Port = strings.TrimSpace(s.Port)
	if s.Port == "" {
		s.Port = def.Port
	}
	if n, err := strconv.Atoi(s.Port); err != nil || n < 1 || n > 65535 {
		return s, fmt.Errorf("监听端口 %q 不合法", s.Port)
	}

	switch strings.ToLower(strings.TrimSpace(s.Strategy)) {
	case "", strategySequential:
		s.Strategy = strategySequential
	case strategyRace, "parallel":
		s.Strategy = strategyRace
	default:
		return s, fmt.Errorf("查询策略 %q 不支持，可选 sequential/race", s.Strategy)
	}

	if s.TimeoutMS <= 0 {
		s.TimeoutMS = def.TimeoutMS
	}
	if s.TimeoutMS < 200 {
		s.TimeoutMS = 200
	}
	if s.TimeoutMS > 30000 {
		s.TimeoutMS = 30000
	}
	if s.CacheSize <= 0 {
		s.CacheSize = def.CacheSize
	}
	if s.CacheSize > 65536 {
		s.CacheSize = 65536
	}
	if s.MinTTL < 0 {
		s.MinTTL = 0
	}
	if s.MaxTTL <= 0 {
		s.MaxTTL = def.MaxTTL
	}
	if s.MaxTTL < s.MinTTL {
		s.MaxTTL = s.MinTTL
	}

	ups := make([]Upstream, 0, len(s.Upstreams))
	names := make(map[string]bool, len(s.Upstreams))
	for i, u := range s.Upstreams {
		nu, err := normalizeUpstream(u)
		if err != nil {
			return s, fmt.Errorf("第 %d 个上游: %v", i+1, err)
		}
		// 名字要唯一，界面和统计都拿它当标识
		base := nu.Name
		for n := 2; names[nu.Name]; n++ {
			nu.Name = fmt.Sprintf("%s #%d", base, n)
		}
		names[nu.Name] = true
		ups = append(ups, nu)
	}
	s.Upstreams = ups

	hosts := make([]HostRecord, 0, len(s.Hosts))
	for i, h := range s.Hosts {
		domain := strings.ToLower(strings.Trim(strings.TrimSpace(h.Domain), "."))
		ipStr := strings.TrimSpace(h.IP)
		if domain == "" && ipStr == "" {
			continue
		}
		bare := strings.TrimPrefix(domain, "*.")
		if bare == "" || !netutil.IsValidDomain(bare) {
			return s, fmt.Errorf("第 %d 条静态记录的域名 %q 不合法", i+1, h.Domain)
		}
		if net.ParseIP(ipStr) == nil {
			return s, fmt.Errorf("第 %d 条静态记录的 IP %q 不合法", i+1, h.IP)
		}
		hosts = append(hosts, HostRecord{Domain: domain, IP: ipStr})
	}
	s.Hosts = hosts

	return s, nil
}
