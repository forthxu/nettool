package main

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/armon/go-socks5"
	"golang.org/x/net/proxy"
)

//go:embed static/*
var staticFiles embed.FS

// Global Auth Configuration
var authConfig struct {
	mu       sync.Mutex
	username string
	password string
}

func setAuth(user, pass string) {
	authConfig.mu.Lock()
	defer authConfig.mu.Unlock()
	authConfig.username = user
	authConfig.password = pass
}

func checkAuth(r *http.Request) bool {
	authConfig.mu.Lock()
	user := authConfig.username
	pass := authConfig.password
	authConfig.mu.Unlock()

	// If no username/password configured, allow all
	if user == "" && pass == "" {
		return true
	}

	u, p, ok := r.BasicAuth()
	if !ok {
		return false
	}

	usernameMatch := subtle.ConstantTimeCompare([]byte(u), []byte(user)) == 1
	passwordMatch := subtle.ConstantTimeCompare([]byte(p), []byte(pass)) == 1

	return usernameMatch && passwordMatch
}

func basicAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted Access"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// ---------------------------------------------------------
// Traffic & Connection Monitoring Structures
// ---------------------------------------------------------

type ConnectionInfo struct {
	ID         string    `json:"id"`
	ClientAddr string    `json:"client_addr"`
	TargetAddr string    `json:"target_addr"`
	BytesIn    int64     `json:"bytes_in"`  // Download
	BytesOut   int64     `json:"bytes_out"` // Upload
	StartTime  time.Time `json:"start_time"`
}

type StatsManager struct {
	mu                sync.Mutex
	totalBytesIn      int64
	totalBytesOut     int64
	totalConnections  int64
	activeConnections map[string]*ConnectionInfo
}

var stats = &StatsManager{
	activeConnections: make(map[string]*ConnectionInfo),
}

func (s *StatsManager) AddConnection(id, client, target string) *ConnectionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	atomic.AddInt64(&s.totalConnections, 1)
	conn := &ConnectionInfo{
		ID:         id,
		ClientAddr: client,
		TargetAddr: target,
		StartTime:  time.Now(),
	}
	s.activeConnections[id] = conn
	return conn
}

func (s *StatsManager) RemoveConnection(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.activeConnections, id)
}

func (s *StatsManager) AddBytes(in, out int64) {
	if in > 0 {
		atomic.AddInt64(&s.totalBytesIn, in)
	}
	if out > 0 {
		atomic.AddInt64(&s.totalBytesOut, out)
	}
}

type MonitoredConn struct {
	net.Conn
	info  *ConnectionInfo
	owner *statsListener // 停止代理时用来主动断开这条隧道
}

func (mc *MonitoredConn) Read(b []byte) (int, error) {
	n, err := mc.Conn.Read(b)
	if n > 0 {
		atomic.AddInt64(&mc.info.BytesIn, int64(n))
		stats.AddBytes(int64(n), 0)
	}
	return n, err
}

func (mc *MonitoredConn) Write(b []byte) (int, error) {
	n, err := mc.Conn.Write(b)
	if n > 0 {
		atomic.AddInt64(&mc.info.BytesOut, int64(n))
		stats.AddBytes(0, int64(n))
	}
	return n, err
}

func (mc *MonitoredConn) Close() error {
	stats.RemoveConnection(mc.info.ID)
	if mc.owner != nil {
		mc.owner.forget(mc)
	}
	return mc.Conn.Close()
}

// ---------------------------------------------------------
// Route Manager & Proxy Server
// ---------------------------------------------------------

type RouteRule struct {
	Destination string `json:"destination"` // 实际下发到内核的目标，统一为 CIDR
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface,omitempty"`

	// 按域名添加时记录来源，便于日后对账：内核里只有 IP，
	// 不记下来就无从知道这条路由是谁、什么时候解析出来的。
	//
	// 是数组而不是单个域名：不同域名完全可能解析到同一个 IP（同一个 CDN 或同
	// 一台主机上的多个站点就是这样），而内核路由表里一个目标只能有一条路由，
	// 所以这条路由要能被多个域名共同持有，最后一个持有者撤走时才真正删除。
	Domains    []string   `json:"domains,omitempty"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`

	// 暂停：从内核撤下但保留台账记录，随时可恢复
	Paused   bool       `json:"paused,omitempty"`
	PausedAt *time.Time `json:"paused_at,omitempty"`

	// 旧台账里的单域名字段，载入时迁移到 Domains 后清空
	LegacyDomain string `json:"domain,omitempty"`
}

func (r RouteRule) HasDomain(domain string) bool {
	for _, d := range r.Domains {
		if d == domain {
			return true
		}
	}
	return false
}

func routeOrigin(domains []string) string {
	switch len(domains) {
	case 0:
		return "手动指定"
	case 1:
		return "域名 " + domains[0]
	default:
		return "域名 " + strings.Join(domains, "、") + " 共用"
	}
}

// DomainEntry 独立记录被托管的域名本身。
//
// 不能靠"还有没有该域名的路由"来反推域名是否被托管：某轮刷新如果把旧 IP 撤下、
// 新 IP 又恰好添加失败，域名就会从台账里彻底消失，再也不会被自动刷新。
type DomainEntry struct {
	Domain       string     `json:"domain"`
	Gateway      string     `json:"gateway"`
	Interface    string     `json:"interface,omitempty"`
	LastResolved *time.Time `json:"last_resolved,omitempty"`
	LastError    string     `json:"last_error,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	// 暂停的域名不参与定时重新解析，其路由也从内核撤下
	Paused bool `json:"paused,omitempty"`
}

type RouterManager struct {
	mu      sync.Mutex
	routes  map[string]RouteRule
	domains map[string]DomainEntry
}

var manager = &RouterManager{
	routes:  make(map[string]RouteRule),
	domains: make(map[string]DomainEntry),
}

// ProxyServer 的配置（port / outboundIP）与运行状态是分开的：代理停着的时候
// 也能改配置，改完点启动才生效。
type ProxyServer struct {
	mu         sync.Mutex
	port       string
	outboundIP string
	startedAt  time.Time // 代理最近一次启动的时间，改配置重启会刷新
	listener   *statsListener
	closeChan  chan struct{}
}

// processStartedAt 是进程本身的启动时间，代理重启不影响它
var processStartedAt = time.Now()

var proxyMgr = &ProxyServer{
	port:       "1080",
	outboundIP: "",
}

func (p *ProxyServer) Start(port string, outboundIP string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.startLocked(port, outboundIP)
}

// StartCurrent 用已保存的配置启动，供 Web 后台的「启动」按钮使用
func (p *ProxyServer) StartCurrent() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.startLocked(p.port, p.outboundIP)
}

// Stop 停止代理并断开现有连接；已经停止时是空操作
func (p *ProxyServer) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener == nil {
		return nil
	}
	log.Printf("[SOCKS5] Stopping SOCKS5 proxy server on port %s", p.port)
	return p.stopLocked()
}

func (p *ProxyServer) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.listener != nil
}

// SetConfig 只改配置：代理在跑就带新配置重启，停着就先记下来，下次启动时生效。
func (p *ProxyServer) SetConfig(port, outboundIP string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.listener != nil {
		return p.startLocked(port, outboundIP)
	}
	// 停止状态下也要校验，免得存进去一个启动时才报错的出口 IP
	if outboundIP != "" {
		if _, err := validateOutboundIP(outboundIP); err != nil {
			return err
		}
	}
	p.port = port
	p.outboundIP = outboundIP
	return nil
}

// stopLocked 需持有 p.mu
func (p *ProxyServer) stopLocked() error {
	if p.listener == nil {
		return nil
	}
	if p.closeChan != nil {
		close(p.closeChan)
	}
	err := p.listener.shutdown()
	// 立即置空：后续步骤（如端口被占用）出错提前返回时，
	// 下一次 Start 不会再次 close 同一个已关闭的 channel 而 panic
	p.listener = nil
	p.closeChan = nil
	p.startedAt = time.Time{}
	return err
}

// startLocked 需持有 p.mu
func (p *ProxyServer) startLocked(port string, outboundIP string) error {
	// 先校验出口 IP，校验失败时不动已在运行的代理服务
	var localIP net.IP
	if outboundIP != "" {
		var err error
		localIP, err = validateOutboundIP(outboundIP)
		if err != nil {
			return err
		}
	}

	p.stopLocked()

	conf := &socks5.Config{}

	var dialer *net.Dialer
	if outboundIP != "" {
		dialer = &net.Dialer{
			LocalAddr: &net.TCPAddr{IP: localIP},
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
	} else {
		dialer = &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
	}

	conf.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	srv, err := socks5.New(conf)
	if err != nil {
		return fmt.Errorf("failed to create SOCKS5 server: %v", err)
	}

	addr := fmt.Sprintf("0.0.0.0:%s", port)
	rawListener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", addr, err)
	}

	connIDCounter := int64(0)
	listener := &statsListener{
		Listener:    rawListener,
		connCounter: &connIDCounter,
		conns:       make(map[*MonitoredConn]struct{}),
	}

	closeChan := make(chan struct{})
	p.port = port
	p.outboundIP = outboundIP
	p.startedAt = time.Now()
	p.listener = listener
	p.closeChan = closeChan

	go func() {
		log.Printf("[SOCKS5] Starting SOCKS5 proxy server on %s (Outbound IP: %s)", addr, func() string {
			if outboundIP == "" {
				return "Default"
			}
			return outboundIP
		}())
		if err := srv.Serve(listener); err != nil {
			select {
			case <-closeChan:
				return
			default:
				log.Printf("[SOCKS5] Server error: %v", err)
			}
		}
	}()

	return nil
}

type statsListener struct {
	net.Listener
	connCounter *int64

	mu     sync.Mutex
	conns  map[*MonitoredConn]struct{}
	closed bool
}

func (sl *statsListener) Accept() (net.Conn, error) {
	c, err := sl.Listener.Accept()
	if err != nil {
		return nil, err
	}

	id := fmt.Sprintf("conn-%d", atomic.AddInt64(sl.connCounter, 1))
	clientAddr := c.RemoteAddr().String()
	info := stats.AddConnection(id, clientAddr, "SOCKS5 Proxy Tunnel")
	mc := &MonitoredConn{Conn: c, info: info, owner: sl}

	sl.mu.Lock()
	if sl.closed {
		// 与停止操作赛跑时抢到的连接，直接丢弃
		sl.mu.Unlock()
		mc.Close()
		return nil, net.ErrClosed
	}
	sl.conns[mc] = struct{}{}
	sl.mu.Unlock()

	return mc, nil
}

func (sl *statsListener) forget(mc *MonitoredConn) {
	sl.mu.Lock()
	delete(sl.conns, mc)
	sl.mu.Unlock()
}

// shutdown 关掉监听口并断开还在跑的隧道。只关监听口的话已建立的连接会一直
// 转发下去，用户点了「停止」却发现流量还在走，那不叫停止。
func (sl *statsListener) shutdown() error {
	err := sl.Listener.Close()

	sl.mu.Lock()
	sl.closed = true
	live := make([]*MonitoredConn, 0, len(sl.conns))
	for c := range sl.conns {
		live = append(live, c)
	}
	sl.conns = make(map[*MonitoredConn]struct{})
	sl.mu.Unlock()

	for _, c := range live {
		c.Close()
	}
	return err
}

func (p *ProxyServer) GetConfig() (string, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.port, p.outboundIP
}

func (p *ProxyServer) StartedAt() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.startedAt
}

// ---------------------------------------------------------
// OS Route Execution
// ---------------------------------------------------------

// RouteResult 汇总一次添加请求的结果：按域名添加时一个请求会产生多条路由，
// 成功和失败的部分都要如实回报，不能只报一个笼统的成功。
type RouteResult struct {
	Domain     string       `json:"domain,omitempty"`
	ResolvedAt *time.Time   `json:"resolved_at,omitempty"`
	Added      []RouteRule  `json:"added"`
	Failed     []RouteError `json:"failed,omitempty"`
}

type RouteError struct {
	Destination string `json:"destination"`
	Error       string `json:"error"`
}

// AddTarget 接受 IP、CIDR 或域名。域名会先解析成 A 记录，每个 IPv4 下发一条
// 主机路由，并把域名与解析时间一并记录下来。
func (rm *RouterManager) AddTarget(target, gateway, iface string) (*RouteResult, error) {
	target = strings.TrimSpace(target)

	dests, domain, resolvedAt, err := resolveRouteTargets(target)
	if err != nil {
		return nil, err
	}
	if domain != "" {
		log.Printf("[Router] 域名 %s 解析到 %d 个 IPv4: %s", domain, len(dests), strings.Join(dests, ", "))
	}

	// macOS 上必须把路由放进网卡作用域，否则会被克隆路由压掉（见 buildRouteCmd）。
	// 作用域网卡随路由一起记进台账，删除/重新下发时要用同一个。
	if iface == "" {
		iface = routeScopeInterface(gateway)
		if iface != "" {
			log.Printf("[Router] 网关 %s 归属网卡 %s，路由将限定在该网卡作用域内", gateway, iface)
		}
	}

	var domains []string
	if domain != "" {
		domains = []string{domain}
	}

	result := &RouteResult{Domain: domain, ResolvedAt: resolvedAt}
	for _, dest := range dests {
		rule := RouteRule{
			Destination: dest,
			Gateway:     gateway,
			Interface:   iface,
			Domains:     domains,
			ResolvedAt:  resolvedAt,
			CreatedAt:   time.Now(),
		}
		if err := rm.addRoute(rule); err != nil {
			log.Printf("[Router] 添加失败: %s -> %s (来源: %s): %v", dest, gateway, routeOrigin(domains), err)
			result.Failed = append(result.Failed, RouteError{Destination: dest, Error: err.Error()})
			continue
		}
		result.Added = append(result.Added, rule)
	}

	if len(result.Added) == 0 {
		return result, fmt.Errorf("所有目标均添加失败")
	}

	if domain != "" {
		rm.mu.Lock()
		entry, exists := rm.domains[domain]
		if !exists {
			entry = DomainEntry{Domain: domain, CreatedAt: time.Now()}
		}
		entry.Gateway, entry.Interface, entry.LastResolved, entry.LastError = gateway, iface, resolvedAt, ""
		rm.domains[domain] = entry
		rm.persistLocked()
		rm.mu.Unlock()
	}
	return result, nil
}

func (rm *RouterManager) addRoute(rule RouteRule) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// 已有同目标的路由：内核里一个目标只能有一条，只能共用
	if existing, ok := rm.routes[rule.Destination]; ok {
		if existing.Gateway != rule.Gateway {
			return fmt.Errorf("目标 %s 已有一条走网关 %s 的路由（来源: %s），无法再指向 %s；"+
				"请先删除原路由，或给这两者指定同一个网关",
				rule.Destination, existing.Gateway, routeOrigin(existing.Domains), rule.Gateway)
		}
		merged := existing
		for _, d := range rule.Domains {
			if !merged.HasDomain(d) {
				merged.Domains = append(merged.Domains, d)
			}
		}
		sort.Strings(merged.Domains)
		if rule.ResolvedAt != nil {
			merged.ResolvedAt = rule.ResolvedAt
		}
		rm.routes[rule.Destination] = merged
		rm.persistLocked()
		log.Printf("[Router] 复用已有路由: %s -> 网关 %s (现归属: %s)",
			merged.Destination, merged.Gateway, routeOrigin(merged.Domains))
		return nil
	}

	if err := execOSRoute("add", rule.Destination, rule.Gateway, rule.Interface); err != nil {
		// 内核里已经有这条了（别处加的或上次没记上），当成成功并接管记账
		if !isRouteExistsError(err) {
			return fmt.Errorf("failed to add OS route: %v", err)
		}
		log.Printf("[Router] 内核中已存在 %s 的路由，纳入台账管理", rule.Destination)
	}

	rm.routes[rule.Destination] = rule
	rm.persistLocked()
	log.Printf("[Router] 已添加路由: %s -> 网关 %s (来源: %s)",
		rule.Destination, rule.Gateway, routeOrigin(rule.Domains))
	return nil
}

// isRouteMissingError 判断"内核里本来就没有这条路由"这类错误。
// macOS: not in table；Linux: RTNETLINK answers: No such process。
func isRouteMissingError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not in table") || strings.Contains(msg, "no such process") ||
		strings.Contains(msg, "element not found")
}

// isRouteExistsError 判断"这条路由内核里已经有了"这类错误。
// macOS/Linux 都是 File exists，Windows 是 The object already exists。
func isRouteExistsError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "file exists") || strings.Contains(msg, "already exists")
}

// SetPaused 暂停/恢复若干条路由。暂停 = 从内核撤下但保留台账，随时可恢复。
// destinations 为空表示全部。
func (rm *RouterManager) SetPaused(destinations []string, paused bool) (changed []string, failed []RouteError) {
	rm.mu.Lock()
	targets := make([]RouteRule, 0)
	if len(destinations) == 0 {
		for _, r := range rm.routes {
			targets = append(targets, r)
		}
	} else {
		for _, dest := range destinations {
			if r, ok := rm.routes[dest]; ok {
				targets = append(targets, r)
			} else {
				failed = append(failed, RouteError{Destination: dest, Error: "台账中没有这条记录"})
			}
		}
	}
	rm.mu.Unlock()

	sort.Slice(targets, func(i, j int) bool { return targets[i].Destination < targets[j].Destination })

	action, verb := "del", "暂停"
	if !paused {
		action, verb = "add", "恢复"
	}

	for _, r := range targets {
		if r.Paused == paused {
			continue // 已经是目标状态
		}
		if err := execOSRoute(action, r.Destination, r.Gateway, r.Interface); err != nil {
			// 暂停时内核里本来就没有、恢复时内核里已经有了，都视为已达目标状态
			tolerable := (paused && isRouteMissingError(err)) || (!paused && isRouteExistsError(err))
			if !tolerable {
				log.Printf("[Router] %s路由失败 %s: %v", verb, r.Destination, err)
				failed = append(failed, RouteError{Destination: r.Destination, Error: err.Error()})
				continue
			}
		}

		rm.mu.Lock()
		if cur, ok := rm.routes[r.Destination]; ok {
			cur.Paused = paused
			if paused {
				now := time.Now()
				cur.PausedAt = &now
			} else {
				cur.PausedAt = nil
			}
			rm.routes[r.Destination] = cur
		}
		rm.persistLocked()
		rm.mu.Unlock()

		log.Printf("[Router] 已%s路由: %s -> %s (来源: %s)", verb, r.Destination, r.Gateway, routeOrigin(r.Domains))
		changed = append(changed, r.Destination)
	}

	// 全部暂停时连同域名一起暂停，否则定时重新解析会把路由又加回来。
	// 有路由没能操作成功时不改域名状态，避免"域名显示已暂停、路由却还生效"
	if len(destinations) == 0 && len(failed) > 0 {
		log.Printf("[Router] 有 %d 条路由%s失败，域名的定时重新解析维持原状", len(failed), verb)
	}
	if len(destinations) == 0 && len(failed) == 0 {
		rm.mu.Lock()
		for name, entry := range rm.domains {
			entry.Paused = paused
			rm.domains[name] = entry
		}
		rm.persistLocked()
		rm.mu.Unlock()
		log.Printf("[Router] 已%s全部托管域名的定时重新解析", verb)
	}

	return changed, failed
}

// SetDomainPaused 暂停/恢复某个域名：它的路由全部撤下/重下，并停止/恢复定时重新解析。
func (rm *RouterManager) SetDomainPaused(domain string, paused bool) ([]string, []RouteError, error) {
	rm.mu.Lock()
	entry, ok := rm.domains[domain]
	dests := make([]string, 0)
	for dest, rule := range rm.routes {
		if rule.HasDomain(domain) {
			dests = append(dests, dest)
		}
	}
	if ok {
		entry.Paused = paused
		rm.domains[domain] = entry
		rm.persistLocked()
	}
	rm.mu.Unlock()

	if !ok {
		return nil, nil, fmt.Errorf("没有找到托管的域名 %s", domain)
	}

	changed, failed := rm.SetPaused(dests, paused)
	verb := "暂停"
	if !paused {
		verb = "恢复"
	}
	log.Printf("[Router] 域名 %s 已%s（%d 条路由）", domain, verb, len(changed))
	return changed, failed, nil
}

// releaseRoute 让某个域名放弃一条路由：还有别的域名在用就只改归属，
// 最后一个持有者撤走时才真正从内核删除。
func (rm *RouterManager) releaseRoute(destination, domain string) (deleted bool, err error) {
	rm.mu.Lock()
	rule, ok := rm.routes[destination]
	if !ok {
		rm.mu.Unlock()
		return false, fmt.Errorf("route for destination %s not found", destination)
	}

	remaining := make([]string, 0, len(rule.Domains))
	for _, d := range rule.Domains {
		if d != domain {
			remaining = append(remaining, d)
		}
	}
	if len(remaining) > 0 {
		rule.Domains = remaining
		rm.routes[destination] = rule
		rm.persistLocked()
		rm.mu.Unlock()
		log.Printf("[Router] %s 不再由域名 %s 持有，仍被 %s 使用，保留内核路由",
			destination, domain, routeOrigin(remaining))
		return false, nil
	}
	rm.mu.Unlock()

	return true, rm.DeleteRoute(destination)
}

// routeScopeInterface 判断网关应当归属哪块网卡。
//
// macOS 只有把路由加进网卡作用域（-ifscope）才不会被默认路由克隆出来的表项压掉，
// 所以必须先确定网卡。同一网段可能同时存在于多块网卡上（例如 en0 和 en7 都是
// 192.168.10.0/24），此时优先选"系统配置里上游路由器正好就是该网关"的那块。
// 其他系统不需要作用域，返回空串。
func routeScopeInterface(gateway string) string {
	if runtime.GOOS != "darwin" {
		return ""
	}

	gw := net.ParseIP(gateway)
	if gw == nil {
		return ""
	}

	var fallback string
	for _, iface := range GetLocalInterfaces() {
		if iface.Loopback {
			continue
		}
		// 系统就是把这个网关配给这块网卡的，最可靠
		if iface.Gateway == gateway {
			return iface.Name
		}
		if fallback != "" {
			continue
		}
		if _, ipNet, err := net.ParseCIDR(iface.CIDR); err == nil && ipNet.Contains(gw) {
			fallback = iface.Name // 网段能覆盖该网关，作为备选
		}
	}
	return fallback
}

func (rm *RouterManager) DeleteRoute(destination string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rule, exists := rm.routes[destination]
	if !exists {
		return fmt.Errorf("route for destination %s not found", destination)
	}

	err := execOSRoute("del", rule.Destination, rule.Gateway, rule.Interface)
	if err != nil {
		log.Printf("[Router] 警告: 删除内核路由失败 %s: %v", destination, err)
	}

	delete(rm.routes, destination)
	rm.persistLocked()
	log.Printf("[Router] 已删除路由: %s (来源: %s)", destination, routeOrigin(rule.Domains))
	return nil
}

// DomainRefreshResult 记录一次重新解析带来的变化
type DomainRefreshResult struct {
	Domain     string       `json:"domain"`
	ResolvedAt time.Time    `json:"resolved_at"`
	Gateway    string       `json:"gateway"`
	Current    []string     `json:"current"`           // 本次解析到的全部 IP
	Added      []string     `json:"added,omitempty"`   // 新增的
	Removed    []string     `json:"removed,omitempty"` // 已不再解析到、被撤下的
	Kept       []string     `json:"kept,omitempty"`    // 不变的
	Failed     []RouteError `json:"failed,omitempty"`
}

// RefreshDomain 重新解析域名并让内核路由与最新的 A 记录对齐。
// CDN 域名的 IP 会轮换，所以变化必须逐条记录下来。
func (rm *RouterManager) RefreshDomain(domain string) (*DomainRefreshResult, error) {
	rm.mu.Lock()
	existing := make(map[string]RouteRule)
	for dest, rule := range rm.routes {
		if rule.HasDomain(domain) {
			existing[dest] = rule
		}
	}
	entry, hasEntry := rm.domains[domain]
	rm.mu.Unlock()

	if hasEntry && entry.Paused {
		return nil, fmt.Errorf("域名 %s 已暂停，请先恢复再重新解析", domain)
	}

	// 网关以域名记录为准；老台账没有域名记录时回落到现有路由
	gateway, iface := entry.Gateway, entry.Interface
	if !hasEntry {
		if len(existing) == 0 {
			return nil, fmt.Errorf("没有找到域名 %s 对应的路由", domain)
		}
		for _, rule := range existing {
			gateway, iface = rule.Gateway, rule.Interface
			break
		}
	}

	dests, _, resolvedAt, err := resolveRouteTargets(domain)
	if err != nil {
		// 解析失败要记下来，界面上能看到某个域名一直在失败
		rm.mu.Lock()
		if e, ok := rm.domains[domain]; ok {
			e.LastError = err.Error()
			rm.domains[domain] = e
			rm.persistLocked()
		}
		rm.mu.Unlock()
		return nil, err
	}

	result := &DomainRefreshResult{
		Domain: domain, ResolvedAt: *resolvedAt, Gateway: gateway, Current: dests,
	}
	current := make(map[string]bool, len(dests))
	for _, dest := range dests {
		current[dest] = true
	}

	// 新增：这次解析到、但之前没有的
	for _, dest := range dests {
		if _, ok := existing[dest]; ok {
			result.Kept = append(result.Kept, dest)
			continue
		}
		rule := RouteRule{
			Destination: dest, Gateway: gateway, Interface: iface,
			Domains: []string{domain}, ResolvedAt: resolvedAt, CreatedAt: time.Now(),
		}
		if err := rm.addRoute(rule); err != nil {
			result.Failed = append(result.Failed, RouteError{Destination: dest, Error: err.Error()})
			continue
		}
		result.Added = append(result.Added, dest)
	}

	// 撤下：之前有、这次解析不到的
	removed := make([]string, 0)
	for dest := range existing {
		if !current[dest] {
			removed = append(removed, dest)
		}
	}
	sort.Strings(removed)

	// 保护：新 IP 一条都没加成功却要撤掉全部旧 IP，会让这个域名直接断流。
	// 宁可留着可能过期的旧路由，等下一轮再试。
	if len(result.Added) == 0 && len(result.Failed) > 0 && len(removed) >= len(existing) {
		log.Printf("[Router] 域名 %s: 新 IP 全部添加失败，暂不撤下现有 %d 条旧路由，等下一轮重试",
			domain, len(existing))
		removed = nil
	}

	for _, dest := range removed {
		if _, err := rm.releaseRoute(dest, domain); err != nil {
			result.Failed = append(result.Failed, RouteError{Destination: dest, Error: err.Error()})
			continue
		}
		result.Removed = append(result.Removed, dest)
	}

	// 保留下来的条目也要刷新解析时间，台账才反映"最近一次确认"
	rm.mu.Lock()
	for _, dest := range result.Kept {
		if rule, ok := rm.routes[dest]; ok {
			rule.ResolvedAt = resolvedAt
			rm.routes[dest] = rule
		}
	}
	if e, ok := rm.domains[domain]; ok {
		e.LastResolved = resolvedAt
		e.LastError = ""
		if len(result.Failed) > 0 {
			e.LastError = fmt.Sprintf("%d 条操作失败，最近一条: %s", len(result.Failed), result.Failed[0].Error)
		}
		rm.domains[domain] = e
	}
	rm.persistLocked()
	rm.mu.Unlock()

	// 定时刷新每轮都打日志会刷屏，只有真的变了才记
	if len(result.Added) > 0 || len(result.Removed) > 0 || len(result.Failed) > 0 {
		log.Printf("[Router] 域名 %s 重新解析: 共 %d 个 IP (新增 %d, 撤下 %d, 不变 %d, 失败 %d)",
			domain, len(dests), len(result.Added), len(result.Removed), len(result.Kept), len(result.Failed))
		if len(result.Added) > 0 {
			log.Printf("[Router]   新增: %s", strings.Join(result.Added, ", "))
		}
		if len(result.Removed) > 0 {
			log.Printf("[Router]   撤下: %s", strings.Join(result.Removed, ", "))
		}
	}
	return result, nil
}

// ListDomains 返回台账里出现过的所有域名
func (rm *RouterManager) ListDomains() []string {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	seen := make(map[string]bool)
	domains := make([]string, 0)
	for domain := range rm.domains {
		seen[domain] = true
		domains = append(domains, domain)
	}
	// 老台账没有域名记录，从路由条目里补
	for _, rule := range rm.routes {
		for _, d := range rule.Domains {
			if !seen[d] {
				seen[d] = true
				domains = append(domains, d)
			}
		}
	}
	sort.Strings(domains)
	return domains
}

func (rm *RouterManager) IsDomainPaused(domain string) bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return rm.domains[domain].Paused
}

// ListDomainEntries 返回被托管的域名记录（含最近一次解析时间与错误）
func (rm *RouterManager) ListDomainEntries() []DomainEntry {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	list := make([]DomainEntry, 0, len(rm.domains))
	for _, e := range rm.domains {
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Domain < list[j].Domain })
	return list
}

// domainRefreshInterval 为 0 表示关闭自动重新解析
var domainRefreshInterval time.Duration

// startDomainRefresher 定期重新解析域名路由。CDN 域名的 A 记录随时会换，
// 加完就不管的话路由很快就指向一批没人用的 IP。
func startDomainRefresher(interval time.Duration) {
	domainRefreshInterval = interval
	if interval <= 0 {
		log.Printf("[Router] 域名路由自动重新解析: 已关闭")
		return
	}
	log.Printf("[Router] 域名路由自动重新解析: 每 %s 一次", interval)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			refreshAllDomains()
		}
	}()
}

func refreshAllDomains() {
	for _, domain := range manager.ListDomains() {
		if manager.IsDomainPaused(domain) {
			continue // 已暂停的域名不参与定时重新解析
		}
		if _, err := manager.RefreshDomain(domain); err != nil {
			// 解析失败时保持现状，绝不能因为一次 DNS 抖动就把路由全撤了
			log.Printf("[Router] 自动重新解析 %s 失败，保留现有路由: %v", domain, err)
		}
	}
}

// DeleteDomain 删除某个域名解析出来的全部路由。
func (rm *RouterManager) DeleteDomain(domain string) (int, error) {
	rm.mu.Lock()
	dests := make([]string, 0)
	for dest, rule := range rm.routes {
		if rule.HasDomain(domain) {
			dests = append(dests, dest)
		}
	}
	rm.mu.Unlock()

	// 先摘掉域名记录，避免刚删完又被定时刷新加回来
	rm.mu.Lock()
	_, tracked := rm.domains[domain]
	delete(rm.domains, domain)
	if tracked {
		rm.persistLocked()
	}
	rm.mu.Unlock()

	if len(dests) == 0 {
		if tracked {
			log.Printf("[Router] 已取消托管域名 %s（当时没有对应的路由）", domain)
			return 0, nil
		}
		return 0, fmt.Errorf("没有找到域名 %s 对应的路由", domain)
	}

	sort.Strings(dests)
	deleted, released := 0, 0
	for _, dest := range dests {
		removed, err := rm.releaseRoute(dest, domain)
		if err != nil {
			log.Printf("[Router] 警告: 释放 %s 失败: %v", dest, err)
			continue
		}
		if removed {
			deleted++
		} else {
			released++ // 还有别的域名在用，内核路由保留
		}
	}
	log.Printf("[Router] 域名 %s: 删除 %d 条路由，%d 条因被其他域名共用而保留", domain, deleted, released)
	return deleted, nil
}

// resolveRouteTargets 把用户输入的目标转换成待下发的 CIDR 列表。
// 输入是域名时返回域名本身与解析时间，供上层记录。
func resolveRouteTargets(target string) (dests []string, domain string, resolvedAt *time.Time, err error) {
	if target == "" {
		return nil, "", nil, fmt.Errorf("目标不能为空")
	}

	// 先按 IP / CIDR 处理
	if cidr, cidrErr := normalizeDestination(target); cidrErr == nil {
		return []string{cidr}, "", nil, nil
	} else if looksLikeIPOrCIDR(target) {
		// 形如 IP/CIDR 但不合法（例如 IPv6 或掩码越界），直接报错，别当域名去解析
		return nil, "", nil, cidrErr
	}

	if !isValidDomain(target) {
		return nil, "", nil, fmt.Errorf("目标 %q 既不是合法的 IP/网段，也不是合法的域名", target)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, lookupErr := net.DefaultResolver.LookupIPAddr(ctx, target)
	if lookupErr != nil {
		return nil, "", nil, fmt.Errorf("域名 %s 解析失败: %v", target, lookupErr)
	}

	now := time.Now()
	resolvedAt = &now
	seen := make(map[string]bool)
	for _, addr := range addrs {
		ip4 := addr.IP.To4()
		if ip4 == nil {
			continue // 内核路由这里只处理 IPv4
		}
		cidr := ip4.String() + "/32"
		if seen[cidr] {
			continue
		}
		seen[cidr] = true
		dests = append(dests, cidr)
	}
	if len(dests) == 0 {
		return nil, "", nil, fmt.Errorf("域名 %s 没有解析到任何 IPv4 地址", target)
	}
	sort.Strings(dests)

	return dests, target, resolvedAt, nil
}

// normalizeDestination 把 IP 或 CIDR 统一成网络地址形式的 CIDR（192.168.2.5/24 -> 192.168.2.0/24）。
func normalizeDestination(target string) (string, error) {
	if ip := net.ParseIP(target); ip != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			return "", fmt.Errorf("暂不支持 IPv6 目标: %s", target)
		}
		return ip4.String() + "/32", nil
	}

	ip, ipNet, err := net.ParseCIDR(target)
	if err != nil {
		return "", fmt.Errorf("无法解析目标网段 %q: %v", target, err)
	}
	if ip.To4() == nil {
		return "", fmt.Errorf("暂不支持 IPv6 目标: %s", target)
	}
	return ipNet.String(), nil
}

func looksLikeIPOrCIDR(target string) bool {
	return strings.Contains(target, "/") || strings.Contains(target, ":") ||
		strings.IndexFunc(target, func(r rune) bool {
			return (r < '0' || r > '9') && r != '.'
		}) < 0
}

func isValidDomain(target string) bool {
	if len(target) > 253 || !strings.Contains(target, ".") {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(target, "."), ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			isAlnum := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
			if !isAlnum && r != '-' && r != '_' {
				return false
			}
		}
	}
	return true
}

// ---------------------------------------------------------
// 路由台账：持久化 + 启动对账
//
// 内核路由表里没有"谁加的"这种信息，所以本程序下发的每一条都写进台账文件；
// 重启后拿台账和内核路由表对一遍，就能分清哪些还在、哪些已经失效。
// Linux 上额外给路由打 proto 标记，台账丢了也还能认出来。
// ---------------------------------------------------------

const (
	routeStateVersion = 1
	// Linux 自定义路由协议号，用于标记"本程序下发"，可用 ip route show proto 210 查看
	linuxRouteProto = "210"
)

type routeState struct {
	Version int           `json:"version"`
	SavedAt time.Time     `json:"saved_at"`
	Routes  []RouteRule   `json:"routes"`
	Domains []DomainEntry `json:"domains,omitempty"`
}

// stateFilePath 为空表示未启用持久化（写入失败时会降级到这种状态）
var stateFilePath string

// resolveStateFile 决定台账落在哪里：显式指定 > 系统级目录 > 用户目录。
func resolveStateFile(flagVal string) string {
	if flagVal != "" {
		if err := ensureStateDir(flagVal); err != nil {
			log.Printf("[State] 无法使用指定的台账文件 %s: %v，本次运行不持久化路由", flagVal, err)
			return ""
		}
		return flagVal
	}

	candidates := []string{filepath.Join("/var/lib/lan-proxy", "routes.json")}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates, filepath.Join(home, ".lan-proxy", "routes.json"))
	}
	candidates = append(candidates, "lan-proxy-routes.json")

	for _, c := range candidates {
		if err := ensureStateDir(c); err == nil {
			return c
		}
	}
	log.Printf("[State] 所有候选台账路径均不可写，本次运行不持久化路由")
	return ""
}

func ensureStateDir(path string) error {
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	// 试写一次，避免"目录能建但文件写不了"的情况到添加路由时才暴露
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	return f.Close()
}

// persistLocked 调用方必须已持有 rm.mu
func (rm *RouterManager) persistLocked() {
	if stateFilePath == "" {
		return
	}

	list := make([]RouteRule, 0, len(rm.routes))
	for _, r := range rm.routes {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Destination < list[j].Destination })

	domains := make([]DomainEntry, 0, len(rm.domains))
	for _, e := range rm.domains {
		domains = append(domains, e)
	}
	sort.Slice(domains, func(i, j int) bool { return domains[i].Domain < domains[j].Domain })

	data, err := json.MarshalIndent(routeState{
		Version: routeStateVersion,
		SavedAt: time.Now(),
		Routes:  list,
		Domains: domains,
	}, "", "  ")
	if err != nil {
		log.Printf("[State] 序列化台账失败: %v", err)
		return
	}

	// 先写临时文件再原子替换，避免掉电/崩溃留下半个文件
	tmp := stateFilePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		log.Printf("[State] 写入台账失败 %s: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, stateFilePath); err != nil {
		log.Printf("[State] 替换台账失败 %s: %v", stateFilePath, err)
	}
}

// LoadState 读取台账并与内核路由表对账，返回载入条数与已失效的条目。
func (rm *RouterManager) LoadState() (loaded int, missing []RouteRule) {
	if stateFilePath == "" {
		return 0, nil
	}

	data, err := os.ReadFile(stateFilePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[State] 读取台账失败 %s: %v", stateFilePath, err)
		}
		return 0, nil
	}
	if len(data) == 0 {
		return 0, nil
	}

	var state routeState
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("[State] 台账文件损坏 %s: %v（本次忽略，不会覆盖，请手动检查）", stateFilePath, err)
		stateFilePath = "" // 不要用空台账把用户的记录覆盖掉
		return 0, nil
	}

	kernel, kernelErr := kernelRouteTable()

	rm.mu.Lock()
	for _, r := range state.Routes {
		// 旧台账的单域名字段迁移到归属集合
		if r.LegacyDomain != "" && len(r.Domains) == 0 {
			r.Domains = []string{r.LegacyDomain}
		}
		r.LegacyDomain = ""
		rm.routes[r.Destination] = r
	}
	for _, d := range state.Domains {
		rm.domains[d.Domain] = d
	}
	// 老台账没有 domains 段，从路由条目里重建，否则这些域名不会被自动刷新
	for _, r := range rm.routes {
		for _, d := range r.Domains {
			if _, ok := rm.domains[d]; !ok {
				rm.domains[d] = DomainEntry{
					Domain: d, Gateway: r.Gateway, Interface: r.Interface,
					LastResolved: r.ResolvedAt, CreatedAt: r.CreatedAt,
				}
			}
		}
	}
	loaded = len(rm.routes)
	domainCount := len(rm.domains)
	rm.mu.Unlock()
	if domainCount > 0 {
		log.Printf("[State] 托管域名 %d 个", domainCount)
	}

	if kernelErr != nil {
		log.Printf("[State] 已载入 %d 条台账记录，但无法读取内核路由表进行对账: %v", loaded, kernelErr)
		return loaded, nil
	}

	for _, r := range state.Routes {
		if r.Paused {
			continue // 暂停的本来就不该在内核里
		}
		if !kernelHasRoute(kernel, r.Destination, r.Gateway) {
			missing = append(missing, r)
		}
	}

	log.Printf("[State] 台账 %s: 载入 %d 条，其中 %d 条已不在内核路由表中",
		stateFilePath, loaded, len(missing))
	for _, r := range missing {
		log.Printf("[State]   失效: %s -> %s (来源: %s, 添加于 %s)",
			r.Destination, r.Gateway, routeOrigin(r.Domains), r.CreatedAt.Format(time.RFC3339))
	}
	return loaded, missing
}

// RestoreRoutes 重新下发指定的路由（destinations 为空表示重下所有失效的）。
func (rm *RouterManager) RestoreRoutes(destinations []string) (restored []string, failed []RouteError) {
	rm.mu.Lock()
	targets := make([]RouteRule, 0, len(destinations))
	if len(destinations) == 0 {
		for _, r := range rm.routes {
			targets = append(targets, r)
		}
	} else {
		for _, dest := range destinations {
			if r, ok := rm.routes[dest]; ok {
				targets = append(targets, r)
			} else {
				failed = append(failed, RouteError{Destination: dest, Error: "台账中没有这条记录"})
			}
		}
	}
	rm.mu.Unlock()

	sort.Slice(targets, func(i, j int) bool { return targets[i].Destination < targets[j].Destination })

	kernel, _ := kernelRouteTable()
	for _, r := range targets {
		if r.Paused {
			continue // 暂停中的不要重新下发
		}
		if kernel != nil && kernelHasRoute(kernel, r.Destination, r.Gateway) {
			continue // 已经在内核里，不重复下发
		}
		if err := execOSRoute("add", r.Destination, r.Gateway, r.Interface); err != nil {
			log.Printf("[State] 重新下发失败 %s -> %s: %v", r.Destination, r.Gateway, err)
			failed = append(failed, RouteError{Destination: r.Destination, Error: err.Error()})
			continue
		}
		log.Printf("[State] 已重新下发: %s -> %s (来源: %s)", r.Destination, r.Gateway, routeOrigin(r.Domains))
		restored = append(restored, r.Destination)
	}
	return restored, failed
}

func (rm *RouterManager) ListRoutes() []RouteRule {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	list := make([]RouteRule, 0, len(rm.routes))
	for _, r := range rm.routes {
		list = append(list, r)
	}

	// 手动添加的排在前面，域名解析出来的按首个域名聚在一起，方便界面分组展示
	primary := func(r RouteRule) string {
		if len(r.Domains) == 0 {
			return ""
		}
		return r.Domains[0]
	}
	sort.Slice(list, func(i, j int) bool {
		pi, pj := primary(list[i]), primary(list[j])
		if (pi == "") != (pj == "") {
			return pi == ""
		}
		if pi != pj {
			return pi < pj
		}
		return list[i].Destination < list[j].Destination
	})
	return list
}

// execOSRoute 下发/删除内核路由。dest 必须是 normalizeDestination 归一化后的
// CIDR：域名解析出来的是 /32 主机路由，各平台的写法与网段路由并不相同。
// ---------------------------------------------------------
// 内核路由表解析（用于对账）
// ---------------------------------------------------------

// kernelRoute 是从系统路由表里解析出来的一条记录
type kernelRoute struct {
	Destination string // 归一化后的 CIDR
	Gateway     string
	Ours        bool // Linux 上带本程序 proto 标记
}

func kernelRouteTable() ([]kernelRoute, error) {
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("ip", "route", "show").CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("%v (%s)", err, strings.TrimSpace(string(out)))
		}
		return parseLinuxRoutes(string(out)), nil
	case "darwin":
		out, err := exec.Command("netstat", "-nrf", "inet").CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("%v (%s)", err, strings.TrimSpace(string(out)))
		}
		return parseDarwinRoutes(string(out)), nil
	default:
		return nil, fmt.Errorf("%s 暂不支持路由对账", runtime.GOOS)
	}
}

func kernelHasRoute(table []kernelRoute, dest, gateway string) bool {
	for _, r := range table {
		if r.Destination == dest && r.Gateway == gateway {
			return true
		}
	}
	return false
}

// parseLinuxRoutes 解析 ip route show：
//
//	104.20.23.154 via 192.168.1.1 dev eth0 proto 210
//	192.168.2.0/24 via 192.168.1.254 dev eth0
func parseLinuxRoutes(out string) []kernelRoute {
	var result []kernelRoute
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] == "default" {
			continue
		}
		dest, ok := normalizeKernelDest(fields[0])
		if !ok {
			continue
		}
		entry := kernelRoute{Destination: dest}
		for i := 1; i < len(fields)-1; i++ {
			switch fields[i] {
			case "via":
				entry.Gateway = fields[i+1]
			case "proto":
				entry.Ours = fields[i+1] == linuxRouteProto
			}
		}
		if entry.Gateway == "" {
			continue // 直连路由，不是本程序下发的形态
		}
		result = append(result, entry)
	}
	return result
}

// parseDarwinRoutes 解析 netstat -nrf inet：
//
//	Destination        Gateway            Flags     Netif
//	192.168.2          192.168.1.254      UGSc      en0
//	104.20.23.154      192.168.10.249     UGHS      en0
func parseDarwinRoutes(out string) []kernelRoute {
	var result []kernelRoute
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] == "default" || fields[0] == "Destination" {
			continue
		}
		dest, ok := normalizeKernelDest(fields[0])
		if !ok {
			continue
		}
		if net.ParseIP(fields[1]) == nil {
			continue // link#16 / MAC 之类的直连表项
		}
		result = append(result, kernelRoute{Destination: dest, Gateway: fields[1]})
	}
	return result
}

// normalizeKernelDest 把路由表里的目标写法统一成 CIDR。
// BSD/macOS 会省略掩码与末尾的 0：192.168.2 表示 192.168.2.0/24，
// 172.20.0/23 表示 172.20.0.0/23，裸 IP 表示 /32。
func normalizeKernelDest(token string) (string, bool) {
	addr, mask := token, ""
	if i := strings.Index(token, "/"); i >= 0 {
		addr, mask = token[:i], token[i+1:]
	}

	octets := strings.Split(addr, ".")
	if len(octets) == 0 || len(octets) > 4 || strings.Contains(addr, ":") {
		return "", false
	}
	implied := len(octets) * 8
	for len(octets) < 4 {
		octets = append(octets, "0")
	}
	full := strings.Join(octets, ".")
	if net.ParseIP(full) == nil {
		return "", false
	}
	if mask == "" {
		mask = fmt.Sprintf("%d", implied)
		if implied == 32 {
			mask = "32"
		}
	}

	_, ipNet, err := net.ParseCIDR(full + "/" + mask)
	if err != nil {
		return "", false
	}
	return ipNet.String(), true
}

func execOSRoute(action, dest, gateway, iface string) error {
	// 老台账里的记录没有作用域网卡，删除/重下时补一次，保证与添加时用的一致
	if iface == "" {
		iface = routeScopeInterface(gateway)
	}

	cmd, err := buildRouteCmd(runtime.GOOS, action, dest, gateway, iface)
	if err != nil {
		return err
	}

	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}

	// busybox 等精简版 ip 命令可能不认 proto 参数，去掉标记重试一次
	if runtime.GOOS == "linux" && action == "add" && strings.Contains(strings.ToLower(string(output)), "proto") {
		log.Printf("[Router] ip 不支持 proto 标记，去掉后重试: %s", strings.TrimSpace(string(output)))
		args := cmd.Args[1 : len(cmd.Args)-2] // 去掉末尾的 proto <N>
		retry := exec.Command("ip", args...)
		if retryOut, retryErr := retry.CombinedOutput(); retryErr == nil {
			return nil
		} else {
			output, err = retryOut, retryErr
		}
	}

	return fmt.Errorf("%s (output: %s)", err, string(output))
}

// buildRouteCmd 组装各平台的路由命令。单独拆出来是因为真正执行需要 root，
// 只有把命令构造独立出来才能被测试覆盖。
func buildRouteCmd(osName, action, dest, gateway, iface string) (*exec.Cmd, error) {
	ip, ipNet, err := net.ParseCIDR(dest)
	if err != nil {
		return nil, fmt.Errorf("非法的路由目标 %q: %v", dest, err)
	}
	ones, _ := ipNet.Mask.Size()
	isHost := ones == 32

	var cmd *exec.Cmd
	switch osName {
	case "linux":
		// ip route 本身就接受 CIDR，主机路由写成 x.x.x.x/32 即可
		verb := "add"
		if action != "add" {
			verb = "del"
		}
		args := []string{"route", verb, dest, "via", gateway}
		if verb == "add" {
			if iface != "" {
				args = append(args, "dev", iface)
			}
			// 打上标记，日后 ip route show proto 210 就能认出是本程序加的
			args = append(args, "proto", linuxRouteProto)
		}
		cmd = exec.Command("ip", args...)
	case "darwin":
		verb := "add"
		if action != "add" {
			verb = "delete"
		}
		args := []string{"-n", verb}
		if isHost {
			args = append(args, "-host", ip.String(), gateway)
		} else {
			args = append(args, "-net", dest, gateway)
		}
		// 不加 -ifscope 的话，这条全局路由会被 en0 作用域里从默认路由克隆出来的
		// 表项（WASCLONED）压掉：路由表里看得见，实际流量却还是走默认网关。
		if iface != "" {
			args = append(args, "-ifscope", iface)
		}
		cmd = exec.Command("route", args...)
	case "windows":
		mask := net.IP(ipNet.Mask).String()
		if action == "add" {
			cmd = exec.Command("route", "ADD", ipNet.IP.String(), "MASK", mask, gateway)
		} else {
			cmd = exec.Command("route", "DELETE", ipNet.IP.String(), "MASK", mask, gateway)
		}
	default:
		return nil, fmt.Errorf("unsupported operating system: %s", osName)
	}

	return cmd, nil
}

func GetSystemRoutes() []string {
	osName := runtime.GOOS
	var cmd *exec.Cmd

	switch osName {
	case "linux":
		cmd = exec.Command("ip", "route", "show")
	case "darwin":
		cmd = exec.Command("netstat", "-nr")
	case "windows":
		cmd = exec.Command("route", "print")
	default:
		return []string{"Unsupported OS for system routes"}
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return []string{fmt.Sprintf("Failed to get system routes: %v", err)}
	}

	lines := strings.Split(string(output), "\n")
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// ---------------------------------------------------------
// Local Interface Discovery
// ---------------------------------------------------------

type InterfaceInfo struct {
	Name     string `json:"name"`
	IP       string `json:"ip"`
	CIDR     string `json:"cidr"`
	MAC      string `json:"mac,omitempty"`
	Gateway  string `json:"gateway,omitempty"`
	Loopback bool   `json:"loopback"`
}

// GetLocalInterfaces returns every usable (UP) IPv4 address of the local
// machine, so the Web UI can offer them as SOCKS5 outbound bind candidates.
func GetLocalInterfaces() []InterfaceInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("[Interfaces] Failed to list interfaces: %v", err)
		return []InterfaceInfo{}
	}

	list := make([]InterfaceInfo, 0, len(ifaces))

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil {
				continue // only IPv4 can be bound as outbound here
			}
			ones, _ := ipNet.Mask.Size()
			list = append(list, InterfaceInfo{
				Name:     iface.Name,
				IP:       ip4.String(),
				CIDR:     fmt.Sprintf("%s/%d", ip4.String(), ones),
				MAC:      iface.HardwareAddr.String(),
				Loopback: iface.Flags&net.FlagLoopback != 0,
			})
		}
	}

	resolveGateways(list)

	// Physical/usable NICs first, loopback last.
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Loopback != list[j].Loopback {
			return !list[i].Loopback
		}
		if (list[i].Gateway != "") != (list[j].Gateway != "") {
			return list[i].Gateway != ""
		}
		return list[i].Name < list[j].Name
	})

	return list
}

// validateOutboundIP checks that the requested SOCKS5 outbound address is an
// IPv4 address actually configured on one of this machine's interfaces —
// binding to anything else would fail later at dial time with an opaque error.
func validateOutboundIP(outboundIP string) (net.IP, error) {
	ip := net.ParseIP(outboundIP)
	if ip == nil {
		return nil, fmt.Errorf("出口 IP %q 不是合法的 IP 地址", outboundIP)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("出口 IP %s 不是 IPv4 地址，暂不支持绑定 IPv6 出口", outboundIP)
	}

	list := GetLocalInterfaces()
	for _, iface := range list {
		if iface.IP == ip4.String() {
			return ip4, nil
		}
	}

	available := make([]string, 0, len(list))
	for _, iface := range list {
		available = append(available, fmt.Sprintf("%s(%s)", iface.IP, iface.Name))
	}
	if len(available) == 0 {
		return nil, fmt.Errorf("出口 IP %s 不属于本机任何网卡（未检测到可用的本机 IPv4 网卡）", outboundIP)
	}
	return nil, fmt.Errorf("出口 IP %s 不属于本机任何网卡，可用的本机 IP: %s", outboundIP, strings.Join(available, ", "))
}

// resolveGateways fills in the Gateway field of each entry.
//
// The lookup is per IP address, not per interface: one NIC can carry several
// addresses belonging to different upstream routers (macOS 的多个网络服务、
// Linux 的 source-based policy routing), and binding to each address egresses
// through its own gateway.
func resolveGateways(list []InterfaceInfo) {
	byIP := gatewaysByIP(list)
	byIface := defaultGatewaysByInterface()

	for i := range list {
		if gw := byIP[list[i].IP]; gw != "" {
			list[i].Gateway = gw
			continue
		}
		list[i].Gateway = byIface[list[i].Name]
	}
}

// gatewaysByIP maps local IPv4 address -> gateway actually used when traffic is
// sourced from that address. Best effort: an empty map just falls back to the
// per-interface default route.
func gatewaysByIP(list []InterfaceInfo) map[string]string {
	switch runtime.GOOS {
	case "darwin":
		return darwinServiceGateways()
	case "linux":
		return linuxSourceGateways(list)
	}
	return map[string]string{}
}

// darwinServiceGateways reads每个网络服务的 IPv4 配置 (scutil)，得到
// 地址 -> Router 的映射。macOS 允许同一块网卡上配置多个网络服务，
// 各自拥有独立的路由器地址，而内核路由表里只有优先级最高的那条默认路由。
func darwinServiceGateways() map[string]string {
	result := make(map[string]string)

	listCmd := exec.Command("scutil")
	listCmd.Stdin = strings.NewReader("list State:/Network/Service/[^/]+/IPv4\n")
	listOut, err := listCmd.Output()
	if err != nil {
		return result
	}

	var showCmds strings.Builder
	for _, line := range strings.Split(string(listOut), "\n") {
		//   subKey [0] = State:/Network/Service/<UUID>/IPv4
		idx := strings.Index(line, "State:/Network/Service/")
		if idx < 0 {
			continue
		}
		fmt.Fprintf(&showCmds, "show %s\n", strings.TrimSpace(line[idx:]))
	}
	if showCmds.Len() == 0 {
		return result
	}

	showCmd := exec.Command("scutil")
	showCmd.Stdin = strings.NewReader(showCmds.String())
	showOut, err := showCmd.Output()
	if err != nil {
		return result
	}

	// 每个 show 输出一个 <dictionary> { ... }，其中 Addresses 是地址数组、
	// Router 是该服务的网关；AdditionalRoutes 等嵌套结构靠括号深度跳过。
	var (
		depth     int
		container = map[int]string{}
		addrs     []string
		router    string
	)
	flushBlock := func() {
		if router != "" {
			for _, a := range addrs {
				if _, exists := result[a]; !exists {
					result[a] = router
				}
			}
		}
		addrs = nil
		router = ""
	}

	for _, raw := range strings.Split(string(showOut), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasSuffix(line, "{"):
			name := ""
			if i := strings.Index(line, ":"); i >= 0 {
				name = strings.TrimSpace(line[:i])
			}
			depth++
			container[depth] = name
		case line == "}":
			if depth == 1 {
				flushBlock()
			}
			delete(container, depth)
			depth--
		case depth == 1 && strings.HasPrefix(line, "Router :"):
			gw := strings.TrimSpace(strings.TrimPrefix(line, "Router :"))
			if net.ParseIP(gw) != nil {
				router = gw
			}
		case depth == 2 && container[2] == "Addresses":
			if i := strings.Index(line, ":"); i >= 0 {
				ip := strings.TrimSpace(line[i+1:])
				if net.ParseIP(ip) != nil {
					addrs = append(addrs, ip)
				}
			}
		}
	}
	flushBlock()

	return result
}

// linuxSourceGateways asks the kernel which gateway would be used for traffic
// sourced from each local address, so `ip rule` / 多路由表 的策略路由也能正确反映。
func linuxSourceGateways(list []InterfaceInfo) map[string]string {
	result := make(map[string]string)

	for _, iface := range list {
		if iface.Loopback {
			continue
		}
		// 仅查询路由表，不产生任何流量
		out, err := exec.Command("ip", "-4", "route", "get", "1.1.1.1", "from", iface.IP).Output()
		if err != nil {
			continue
		}
		// 1.1.1.1 from 192.168.1.5 via 192.168.1.1 dev eth0 ...
		fields := strings.Fields(string(out))
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "via" {
				if net.ParseIP(fields[i+1]) != nil {
					result[iface.IP] = fields[i+1]
				}
				break
			}
		}
	}

	return result
}

// defaultGatewaysByInterface maps interface name -> default gateway IP by
// parsing the OS routing table. Used as a fallback when no per-address gateway
// could be determined. Returns an empty map when unsupported/unavailable.
func defaultGatewaysByInterface() map[string]string {
	result := make(map[string]string)

	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("ip", "route", "show", "default").CombinedOutput()
		if err != nil {
			return result
		}
		// default via 192.168.1.1 dev eth0 proto dhcp metric 100
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			var via, dev string
			for i := 0; i < len(fields)-1; i++ {
				switch fields[i] {
				case "via":
					via = fields[i+1]
				case "dev":
					dev = fields[i+1]
				}
			}
			if via != "" && dev != "" {
				if _, exists := result[dev]; !exists {
					result[dev] = via
				}
			}
		}
	case "darwin":
		out, err := exec.Command("netstat", "-nrf", "inet").CombinedOutput()
		if err != nil {
			return result
		}
		// default            192.168.1.1        UGScg             en0
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[0] != "default" {
				continue
			}
			gw := fields[1]
			dev := fields[len(fields)-1]
			if net.ParseIP(gw) == nil {
				continue
			}
			if _, exists := result[dev]; !exists {
				result[dev] = gw
			}
		}
	}

	return result
}

// ---------------------------------------------------------
// HTTP API Handlers (with Basic Auth)
// ---------------------------------------------------------

func handleRoutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		routes := manager.ListRoutes()
		kernel, kernelErr := kernelRouteTable()

		// 台账里的每一条都标出当前是否还在内核路由表中
		type routeView struct {
			RouteRule
			Status string `json:"status"` // active / missing / unknown
		}
		views := make([]routeView, 0, len(routes))
		for _, r := range routes {
			status := "unknown"
			if r.Paused {
				status = "paused" // 暂停的本来就不在内核里，不算失效
			} else if kernelErr == nil {
				status = "missing"
				if kernelHasRoute(kernel, r.Destination, r.Gateway) {
					status = "active"
				}
			}
			views = append(views, routeView{RouteRule: r, Status: status})
		}

		// Linux 上还能反向找出"内核里带本程序标记、但台账里没有"的漏网之鱼
		orphans := make([]kernelRoute, 0)
		if kernelErr == nil {
			for _, kr := range kernel {
				if !kr.Ours {
					continue
				}
				if !containsDestination(routes, kr.Destination) {
					orphans = append(orphans, kr)
				}
			}
		}

		payload := map[string]interface{}{
			"routes":                 views,
			"orphans":                orphans,
			"state_file":             stateFilePath,
			"domain_refresh_seconds": int(domainRefreshInterval.Seconds()),
			"domains":                manager.ListDomainEntries(),
		}
		if kernelErr != nil {
			payload["reconcile_error"] = kernelErr.Error()
		}
		json.NewEncoder(w).Encode(payload)

	case http.MethodPost:
		var rule RouteRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if rule.Destination == "" || rule.Gateway == "" {
			http.Error(w, "destination and gateway are required", http.StatusBadRequest)
			return
		}
		if net.ParseIP(rule.Gateway) == nil {
			http.Error(w, fmt.Sprintf("网关 %q 不是合法的 IP 地址", rule.Gateway), http.StatusBadRequest)
			return
		}

		result, err := manager.AddTarget(rule.Destination, rule.Gateway, rule.Interface)
		if err != nil {
			// 解析/校验类错误属于用户输入问题，下发失败才是系统问题
			status := http.StatusBadRequest
			if result != nil {
				status = http.StatusInternalServerError
				if len(result.Failed) > 0 {
					http.Error(w, result.Failed[0].Error, status)
					return
				}
			}
			http.Error(w, err.Error(), status)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(result)

	case http.MethodDelete:
		var req struct {
			Destination string `json:"destination"`
			Domain      string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if req.Domain != "" {
			deleted, err := manager.DeleteDomain(req.Domain)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "success", "domain": req.Domain, "deleted": deleted,
			})
			return
		}

		if req.Destination == "" {
			http.Error(w, "destination is required", http.StatusBadRequest)
			return
		}
		if err := manager.DeleteRoute(req.Destination); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "route deleted"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func containsDestination(routes []RouteRule, dest string) bool {
	for _, r := range routes {
		if r.Destination == dest {
			return true
		}
	}
	return false
}

// handleRefreshDomain 重新解析域名，让路由跟上最新的 A 记录。
func handleRefreshDomain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Domain == "" {
		http.Error(w, "domain is required", http.StatusBadRequest)
		return
	}

	result, err := manager.RefreshDomain(req.Domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(result)
}

// handlePauseRoutes 暂停/恢复路由：暂停即从内核撤下但保留台账记录。
// 可按单条 destination、按 domain，或 all=true 全部操作。
func handlePauseRoutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Destination string `json:"destination"`
		Domain      string `json:"domain"`
		All         bool   `json:"all"`
		Paused      bool   `json:"paused"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var changed []string
	var failed []RouteError

	switch {
	case req.Domain != "":
		var err error
		changed, failed, err = manager.SetDomainPaused(req.Domain, req.Paused)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
	case req.All:
		changed, failed = manager.SetPaused(nil, req.Paused)
	case req.Destination != "":
		changed, failed = manager.SetPaused([]string{req.Destination}, req.Paused)
	default:
		http.Error(w, "需要指定 destination、domain 或 all", http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"paused":  req.Paused,
		"changed": changed,
		"failed":  failed,
	})
}

// handleRestoreRoutes 把台账里已失效的路由重新下发（机器重启后内核路由会丢）。
func handleRestoreRoutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Destinations []string `json:"destinations"`
	}
	// 允许空 body，表示重下全部
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	restored, failed := manager.RestoreRoutes(req.Destinations)
	status := http.StatusOK
	if len(restored) == 0 && len(failed) > 0 {
		status = http.StatusInternalServerError
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"restored": restored,
		"failed":   failed,
	})
}

func handleSystemRoutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	routes := GetSystemRoutes()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"routes": routes,
	})
}

func handleInterfaces(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, outboundIP := proxyMgr.GetConfig()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"interfaces":  GetLocalInterfaces(),
		"outbound_ip": outboundIP,
	})
}

// 出口探测服务：与 README 中的
// curl --socks5-hostname 127.0.0.1:<port> 'https://myip.ipip.net/' 等价
const egressCheckURL = "https://myip.ipip.net/"

var egressIPPattern = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)

// handleEgressIP 真的通过本机 SOCKS5 端口发一次请求，用来确认"绑定的出口 IP
// 到底有没有生效"——只看本地配置是看不出来的。
func handleEgressIP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	port, outboundIP := proxyMgr.GetConfig()
	proxyAddr := net.JoinHostPort("127.0.0.1", port)
	command := fmt.Sprintf("curl --socks5-hostname %s '%s'", proxyAddr, egressCheckURL)

	respond := func(status int, payload map[string]interface{}) {
		payload["socks_port"] = port
		payload["bound_outbound_ip"] = outboundIP
		payload["command"] = command
		payload["checked_at"] = time.Now()
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(payload)
	}

	if !proxyMgr.Running() {
		respond(http.StatusConflict, map[string]interface{}{
			"ok": false, "error": "代理当前处于停止状态，请先启动代理再检测",
		})
		return
	}

	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		respond(http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "error": fmt.Sprintf("创建 SOCKS5 客户端失败: %v", err),
		})
		return
	}
	ctxDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		respond(http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "error": "SOCKS5 客户端不支持带超时的连接",
		})
		return
	}

	client := &http.Client{
		Transport: &http.Transport{DialContext: ctxDialer.DialContext},
		Timeout:   15 * time.Second,
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, egressCheckURL, nil)
	if err != nil {
		respond(http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	req.Header.Set("User-Agent", "curl/8.0")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[Egress] 出口探测失败 (端口 %s, 绑定 %s): %v", port, outboundIP, err)
		respond(http.StatusBadGateway, map[string]interface{}{
			"ok":    false,
			"error": fmt.Sprintf("经由本机 SOCKS5 请求失败: %v", err),
		})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		respond(http.StatusBadGateway, map[string]interface{}{
			"ok": false, "error": fmt.Sprintf("读取响应失败: %v", err),
		})
		return
	}

	raw := strings.TrimSpace(string(body))
	egressIP := ""
	if m := egressIPPattern.FindString(raw); m != "" {
		egressIP = m
	}
	log.Printf("[Egress] 出口探测成功 (端口 %s, 绑定 %s): %s", port, outboundIP, raw)

	respond(http.StatusOK, map[string]interface{}{
		"ok":        true,
		"egress_ip": egressIP,
		"raw":       raw,
	})
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats.mu.Lock()
	activeConns := make([]*ConnectionInfo, 0, len(stats.activeConnections))
	for _, c := range stats.activeConnections {
		activeConns = append(activeConns, c)
	}
	stats.mu.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_bytes_in":           atomic.LoadInt64(&stats.totalBytesIn),
		"total_bytes_out":          atomic.LoadInt64(&stats.totalBytesOut),
		"total_connections":        atomic.LoadInt64(&stats.totalConnections),
		"active_connections_count": len(activeConns),
		"active_connections":       activeConns,
	})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(proxyStatusPayload())

	case http.MethodPost:
		var req struct {
			SocksPort  string `json:"socks_port"`
			OutboundIP string `json:"outbound_ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.SocksPort == "" {
			http.Error(w, "socks_port is required", http.StatusBadRequest)
			return
		}
		if req.OutboundIP != "" {
			if _, err := validateOutboundIP(req.OutboundIP); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		// 代理停着的时候只存配置，不会被动拉起来
		if err := proxyMgr.SetConfig(req.SocksPort, req.OutboundIP); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		payload := proxyStatusPayload()
		payload["status"] = "success"
		json.NewEncoder(w).Encode(payload)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// proxyStatusPayload 汇总代理的开关状态与配置。代理停止时 started_at 为空，
// 运行时长归零，前端据此显示「已停止」。
func proxyStatusPayload() map[string]interface{} {
	port, outboundIP := proxyMgr.GetConfig()
	running := proxyMgr.Running()
	startedAt := proxyMgr.StartedAt()

	payload := map[string]interface{}{
		"running":             running,
		"proxy_state":         map[bool]string{true: "running", false: "stopped"}[running],
		"socks_port":          port,
		"outbound_ip":         outboundIP,
		"started_at":          nil, // 代理最近一次启动（改配置会重启）
		"uptime_seconds":      0,
		"process_started_at":  processStartedAt, // 进程启动，代理开关不影响
		"process_uptime_secs": int(time.Since(processStartedAt).Seconds()),
		"server_time":         time.Now(),
	}
	if running && !startedAt.IsZero() {
		payload["started_at"] = startedAt
		payload["uptime_seconds"] = int(time.Since(startedAt).Seconds())
	}
	return payload
}

// handleProxyPower 单独控制代理的启停，与保存配置分开：
// 默认不启动，用户改好端口和出口 IP 再点启动。
func handleProxyPower(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Action string `json:"action"` // start | stop
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch req.Action {
	case "start":
		if err := proxyMgr.StartCurrent(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "stop":
		if err := proxyMgr.Stop(); err != nil {
			// 监听口关闭出错不影响"已停止"这个结果，如实回报即可
			log.Printf("[SOCKS5] 停止代理时出错: %v", err)
		}
	default:
		http.Error(w, `action must be "start" or "stop"`, http.StatusBadRequest)
		return
	}

	payload := proxyStatusPayload()
	payload["status"] = "success"
	json.NewEncoder(w).Encode(payload)
}

func main() {
	socksPort := flag.String("socks-port", "1080", "SOCKS5 proxy port")
	outboundIP := flag.String("outbound-ip", "", "Local IP to bind for SOCKS5 outbound traffic")
	apiPort := flag.String("api-port", "8080", "API management and Web UI port")
	authUser := flag.String("user", "", "Web UI & API username (leave empty for no auth)")
	authPass := flag.String("pass", "", "Web UI & API password (leave empty for no auth)")
	stateFile := flag.String("state-file", "", "路由台账文件路径（留空自动选择 /var/lib/lan-proxy/routes.json 等可写位置）")
	restoreRoutes := flag.Bool("restore-routes", false, "启动时自动重新下发台账中已失效的路由")
	domainRefresh := flag.Duration("domain-refresh", 5*time.Minute, "域名路由自动重新解析间隔（0 表示关闭）")
	startProxy := flag.Bool("start-proxy", false, "启动时立即开启 SOCKS5 代理（默认关闭，可在 Web 后台随时启停）")
	flag.Parse()

	setAuth(*authUser, *authPass)
	if *authUser != "" || *authPass != "" {
		log.Printf("[Security] Web UI & API authentication enabled (User: %s)", *authUser)
	} else {
		log.Printf("[Security] Web UI & API running without authentication")
	}

	// 1. 载入路由台账并与内核路由表对账
	stateFilePath = resolveStateFile(*stateFile)
	if stateFilePath != "" {
		log.Printf("[State] 路由台账文件: %s", stateFilePath)
	}
	loaded, missing := manager.LoadState()
	if len(missing) > 0 {
		if *restoreRoutes {
			dests := make([]string, 0, len(missing))
			for _, r := range missing {
				dests = append(dests, r.Destination)
			}
			restored, failed := manager.RestoreRoutes(dests)
			log.Printf("[State] 自动重下: 成功 %d 条, 失败 %d 条", len(restored), len(failed))
		} else {
			log.Printf("[State] %d/%d 条台账路由当前未生效，可在 Web 后台点击「重新下发」，或加 -restore-routes 启动参数自动重建",
				len(missing), loaded)
		}
	}

	startDomainRefresher(*domainRefresh)

	// 2. SOCKS5 代理默认不启动，只记下配置；加 -start-proxy 或在 Web 后台点启动
	if err := proxyMgr.SetConfig(*socksPort, *outboundIP); err != nil {
		log.Fatalf("Invalid SOCKS5 proxy config: %v", err)
	}
	if *startProxy {
		if err := proxyMgr.Start(*socksPort, *outboundIP); err != nil {
			log.Fatalf("Failed to start SOCKS5 proxy: %v", err)
		}
	} else {
		log.Printf("[SOCKS5] 代理默认未启动（端口 %s），可在 Web 后台点击「启动代理」，或用 -start-proxy 开机即启", *socksPort)
	}

	// 3. Setup Embedded Static Files for Web UI
	subFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("Failed to create sub filesystem: %v", err)
	}

	fileServer := http.FileServer(http.FS(subFS))
	if *authUser != "" || *authPass != "" {
		http.HandleFunc("/", basicAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
			fileServer.ServeHTTP(w, r)
		}))
		http.HandleFunc("/api/routes", basicAuthMiddleware(handleRoutes))
		http.HandleFunc("/api/routes/restore", basicAuthMiddleware(handleRestoreRoutes))
		http.HandleFunc("/api/routes/refresh", basicAuthMiddleware(handleRefreshDomain))
		http.HandleFunc("/api/routes/pause", basicAuthMiddleware(handlePauseRoutes))
		http.HandleFunc("/api/system-routes", basicAuthMiddleware(handleSystemRoutes))
		http.HandleFunc("/api/interfaces", basicAuthMiddleware(handleInterfaces))
		http.HandleFunc("/api/egress-ip", basicAuthMiddleware(handleEgressIP))
		http.HandleFunc("/api/stats", basicAuthMiddleware(handleStats))
		http.HandleFunc("/api/status", basicAuthMiddleware(handleStatus))
		http.HandleFunc("/api/proxy", basicAuthMiddleware(handleProxyPower))
	} else {
		http.Handle("/", fileServer)
		http.HandleFunc("/api/routes", handleRoutes)
		http.HandleFunc("/api/routes/restore", handleRestoreRoutes)
		http.HandleFunc("/api/routes/refresh", handleRefreshDomain)
		http.HandleFunc("/api/routes/pause", handlePauseRoutes)
		http.HandleFunc("/api/system-routes", handleSystemRoutes)
		http.HandleFunc("/api/interfaces", handleInterfaces)
		http.HandleFunc("/api/egress-ip", handleEgressIP)
		http.HandleFunc("/api/stats", handleStats)
		http.HandleFunc("/api/status", handleStatus)
		http.HandleFunc("/api/proxy", handleProxyPower)
	}

	apiAddr := fmt.Sprintf("0.0.0.0:%s", *apiPort)
	log.Printf("[Web UI & API] Management console running at http://%s", apiAddr)

	if err := http.ListenAndServe(apiAddr, nil); err != nil {
		log.Fatalf("[Web UI] Server error: %v", err)
	}
}
