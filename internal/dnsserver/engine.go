package dnsserver

// 查询引擎：一次启动对应一个 engine，改配置重启就换一个新的，
// 免得处理中的查询看到改了一半的配置。
//
// 一次查询的顺序是：静态记录 → 缓存 → 上游。

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type bootstrapEntry struct {
	ip        string
	expiresAt time.Time
}

type engine struct {
	settings Settings
	timeout  time.Duration
	cache    *cache
	stats    *stats

	mu      sync.Mutex
	clients map[string]*http.Client
	boot    map[string]bootstrapEntry
}

func newEngine(s Settings, st *stats) *engine {
	return &engine{
		settings: s,
		timeout:  time.Duration(s.TimeoutMS) * time.Millisecond,
		cache:    newCache(s.CacheSize),
		stats:    st,
		clients:  make(map[string]*http.Client),
		boot:     make(map[string]bootstrapEntry),
	}
}

// selectUpstreams 挑出该由谁来回答这个域名：域名规则最长匹配优先，
// 没有任何规则命中时退回到没写域名限制的兜底上游。
func selectUpstreams(ups []Upstream, name string) []Upstream {
	name = strings.ToLower(strings.Trim(name, "."))

	best := -1
	for _, u := range ups {
		if !u.Enabled {
			continue
		}
		for _, d := range u.Domains {
			if name == d || strings.HasSuffix(name, "."+d) {
				if len(d) > best {
					best = len(d)
				}
			}
		}
	}

	var matched []Upstream
	if best >= 0 {
		for _, u := range ups {
			if !u.Enabled {
				continue
			}
			for _, d := range u.Domains {
				if len(d) == best && (name == d || strings.HasSuffix(name, "."+d)) {
					matched = append(matched, u)
					break
				}
			}
		}
		return matched
	}

	for _, u := range ups {
		if u.Enabled && len(u.Domains) == 0 {
			matched = append(matched, u)
		}
	}
	return matched
}

// matchHosts 查静态记录，域名支持 *.example.com（匹配子域，不匹配 example.com 本身）
func matchHosts(hosts []HostRecord, name string, qtype dnsmessage.Type) []net.IP {
	if qtype != dnsmessage.TypeA && qtype != dnsmessage.TypeAAAA {
		return nil
	}
	name = strings.ToLower(strings.Trim(name, "."))

	var ips []net.IP
	for _, h := range hosts {
		hit := false
		if strings.HasPrefix(h.Domain, "*.") {
			hit = strings.HasSuffix(name, h.Domain[1:])
		} else {
			hit = name == h.Domain
		}
		if !hit {
			continue
		}
		ip := net.ParseIP(h.IP)
		if ip == nil {
			continue
		}
		isV4 := ip.To4() != nil
		if (qtype == dnsmessage.TypeA) == isV4 {
			ips = append(ips, ip)
		}
	}
	return ips
}

// handle 处理一个完整的 DNS 请求报文，返回要发回客户端的应答字节。
// 返回 nil 表示报文坏到没法回应，直接丢弃。
func (rt *engine) handle(req []byte, client string) []byte {
	started := time.Now()

	var p dnsmessage.Parser
	hdr, err := p.Start(req)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		// 连问题段都没有，只能回个格式错误
		return buildResponse(hdr, dnsmessage.Question{}, dnsmessage.RCodeFormatError, nil)
	}

	name := strings.ToLower(q.Name.String())
	bare := strings.TrimSuffix(name, ".")
	entry := queryLog{Time: started, Client: client, Name: name, Type: typeName(q.Type)}

	// 1) 静态记录优先，本地写死的东西不该再问上游
	if ips := matchHosts(rt.settings.Hosts, bare, q.Type); len(ips) > 0 {
		answers := make([]dnsmessage.Resource, 0, len(ips))
		texts := make([]string, 0, len(ips))
		for _, ip := range ips {
			if rr, ok := ipResource(q, ip); ok {
				answers = append(answers, rr)
				texts = append(texts, ip.String())
			}
		}
		resp := buildResponse(hdr, q, dnsmessage.RCodeSuccess, answers)
		entry.Source, entry.Status, entry.Upstream = "hosts", "NOERROR", "本地静态记录"
		entry.Answer = strings.Join(texts, ", ")
		entry.CostMS = time.Since(started).Milliseconds()
		rt.stats.record(entry)
		return resp
	}

	key := cacheKey(q)

	// 2) 缓存
	if rt.settings.Cache {
		if msg, ok := rt.cache.get(key, started); ok {
			msg.Header.ID = hdr.ID
			msg.Header.RecursionDesired = hdr.RecursionDesired
			if packed, perr := msg.Pack(); perr == nil {
				entry.Source, entry.Upstream = "cache", "缓存"
				entry.Status = rcodeName(msg.Header.RCode)
				entry.Answer = summarizeAnswers(msg.Answers)
				entry.CostMS = time.Since(started).Milliseconds()
				rt.stats.record(entry)
				return packed
			}
		}
	}

	// 3) 上游
	ups := selectUpstreams(rt.settings.Upstreams, bare)
	if len(ups) == 0 {
		entry.Source, entry.Status = "error", "SERVFAIL"
		entry.Answer = "没有可用的上游 DNS"
		entry.CostMS = time.Since(started).Milliseconds()
		rt.stats.record(entry)
		return buildResponse(hdr, q, dnsmessage.RCodeServerFailure, nil)
	}

	ctx, cancel := context.WithTimeout(context.Background(), rt.timeout)
	defer cancel()

	raw, used, err := rt.query(ctx, ups, req)
	if err != nil {
		entry.Source, entry.Status, entry.Upstream = "error", "SERVFAIL", used
		entry.Answer = err.Error()
		entry.CostMS = time.Since(started).Milliseconds()
		rt.stats.record(entry)
		return buildResponse(hdr, q, dnsmessage.RCodeServerFailure, nil)
	}

	// 上游的事务 ID 未必和客户端一致（DoH 会把 ID 归零），一律改回来
	setMsgID(raw, hdr.ID)

	entry.Source, entry.Upstream = "upstream", used
	entry.Status = "NOERROR"
	var parsed dnsmessage.Message
	if perr := parsed.Unpack(raw); perr == nil {
		entry.Status = rcodeName(parsed.Header.RCode)
		entry.Answer = summarizeAnswers(parsed.Answers)
		if rt.settings.Cache {
			if ttl := rt.cacheTTL(parsed); ttl > 0 {
				rt.cache.put(key, parsed, ttl, started)
			}
		}
	}
	// 解不开也照发不误：能转发就别因为我们看不懂而丢掉，只是不缓存
	entry.CostMS = time.Since(started).Milliseconds()
	rt.stats.record(entry)
	return raw
}

// cacheTTL 取应答里最小的 TTL 并夹到配置区间；没有记录时按负缓存处理
func (rt *engine) cacheTTL(msg dnsmessage.Message) time.Duration {
	switch msg.Header.RCode {
	case dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError:
	default:
		return 0 // SERVFAIL 之类是暂时状态，缓存下来只会让故障更久
	}

	min := ^uint32(0)
	for _, group := range [][]dnsmessage.Resource{msg.Answers, msg.Authorities} {
		for _, rr := range group {
			if rr.Header.Type == dnsmessage.TypeOPT {
				continue
			}
			if rr.Header.TTL < min {
				min = rr.Header.TTL
			}
		}
	}
	if min == ^uint32(0) {
		return negativeTTL
	}

	ttl := time.Duration(min) * time.Second
	if lo := time.Duration(rt.settings.MinTTL) * time.Second; ttl < lo {
		ttl = lo
	}
	if hi := time.Duration(rt.settings.MaxTTL) * time.Second; hi > 0 && ttl > hi {
		ttl = hi
	}
	return ttl
}

// query 按配置的策略把请求送给上游，返回原始应答和实际出力的上游名字
func (rt *engine) query(ctx context.Context, ups []Upstream, req []byte) ([]byte, string, error) {
	if rt.settings.Strategy == strategyRace && len(ups) > 1 {
		return rt.queryRace(ctx, ups, req)
	}

	var lastErr error
	for _, u := range ups {
		started := time.Now()
		resp, err := rt.exchange(ctx, u, req)
		rt.stats.recordUpstream(u.Name, time.Since(started), err)
		if err == nil {
			return resp, u.Name, nil
		}
		lastErr = fmt.Errorf("%s: %v", u.Name, err)
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("没有可用的上游 DNS")
	}
	return nil, "", lastErr
}

// queryRace 同时问所有上游，谁先给出应答就用谁——上游里混着境内境外时能省掉超时等待
func (rt *engine) queryRace(ctx context.Context, ups []Upstream, req []byte) ([]byte, string, error) {
	type result struct {
		resp []byte
		name string
		err  error
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ch := make(chan result, len(ups))
	for _, u := range ups {
		go func(u Upstream) {
			started := time.Now()
			resp, err := rt.exchange(ctx, u, req)
			rt.stats.recordUpstream(u.Name, time.Since(started), err)
			ch <- result{resp, u.Name, err}
		}(u)
	}

	var lastErr error
	for range ups {
		r := <-ch
		if r.err == nil {
			return r.resp, r.name, nil
		}
		lastErr = fmt.Errorf("%s: %v", r.name, r.err)
	}
	return nil, "", lastErr
}

func (rt *engine) exchange(ctx context.Context, u Upstream, req []byte) ([]byte, error) {
	switch u.Type {
	case upstreamTCP:
		return rt.exchangeStream(ctx, u, req, false)
	case upstreamTLS:
		return rt.exchangeStream(ctx, u, req, true)
	case upstreamHTTPS:
		return rt.exchangeHTTPS(ctx, u, req)
	default:
		return rt.exchangeUDP(ctx, u, req)
	}
}

func (rt *engine) exchangeUDP(ctx context.Context, u Upstream, req []byte) ([]byte, error) {
	addr, err := rt.resolveUpstreamAddr(ctx, u, u.Address)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: rt.timeout}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(rt.deadline(ctx))
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	buf := make([]byte, udpBufSize)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n < 12 {
			continue
		}
		// UDP 上什么都可能飘进来，事务 ID 对不上的直接忽略，接着等真正的应答
		if buf[0] != req[0] || buf[1] != req[1] {
			continue
		}
		resp := make([]byte, n)
		copy(resp, buf[:n])
		// TC 位置起来说明应答被截断了，按 RFC 改用 TCP 重来一次
		if resp[2]&0x02 != 0 {
			tcpUp := u
			tcpUp.Type = upstreamTCP
			if full, err := rt.exchangeStream(ctx, tcpUp, req, false); err == nil {
				return full, nil
			}
		}
		return resp, nil
	}
}

// exchangeStream 走 TCP/DoT：两者都是 2 字节长度前缀 + 报文
func (rt *engine) exchangeStream(ctx context.Context, u Upstream, req []byte, useTLS bool) ([]byte, error) {
	addr, err := rt.resolveUpstreamAddr(ctx, u, u.Address)
	if err != nil {
		return nil, err
	}

	var conn net.Conn
	d := &net.Dialer{Timeout: rt.timeout}
	if useTLS {
		serverName := u.Hostname
		if serverName == "" {
			serverName, _, _ = net.SplitHostPort(u.Address)
		}
		td := &tls.Dialer{NetDialer: d, Config: &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}}
		conn, err = td.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(rt.deadline(ctx))

	if len(req) > 65535 {
		return nil, fmt.Errorf("请求报文过大")
	}
	framed := make([]byte, 2+len(req))
	framed[0] = byte(len(req) >> 8)
	framed[1] = byte(len(req))
	copy(framed[2:], req)
	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(lenBuf[0])<<8 | int(lenBuf[1])
	if n < 12 {
		return nil, fmt.Errorf("上游返回了长度为 %d 的空应答", n)
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (rt *engine) exchangeHTTPS(ctx context.Context, u Upstream, req []byte) ([]byte, error) {
	// RFC 8484 建议 DoH 报文的事务 ID 用 0，这样中间层能按内容缓存；
	// 应答的 ID 由调用方统一改回客户端的那个
	body := make([]byte, len(req))
	copy(body, req)
	setMsgID(body, 0)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.Address, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	resp, err := rt.httpClient(u).Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH 返回 HTTP %d", resp.StatusCode)
	}
	if len(data) < 12 {
		return nil, fmt.Errorf("DoH 应答过短（%d 字节）", len(data))
	}
	return data, nil
}

func (rt *engine) deadline(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(rt.timeout)
}

// httpClient 每个 DoH 上游一个客户端：连接可以复用，且各自带自己的 bootstrap 解析
func (rt *engine) httpClient(u Upstream) *http.Client {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if c, ok := rt.clients[u.Name]; ok {
		return c
	}

	dialer := &net.Dialer{Timeout: rt.timeout}
	up := u
	client := &http.Client{
		Timeout: rt.timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				resolved, err := rt.resolveUpstreamAddr(ctx, up, addr)
				if err != nil {
					return nil, err
				}
				return dialer.DialContext(ctx, network, resolved)
			},
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	rt.clients[u.Name] = client
	return client
}

// resolveUpstreamAddr 把 host:port 里的域名换成 IP。
// 配了 bootstrap 就用它解析：本机很可能正把这个 DNS 服务设成系统解析器，
// 再走系统解析上游域名就是自己问自己。
func (rt *engine) resolveUpstreamAddr(ctx context.Context, u Upstream, addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, nil // 不是 host:port（例如 DoH 的 URL），交给上层原样处理
	}
	if net.ParseIP(host) != nil || u.Bootstrap == "" {
		return addr, nil
	}

	now := time.Now()
	rt.mu.Lock()
	if e, ok := rt.boot[host]; ok && now.Before(e.expiresAt) {
		rt.mu.Unlock()
		return net.JoinHostPort(e.ip, port), nil
	}
	rt.mu.Unlock()

	ip, err := rt.bootstrapLookup(ctx, u.Bootstrap, host)
	if err != nil {
		return "", fmt.Errorf("用 bootstrap %s 解析 %s 失败: %v", u.Bootstrap, host, err)
	}
	rt.mu.Lock()
	rt.boot[host] = bootstrapEntry{ip: ip, expiresAt: now.Add(5 * time.Minute)}
	rt.mu.Unlock()
	return net.JoinHostPort(ip, port), nil
}

// bootstrapLookup 用普通 UDP DNS 查一条 A 记录
func (rt *engine) bootstrapLookup(ctx context.Context, server, host string) (string, error) {
	name, err := dnsmessage.NewName(fqdn(host))
	if err != nil {
		return "", err
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 1, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	packed, err := msg.Pack()
	if err != nil {
		return "", err
	}

	d := net.Dialer{Timeout: rt.timeout}
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(rt.deadline(ctx))
	if _, err := conn.Write(packed); err != nil {
		return "", err
	}

	buf := make([]byte, udpBufSize)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	var reply dnsmessage.Message
	if err := reply.Unpack(buf[:n]); err != nil {
		return "", err
	}
	for _, rr := range reply.Answers {
		if a, ok := rr.Body.(*dnsmessage.AResource); ok {
			return net.IP(a.A[:]).String(), nil
		}
	}
	return "", fmt.Errorf("没有返回 A 记录")
}
