package route

// 域名托管：解析目标、按最新 A 记录对齐内核路由、定时重新解析。
// CDN 域名的 IP 会轮换，加完就不管的话路由很快就指向一批没人用的 IP。

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"lan_router_socks5/internal/netutil"
)

// RefreshDomain 重新解析域名并让内核路由与最新的 A 记录对齐。
func (rm *Manager) RefreshDomain(domain string) (*RefreshResult, error) {
	rm.mu.Lock()
	existing := make(map[string]Rule)
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

	dests, _, resolvedAt, err := resolveTargets(domain)
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

	result := &RefreshResult{
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
		rule := Rule{
			Destination: dest, Gateway: gateway, Interface: iface,
			Domains: []string{domain}, ResolvedAt: resolvedAt, CreatedAt: time.Now(),
		}
		if err := rm.addRoute(rule); err != nil {
			result.Failed = append(result.Failed, OpError{Destination: dest, Error: err.Error()})
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
			result.Failed = append(result.Failed, OpError{Destination: dest, Error: err.Error()})
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

// DeleteDomain 删除某个域名解析出来的全部路由。
func (rm *Manager) DeleteDomain(domain string) (int, error) {
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

// ListDomains 返回台账里出现过的所有域名
func (rm *Manager) ListDomains() []string {
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

func (rm *Manager) IsDomainPaused(domain string) bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return rm.domains[domain].Paused
}

// ListDomainEntries 返回被托管的域名记录（含最近一次解析时间与错误）
func (rm *Manager) ListDomainEntries() []DomainEntry {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	list := make([]DomainEntry, 0, len(rm.domains))
	for _, e := range rm.domains {
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Domain < list[j].Domain })
	return list
}

// refreshInterval 为 0 表示关闭自动重新解析
var refreshInterval time.Duration

// RefreshInterval 供接口展示当前的自动重新解析间隔
func RefreshInterval() time.Duration { return refreshInterval }

// StartDomainRefresher 定期重新解析域名路由。
func StartDomainRefresher(interval time.Duration) {
	refreshInterval = interval
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
			// 网关可能换了网卡（比如 Wi-Fi 也把它设成了默认网关），顺带对一遍作用域
			Default.RescopeRoutes()
		}
	}()
}

func refreshAllDomains() {
	for _, domain := range Default.ListDomains() {
		if Default.IsDomainPaused(domain) {
			continue // 已暂停的域名不参与定时重新解析
		}
		if _, err := Default.RefreshDomain(domain); err != nil {
			// 解析失败时保持现状，绝不能因为一次 DNS 抖动就把路由全撤了
			log.Printf("[Router] 自动重新解析 %s 失败，保留现有路由: %v", domain, err)
		}
	}
}

// resolveTargets 把用户输入的目标转换成待下发的 CIDR 列表。
// 输入是域名时返回域名本身与解析时间，供上层记录。
func resolveTargets(target string) (dests []string, domain string, resolvedAt *time.Time, err error) {
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

	if !netutil.IsValidDomain(target) {
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

// looksLikeIPOrCIDR 判断输入"长得像"IP 或网段——只由数字、点、斜杠、冒号组成
func looksLikeIPOrCIDR(target string) bool {
	return strings.Contains(target, "/") || strings.Contains(target, ":") ||
		strings.IndexFunc(target, func(r rune) bool {
			return (r < '0' || r > '9') && r != '.'
		}) < 0
}
