package route

// 台账的增删改查：添加、删除、暂停/恢复。所有会动内核路由的操作都在这里，
// 真正执行命令的部分在 oscmd.go。

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

// AddTarget 接受 IP、CIDR 或域名。域名会先解析成 A 记录，每个 IPv4 下发一条
// 主机路由，并把域名与解析时间一并记录下来。
func (rm *Manager) AddTarget(target, gateway, iface string) (*Result, error) {
	target = strings.TrimSpace(target)

	dests, domain, resolvedAt, err := resolveTargets(target)
	if err != nil {
		return nil, err
	}
	if domain != "" {
		log.Printf("[Router] 域名 %s 解析到 %d 个 IPv4: %s", domain, len(dests), strings.Join(dests, ", "))
	}

	// macOS 上必须把路由放进网卡作用域，否则会被克隆路由压掉（见 buildRouteCmd）。
	// 作用域网卡随路由一起记进台账，删除/重新下发时要用同一个。
	if iface == "" {
		iface = scopeInterface(gateway)
		if iface != "" {
			log.Printf("[Router] 网关 %s 归属网卡 %s，路由将限定在该网卡作用域内", gateway, iface)
		}
	}

	var domains []string
	if domain != "" {
		domains = []string{domain}
	}

	result := &Result{Domain: domain, ResolvedAt: resolvedAt}
	for _, dest := range dests {
		rule := Rule{
			Destination: dest,
			Gateway:     gateway,
			Interface:   iface,
			Domains:     domains,
			ResolvedAt:  resolvedAt,
			CreatedAt:   time.Now(),
		}
		if err := rm.addRoute(rule); err != nil {
			log.Printf("[Router] 添加失败: %s -> %s (来源: %s): %v", dest, gateway, origin(domains), err)
			result.Failed = append(result.Failed, OpError{Destination: dest, Error: err.Error()})
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

func (rm *Manager) addRoute(rule Rule) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// 已有同目标的路由：内核里一个目标只能有一条，只能共用
	if existing, ok := rm.routes[rule.Destination]; ok {
		if existing.Gateway != rule.Gateway {
			return fmt.Errorf("目标 %s 已有一条走网关 %s 的路由（来源: %s），无法再指向 %s；"+
				"请先删除原路由，或给这两者指定同一个网关",
				rule.Destination, existing.Gateway, origin(existing.Domains), rule.Gateway)
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
			merged.Destination, merged.Gateway, origin(merged.Domains))
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
		rule.Destination, rule.Gateway, origin(rule.Domains))
	return nil
}

// SetPaused 暂停/恢复若干条路由。暂停 = 从内核撤下但保留台账，随时可恢复。
// destinations 为空表示全部。
func (rm *Manager) SetPaused(destinations []string, paused bool) (changed []string, failed []OpError) {
	rm.mu.Lock()
	targets := make([]Rule, 0)
	if len(destinations) == 0 {
		for _, r := range rm.routes {
			targets = append(targets, r)
		}
	} else {
		for _, dest := range destinations {
			if r, ok := rm.routes[dest]; ok {
				targets = append(targets, r)
			} else {
				failed = append(failed, OpError{Destination: dest, Error: "台账中没有这条记录"})
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
				failed = append(failed, OpError{Destination: r.Destination, Error: err.Error()})
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

		log.Printf("[Router] 已%s路由: %s -> %s (来源: %s)", verb, r.Destination, r.Gateway, origin(r.Domains))
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
func (rm *Manager) SetDomainPaused(domain string, paused bool) ([]string, []OpError, error) {
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
func (rm *Manager) releaseRoute(destination, domain string) (deleted bool, err error) {
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
			destination, domain, origin(remaining))
		return false, nil
	}
	rm.mu.Unlock()

	return true, rm.DeleteRoute(destination)
}

func (rm *Manager) DeleteRoute(destination string) error {
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
	log.Printf("[Router] 已删除路由: %s (来源: %s)", destination, origin(rule.Domains))
	return nil
}

// ListRoutes 返回台账里的全部路由，手动添加的排在前面，
// 域名解析出来的按首个域名聚在一起，方便界面分组展示。
func (rm *Manager) ListRoutes() []Rule {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	list := make([]Rule, 0, len(rm.routes))
	for _, r := range rm.routes {
		list = append(list, r)
	}

	primary := func(r Rule) string {
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
