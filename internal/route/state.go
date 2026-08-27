package route

// 台账持久化与启动对账：本程序下发的每一条路由都写进 JSON 文件，
// 重启后拿台账和内核路由表对一遍，就能分清哪些还在、哪些已经失效。

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"nettool/internal/netutil"
)

const stateVersion = 1

type stateFile struct {
	Version int           `json:"version"`
	SavedAt time.Time     `json:"saved_at"`
	Routes  []Rule        `json:"routes"`
	Domains []DomainEntry `json:"domains,omitempty"`
}

// statePath 为空表示未启用持久化（写入失败时会降级到这种状态）
var statePath string

// StateFile 返回当前生效的台账文件路径，空串表示没有持久化
func StateFile() string { return statePath }

// ResolveStateFile 决定台账落在哪里：显式指定 > 系统级目录 > 用户目录。
func ResolveStateFile(flagVal string) string {
	statePath = pickStateFile(flagVal)
	return statePath
}

func pickStateFile(flagVal string) string {
	if flagVal != "" {
		if err := netutil.EnsureStateDir(flagVal); err != nil {
			log.Printf("[State] 无法使用指定的台账文件 %s: %v，本次运行不持久化路由", flagVal, err)
			return ""
		}
		return flagVal
	}

	for _, c := range stateCandidates() {
		if err := netutil.EnsureStateDir(c); err == nil {
			return c
		}
	}
	log.Printf("[State] 所有候选台账路径均不可写，本次运行不持久化路由")
	return ""
}

// stateCandidates 按优先级给出台账的候选位置：先系统级的共享目录，
// 再当前用户的目录，最后退到工作目录。
func stateCandidates() []string {
	var candidates []string

	if runtime.GOOS == "windows" {
		// Windows 上 /var/lib 会被当成当前盘根目录下的 \var\lib，
		// 以管理员身份跑时还真能建出来，台账就落到了一个谁都想不到的地方
		if programData := os.Getenv("ProgramData"); programData != "" {
			candidates = append(candidates, filepath.Join(programData, "nettool", "routes.json"))
		}
		if dir, err := os.UserConfigDir(); err == nil && dir != "" {
			candidates = append(candidates, filepath.Join(dir, "nettool", "routes.json"))
		}
	} else {
		candidates = append(candidates, filepath.Join("/var/lib/nettool", "routes.json"))
	}

	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates, filepath.Join(home, ".nettool", "routes.json"))
	}
	return append(candidates, "nettool-routes.json")
}

// persistLocked 调用方必须已持有 rm.mu
func (rm *Manager) persistLocked() {
	if statePath == "" {
		return
	}

	list := make([]Rule, 0, len(rm.routes))
	for _, r := range rm.routes {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Destination < list[j].Destination })

	domains := make([]DomainEntry, 0, len(rm.domains))
	for _, e := range rm.domains {
		domains = append(domains, e)
	}
	sort.Slice(domains, func(i, j int) bool { return domains[i].Domain < domains[j].Domain })

	data, err := json.MarshalIndent(stateFile{
		Version: stateVersion,
		SavedAt: time.Now(),
		Routes:  list,
		Domains: domains,
	}, "", "  ")
	if err != nil {
		log.Printf("[State] 序列化台账失败: %v", err)
		return
	}

	if err := netutil.WriteFileAtomic(statePath, data, 0o644); err != nil {
		log.Printf("[State] 写入台账失败 %s: %v", statePath, err)
	}
}

// LoadState 读取台账并与内核路由表对账，返回载入条数与已失效的条目。
func (rm *Manager) LoadState() (loaded int, missing []Rule) {
	if statePath == "" {
		return 0, nil
	}

	data, err := os.ReadFile(statePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[State] 读取台账失败 %s: %v", statePath, err)
		}
		return 0, nil
	}
	if len(data) == 0 {
		return 0, nil
	}

	var state stateFile
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("[State] 台账文件损坏 %s: %v（本次忽略，不会覆盖，请手动检查）", statePath, err)
		statePath = "" // 不要用空台账把用户的记录覆盖掉
		return 0, nil
	}

	kernel, kernelErr := KernelTable()

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
		if !KernelHasRoute(kernel, r.Destination, r.Gateway) {
			missing = append(missing, r)
		}
	}

	log.Printf("[State] 台账 %s: 载入 %d 条，其中 %d 条已不在内核路由表中",
		statePath, loaded, len(missing))
	for _, r := range missing {
		log.Printf("[State]   失效: %s -> %s (来源: %s, 添加于 %s)",
			r.Destination, r.Gateway, origin(r.Domains), r.CreatedAt.Format(time.RFC3339))
	}
	return loaded, missing
}

// MissingRoutes 拿台账和内核路由表对一遍，返回当前不在内核里的（暂停的不算）。
func (rm *Manager) MissingRoutes() []Rule {
	kernel, err := KernelTable()
	if err != nil {
		return nil
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()

	missing := make([]Rule, 0)
	for _, r := range rm.routes {
		if r.Paused {
			continue
		}
		if !KernelHasRoute(kernel, r.Destination, r.Gateway) {
			missing = append(missing, r)
		}
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i].Destination < missing[j].Destination })
	return missing
}

// RestoreRoutes 重新下发指定的路由（destinations 为空表示重下所有失效的）。
func (rm *Manager) RestoreRoutes(destinations []string) (restored []string, failed []OpError) {
	rm.mu.Lock()
	targets := make([]Rule, 0, len(destinations))
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

	kernel, _ := KernelTable()
	for _, r := range targets {
		if r.Paused {
			continue // 暂停中的不要重新下发
		}
		if kernel != nil && KernelHasRoute(kernel, r.Destination, r.Gateway) {
			continue // 已经在内核里，不重复下发
		}
		if err := execOSRoute("add", r.Destination, r.Gateway, r.Interface); err != nil {
			// 内核里本来就有这条：读不到路由表的平台（或对账之后被别处补上的）
			// 会走到这儿，这是期望结果而不是失败
			if isRouteExistsError(err) {
				continue
			}
			log.Printf("[State] 重新下发失败 %s -> %s: %v", r.Destination, r.Gateway, err)
			failed = append(failed, OpError{Destination: r.Destination, Error: err.Error()})
			continue
		}
		log.Printf("[State] 已重新下发: %s -> %s (来源: %s)", r.Destination, r.Gateway, origin(r.Domains))
		restored = append(restored, r.Destination)
	}
	return restored, failed
}

// rescopeTarget 决定一条路由要不要换作用域网卡。
// want 为空说明网关现在哪块网卡都够不着（网线拔了之类），这时别动它——
// 撤下来反而更糟，等网络恢复下一轮再说。
func rescopeTarget(current, want string) (string, bool) {
	if want == "" || want == current {
		return current, false
	}
	return want, true
}

// RescopeRoutes 修正作用域网卡与网关实际所在网卡不一致的路由。
//
// 作用域是添加那一刻按"网关挂在哪块网卡上"算出来并写进台账的。网关后来换了网卡
// （典型场景：把 Wi-Fi 的默认网关也设成了这个路由器，系统就把它的邻居项挪到了
// Wi-Fi 上），旧作用域里就再也解析不到这个网关，那条路由会变成黑洞——内核里看着
// 还在，走它的流量却发不出去。所以每次对账时都比一遍，不一致就按新网卡重下发。
func (rm *Manager) RescopeRoutes() (fixed []Rule, failed []OpError) {
	if runtime.GOOS != "darwin" {
		return nil, nil // 只有 macOS 的 -ifscope 有这个问题
	}

	rm.mu.Lock()
	targets := make([]Rule, 0, len(rm.routes))
	for _, r := range rm.routes {
		targets = append(targets, r)
	}
	rm.mu.Unlock()
	sort.Slice(targets, func(i, j int) bool { return targets[i].Destination < targets[j].Destination })

	for _, r := range targets {
		if r.Paused {
			continue // 暂停中的本来就不在内核里
		}
		want, need := rescopeTarget(r.Interface, scopeInterface(r.Gateway))
		if !need {
			continue
		}

		log.Printf("[Router] 作用域已变化 %s -> %s: %s → %s，重新下发",
			r.Destination, r.Gateway, netutil.OrDash(r.Interface), want)

		// 先按旧作用域撤掉，撤不掉（本来就没有）不算失败
		if err := execOSRoute("del", r.Destination, r.Gateway, r.Interface); err != nil && !isRouteMissingError(err) {
			log.Printf("[Router] 撤下旧作用域路由失败 %s: %v", r.Destination, err)
			failed = append(failed, OpError{Destination: r.Destination, Error: err.Error()})
			continue
		}
		if err := execOSRoute("add", r.Destination, r.Gateway, want); err != nil && !isRouteExistsError(err) {
			log.Printf("[Router] 按新作用域下发失败 %s: %v", r.Destination, err)
			failed = append(failed, OpError{Destination: r.Destination, Error: err.Error()})
			continue
		}

		rm.mu.Lock()
		if cur, ok := rm.routes[r.Destination]; ok {
			cur.Interface = want
			rm.routes[r.Destination] = cur
			r = cur
		}
		rm.persistLocked()
		rm.mu.Unlock()
		fixed = append(fixed, r)
	}

	if len(fixed) > 0 {
		log.Printf("[Router] 已修正 %d 条路由的作用域网卡", len(fixed))
	}
	return fixed, failed
}
