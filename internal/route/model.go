// Package route 管理"哪些目标走哪个网关"这件事：把用户给的 IP/网段/域名转成内核路由
// 下发下去，同时把每一条记进台账，重启后能对账、能重下发、能按域名重新解析。
//
// 内核路由表里没有"谁加的"这种信息，所以本程序下发的每一条都要自己记账。
package route

import (
	"strings"
	"sync"
	"time"
)

// Rule 是台账里的一条路由记录
type Rule struct {
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

func (r Rule) HasDomain(domain string) bool {
	for _, d := range r.Domains {
		if d == domain {
			return true
		}
	}
	return false
}

// origin 描述一条路由是怎么来的，只用于日志
func origin(domains []string) string {
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

// OpError 是单条目标上的失败，批量操作时逐条回报
type OpError struct {
	Destination string `json:"destination"`
	Error       string `json:"error"`
}

// Result 汇总一次添加请求的结果：按域名添加时一个请求会产生多条路由，
// 成功和失败的部分都要如实回报，不能只报一个笼统的成功。
type Result struct {
	Domain     string     `json:"domain,omitempty"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	Added      []Rule     `json:"added"`
	Failed     []OpError  `json:"failed,omitempty"`
}

// RefreshResult 记录一次重新解析带来的变化
type RefreshResult struct {
	Domain     string    `json:"domain"`
	ResolvedAt time.Time `json:"resolved_at"`
	Gateway    string    `json:"gateway"`
	Current    []string  `json:"current"`           // 本次解析到的全部 IP
	Added      []string  `json:"added,omitempty"`   // 新增的
	Removed    []string  `json:"removed,omitempty"` // 已不再解析到、被撤下的
	Kept       []string  `json:"kept,omitempty"`    // 不变的
	Failed     []OpError `json:"failed,omitempty"`
}

// Manager 持有台账：路由按目标索引，域名单独一份。
type Manager struct {
	mu      sync.Mutex
	routes  map[string]Rule
	domains map[string]DomainEntry
}

// Default 是本进程唯一的路由台账
var Default = &Manager{
	routes:  make(map[string]Rule),
	domains: make(map[string]DomainEntry),
}
