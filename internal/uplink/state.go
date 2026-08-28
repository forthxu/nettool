package uplink

// 出口线路台账。内核里的 ip rule 和路由表同样没有"谁加的"这种信息，
// 所以和 route 包一样，本程序装的每一条都要自己记账，重启后才能对账、清扫。

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	"nettool/internal/netutil"
)

const stateVersion = 1

type stateFile struct {
	Version int       `json:"version"`
	SavedAt time.Time `json:"saved_at"`
	Uplinks []Uplink  `json:"uplinks"`
	// PFToken 是 macOS 上 pfctl -E 拿到的引用令牌。记它的理由和记路由规则一样：
	// 内核不记"这个引用是谁拿的"，进程被 SIGKILL 之后令牌就丢了，那个引用再也
	// 归还不了，PF 会一直开着。落盘之后下次启动能把它还回去，见 pf.go。
	PFToken string `json:"pf_token,omitempty"`
}

// ResolveStateFile 决定台账落在哪里：显式指定 > 路由台账同目录。
// 与 proxy.ResolveConfigFile / dnsserver.ResolveConfigFile 保持一致。
func ResolveStateFile(flagVal, routeState string) string {
	if flagVal != "" {
		if err := netutil.EnsureStateDir(flagVal); err != nil {
			log.Printf("[Uplink] 无法使用指定的台账文件 %s: %v，本次运行不持久化出口线路", flagVal, err)
			return ""
		}
		return flagVal
	}
	if routeState == "" {
		log.Printf("[Uplink] 未启用持久化，出口线路只存在于内存中")
		return ""
	}
	path := filepath.Join(filepath.Dir(routeState), "uplinks.json")
	if err := netutil.EnsureStateDir(path); err != nil {
		log.Printf("[Uplink] 台账文件 %s 不可写: %v，本次运行不持久化", path, err)
		return ""
	}
	return path
}

// StatePath 返回当前生效的台账路径，空串表示没有持久化
func (m *Manager) StatePath() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.path
}

// Load 读入台账。文件损坏时把路径置空——宁可这次运行不持久化，
// 也不能拿一份空台账把用户的记录盖掉（与 route/state.go 的处理一致）。
func (m *Manager) Load(path string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.path = path
	if path == "" {
		return false
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[Uplink] 读取台账失败 %s: %v", path, err)
		}
		return false
	}
	if len(data) == 0 {
		return false
	}

	var state stateFile
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("[Uplink] 台账文件损坏 %s: %v（本次忽略，不会覆盖，请手动检查）", path, err)
		m.path = ""
		return false
	}

	NoteStalePFToken(state.PFToken)

	for _, u := range state.Uplinks {
		// 台账里的编号是当初分配好写死的，这里只做合法性检查：
		// 手工改坏了的记录不能放进来，否则会拿越界的表号去下发命令
		if err := u.validate(); err != nil {
			log.Printf("[Uplink] 台账记录 %s(%s) 不合法，已跳过: %v", u.ID, u.Name, err)
			continue
		}
		u.Applied, u.LastErr = false, ""
		m.uplinks[u.ID] = u
		m.order = append(m.order, u.ID)
	}
	log.Printf("[Uplink] 台账 %s: 载入 %d 条出口线路", path, len(m.uplinks))
	return true
}

// persistLocked 需持有 m.mu
func (m *Manager) persistLocked() {
	if m.path == "" {
		return
	}
	list := make([]Uplink, 0, len(m.uplinks))
	for _, id := range m.order {
		if u, ok := m.uplinks[id]; ok {
			list = append(list, u)
		}
	}
	data, err := json.MarshalIndent(stateFile{
		Version: stateVersion,
		SavedAt: time.Now(),
		Uplinks: list,
		PFToken: CurrentPFToken(),
	}, "", "  ")
	if err != nil {
		log.Printf("[Uplink] 序列化台账失败: %v", err)
		return
	}
	if err := netutil.WriteFileAtomic(m.path, data, 0o644); err != nil {
		log.Printf("[Uplink] 写入台账失败 %s: %v", m.path, err)
	}
}
