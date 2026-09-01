package cftunnel

// 配置持久化：默认和路由台账、DNS 配置放在同一目录，方便一并备份。
//
// 与别的几份配置不同，这份里有机密（API Token 与各隧道的连接器令牌），所以文件
// 权限是 0600 而不是 0644 —— 拿到连接器令牌就等于拿到那条隧道。

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	"nettool/internal/netutil"
)

const configVersion = 1

type configFile struct {
	Version  int       `json:"version"`
	SavedAt  time.Time `json:"saved_at"`
	Settings Settings  `json:"settings"`
	Tunnels  []Tunnel  `json:"tunnels"`
}

// ResolveConfigFile 决定配置文件落在哪里：显式指定 > 路由台账同目录
func ResolveConfigFile(flagVal, routeState string) string {
	if flagVal != "" {
		if err := netutil.EnsureStateDir(flagVal); err != nil {
			log.Printf("[CFTunnel] 无法使用指定的配置文件 %s: %v，本次运行不持久化隧道配置", flagVal, err)
			return ""
		}
		return flagVal
	}
	if routeState == "" {
		log.Printf("[CFTunnel] 未启用持久化，隧道配置只存在于内存中")
		return ""
	}
	path := filepath.Join(filepath.Dir(routeState), "cftunnel.json")
	if err := netutil.EnsureStateDir(path); err != nil {
		log.Printf("[CFTunnel] 配置文件 %s 不可写: %v，本次运行不持久化", path, err)
		return ""
	}
	return path
}

// Load 读入已保存的配置；文件不存在或损坏时保持空配置
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
			log.Printf("[CFTunnel] 读取配置失败 %s: %v", path, err)
		}
		return false
	}
	if len(data) == 0 {
		return false
	}

	var state configFile
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("[CFTunnel] 配置文件损坏 %s: %v（本次忽略，不会覆盖）", path, err)
		m.path = "" // 别拿空配置把用户存的东西盖掉
		return false
	}

	m.settings = state.Settings.normalized()
	m.order = m.order[:0]
	for _, t := range state.Tunnels {
		if t.ID == "" || t.CFID == "" {
			continue // 半截记录，留着只会在界面上变成一行点不动的东西
		}
		m.tunnels[t.ID] = t
		m.procs[t.ID] = &process{label: "隧道「" + t.Name + "」"}
		m.order = append(m.order, t.ID)
	}
	log.Printf("[CFTunnel] 载入 %d 条隧道", len(m.order))
	return true
}

// persistLocked 需持有 m.mu
func (m *Manager) persistLocked() {
	if m.path == "" {
		return
	}
	state := configFile{Version: configVersion, SavedAt: time.Now(), Settings: m.settings}
	for _, id := range m.order {
		if t, ok := m.tunnels[id]; ok {
			state.Tunnels = append(state.Tunnels, t)
		}
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		log.Printf("[CFTunnel] 序列化配置失败: %v", err)
		return
	}
	// 0600：里面是 API Token 和连接器令牌
	if err := netutil.WriteFileAtomic(m.path, data, 0o600); err != nil {
		log.Printf("[CFTunnel] 写入配置失败 %s: %v", m.path, err)
	}
}

// ConfigPath 返回当前生效的配置文件路径（空表示本次运行不持久化）
func (m *Manager) ConfigPath() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.path
}
