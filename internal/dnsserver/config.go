package dnsserver

// 配置持久化：默认和路由台账、Wi-Fi 配置档放在同一目录，方便一并备份。

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"lan_router_socks5/internal/netutil"
)

type configFile struct {
	Version int       `json:"version"`
	SavedAt time.Time `json:"saved_at"`
	// Running 记的是用户的意愿而不是此刻的实况：点了启动为 true，点了停止为 false。
	// 启动失败（53 端口被占等）不会把它改掉，下次起来还会再试一次。
	Running  bool     `json:"running"`
	Settings Settings `json:"settings"`
}

// configPath 为空表示本次运行不持久化
var configPath string

// ConfigPath 返回当前生效的配置文件路径
func ConfigPath() string { return configPath }

// ResolveConfigFile 决定配置文件落在哪里：显式指定 > 路由台账同目录
func ResolveConfigFile(flagVal, routeState string) string {
	if flagVal != "" {
		if err := netutil.EnsureStateDir(flagVal); err != nil {
			log.Printf("[DNS] 无法使用指定的配置文件 %s: %v，本次运行不持久化 DNS 配置", flagVal, err)
			return ""
		}
		return flagVal
	}
	if routeState == "" {
		log.Printf("[DNS] 未启用持久化，DNS 配置只存在于内存中")
		return ""
	}
	path := filepath.Join(filepath.Dir(routeState), "dns.json")
	if err := netutil.EnsureStateDir(path); err != nil {
		log.Printf("[DNS] 配置文件 %s 不可写: %v，本次运行不持久化", path, err)
		return ""
	}
	return path
}

// Load 读入已保存的配置；文件不存在或损坏时保留默认配置
func (s *Server) Load(path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	configPath = path
	if path == "" {
		return false
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[DNS] 读取配置失败 %s: %v", path, err)
		}
		return false
	}
	if len(data) == 0 {
		return false
	}

	var state configFile
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("[DNS] 配置文件损坏 %s: %v（本次忽略，不会覆盖）", path, err)
		configPath = "" // 别拿空配置把用户存的东西盖掉
		return false
	}
	cleaned, err := validateSettings(state.Settings)
	if err != nil {
		log.Printf("[DNS] 配置文件里的设置不合法: %v，改用默认配置", err)
		return false
	}
	s.settings = cleaned
	s.wantRunning = state.Running
	return true
}

// persistLocked 需持有 s.mu
func (s *Server) persistLocked() {
	if configPath == "" {
		return
	}
	data, err := json.MarshalIndent(configFile{
		Version:  configVersion,
		SavedAt:  time.Now(),
		Running:  s.wantRunning,
		Settings: s.settings,
	}, "", "  ")
	if err != nil {
		log.Printf("[DNS] 序列化配置失败: %v", err)
		return
	}
	if err := netutil.WriteFileAtomic(configPath, data, 0o644); err != nil {
		log.Printf("[DNS] 写入配置失败 %s: %v", configPath, err)
	}
}

// ApplyFlags 把命令行给的监听地址/端口/上游合进已载入的配置。
// 上游只在配置里还是空的时候才用命令行那份——否则每次带参数启动都会
// 把用户在后台调好的上游列表冲掉。
func ApplyFlags(listen, port, upstreams string) error {
	s := Default.Settings()
	changed := false

	if v := strings.TrimSpace(listen); v != "" {
		s.Listen, changed = v, true
	}
	if v := strings.TrimSpace(port); v != "" {
		s.Port, changed = v, true
	}
	if v := strings.TrimSpace(upstreams); v != "" && len(s.Upstreams) == 0 {
		for _, item := range strings.Split(v, ",") {
			if item = strings.TrimSpace(item); item != "" {
				s.Upstreams = append(s.Upstreams, Upstream{Address: item, Enabled: true})
			}
		}
		changed = true
	}

	if !changed {
		return nil
	}
	return Default.SetConfig(s)
}
