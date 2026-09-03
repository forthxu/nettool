package proxy

// 配置与开关状态持久化：默认和路由台账、DNS 配置放在同一目录，方便一并备份。
//
// 存的不只是端口/出口线路/代理 DNS，还有「上次是开着还是关着」——
// 进程重启（升级、崩溃、机器重启）后按这个状态自动恢复，
// 免得每次都要再去后台点一次「启动代理」。

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"nettool/internal/netutil"
)

// configVersion 2 起改成实例列表。v1 是单个扁平对象，载入时迁移成一个实例，
// 迁移逻辑见 Load。
const configVersion = 2

// configFile 同时容得下 v1 和 v2 两种形状，这样一次 Unmarshal 就能判断该走哪条路。
// 仓库里已有同样的做法：route.Rule.LegacyDomain（route/model.go）。
type configFile struct {
	Version   int        `json:"version"`
	SavedAt   time.Time  `json:"saved_at"`
	Instances []Instance `json:"instances,omitempty"`

	// v1 的扁平字段。Running 用指针是为了区分"没有这个字段"和"字段是 false"，
	// 否则一份只写了端口的 v1 配置会被误判成没有内容。
	LegacyRunning    *bool  `json:"running,omitempty"`
	LegacyPort       string `json:"port,omitempty"`
	LegacyOutboundIP string `json:"outbound_ip,omitempty"`
	LegacyDNS        string `json:"dns,omitempty"`
}

// ConfigPath 返回当前生效的配置文件路径，空串表示没有持久化
func (m *Manager) ConfigPath() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.path
}

// ResolveConfigFile 决定配置文件落在哪里：显式指定 > 路由台账同目录
func ResolveConfigFile(flagVal, routeState string) string {
	if flagVal != "" {
		if err := netutil.EnsureStateDir(flagVal); err != nil {
			log.Printf("[SOCKS5] 无法使用指定的配置文件 %s: %v，本次运行不持久化代理配置", flagVal, err)
			return ""
		}
		return flagVal
	}
	if routeState == "" {
		log.Printf("[SOCKS5] 未启用持久化，代理配置只存在于内存中")
		return ""
	}
	path := filepath.Join(filepath.Dir(routeState), "proxy.json")
	if err := netutil.EnsureStateDir(path); err != nil {
		log.Printf("[SOCKS5] 配置文件 %s 不可写: %v，本次运行不持久化", path, err)
		return ""
	}
	return path
}

// defaultInstance 是没有任何配置时的起点，与改造前的默认值一致
func defaultInstance() Instance {
	return Instance{ID: "p1", Name: "默认代理", Port: "8091", Listen: defaultListen, CreatedAt: time.Now()}
}

// Load 读入上次保存的实例列表与各自的开关状态。
// 文件不存在时建一个默认实例；文件损坏时保留默认值并停用持久化。
// 出口线路不在这里校验：线路可能还没下发完，真到启动那一步再报错更准确。
func (m *Manager) Load(path string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.path = path

	data, err := m.readConfigLocked(path)
	if err != nil || len(data) == 0 {
		m.newServerLocked(defaultInstance())
		return false
	}

	var state configFile
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("[SOCKS5] 配置文件损坏 %s: %v（本次忽略，不会覆盖）", path, err)
		m.path = "" // 别拿空配置把用户存的东西盖掉
		m.newServerLocked(defaultInstance())
		return false
	}

	instances := state.Instances
	if state.Version < configVersion && len(instances) == 0 {
		if legacy, ok := migrateV1(state); ok {
			// 先把原文件备份一份再写 v2，让降级回旧版本仍有退路
			m.backupLegacyLocked(path, data)
			instances = []Instance{legacy}
		}
	}
	if len(instances) == 0 {
		m.newServerLocked(defaultInstance())
		return false
	}

	for i := range instances {
		instances[i] = sanitizeInstance(instances[i])
	}
	// 建实例之前先把旧的「绑定出口 IP」翻译成出口线路，免得升级后出口静默改变
	migrated := m.migrateOutboundIPsLocked(instances)

	for _, cfg := range instances {
		if cfg.ID == "" {
			cfg.ID = m.nextIDLocked()
		}
		if _, dup := m.servers[cfg.ID]; dup {
			log.Printf("[SOCKS5] 配置里有重复的实例 id %q，已跳过后一条", cfg.ID)
			continue
		}
		m.newServerLocked(cfg)
	}
	log.Printf("[SOCKS5] 配置 %s: 载入 %d 个代理实例", path, len(m.servers))
	if migrated {
		m.persistLocked() // 把清空 outbound_ip、补上 uplink_id 的结果落盘
	}
	return true
}

// migrateOutboundIPsLocked 把旧配置里的「绑定出口 IP」转成出口线路绑定，就地改写
// instances 并清空该字段。返回是否发生过迁移。需持有 m.mu。
//
// 为什么要转而不是直接丢：那个 IP 表达的意图是"走这块网卡的网关"。直接丢掉，
// 升级后实例就悄悄改从默认网关出去了——用户看不到任何提示，是最难排查的一类故障。
//
// 转换可能失败（网卡拔了、没有 root 装不了规则）。那种情况下仍然绑定这条线路：
// 线路未生效时实例会拒绝启动并在界面上报出原因，好过静默走错出口。
func (m *Manager) migrateOutboundIPsLocked(instances []Instance) bool {
	migrated := false
	for i := range instances {
		ip := instances[i].LegacyOutboundIP
		if ip == "" {
			continue
		}
		instances[i].LegacyOutboundIP = ""
		migrated = true

		name := instances[i].Name
		if instances[i].UplinkID != "" {
			log.Printf("[SOCKS5] 实例「%s」已绑定出口线路 %s，旧的出口 IP %s 不再使用",
				name, instances[i].UplinkID, ip)
			continue
		}
		if m.uplinks == nil {
			log.Printf("[SOCKS5] 实例「%s」原先绑定出口 IP %s，但本进程未启用出口线路管理，"+
				"该实例将走系统默认线路", name, ip)
			continue
		}

		id, err := m.uplinks.EnsureForSourceIP(ip, name+" 出口")
		if id == "" {
			log.Printf("[SOCKS5] 实例「%s」原先绑定的出口 IP %s 无法转成出口线路: %v。"+
				"该实例将走系统默认线路，请在「路由管理 → 出口线路」里重新配置", name, ip, err)
			continue
		}
		instances[i].UplinkID = id
		if err != nil {
			log.Printf("[SOCKS5] 实例「%s」的出口 IP %s 已转为出口线路 %s，但该线路下发失败: %v。"+
				"实例会拒绝启动，请到「路由管理 → 出口线路」处理后再启动", name, ip, id, err)
			continue
		}
		log.Printf("[SOCKS5] 实例「%s」的出口 IP %s 已转为出口线路 %s（走哪个网关改由路由决定）",
			name, ip, id)
	}
	return migrated
}

func (m *Manager) readConfigLocked(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[SOCKS5] 读取配置失败 %s: %v", path, err)
			return nil, err
		}
		return nil, nil
	}
	return data, nil
}

// migrateV1 把 v1 的单个扁平对象迁成一个实例。
// 全部字段都为空说明这份配置没有内容，返回 false 让调用方走默认值。
func migrateV1(state configFile) (Instance, bool) {
	if state.LegacyPort == "" && state.LegacyOutboundIP == "" &&
		state.LegacyDNS == "" && state.LegacyRunning == nil {
		return Instance{}, false
	}
	cfg := defaultInstance()
	if state.LegacyPort != "" {
		cfg.Port = state.LegacyPort
	}
	cfg.LegacyOutboundIP = state.LegacyOutboundIP
	cfg.DNS = state.LegacyDNS
	if state.LegacyRunning != nil {
		cfg.Running = *state.LegacyRunning
	}
	if !state.SavedAt.IsZero() {
		cfg.CreatedAt = state.SavedAt
	}
	log.Printf("[SOCKS5] 已把旧版单实例配置迁移为实例「%s」（端口 %s）", cfg.Name, cfg.Port)
	return cfg, true
}

// backupLegacyLocked 在第一次写出 v2 之前留一份 v1 原文，只做一次。
// 多花一次写入，换来的是"降级回旧版本"这条退路仍然存在。
func (m *Manager) backupLegacyLocked(path string, data []byte) {
	if path == "" {
		return
	}
	backup := path + ".v1.bak"
	if _, err := os.Stat(backup); err == nil {
		return // 已经备份过，别拿新内容盖掉最初那份
	}
	if err := netutil.WriteFileAtomic(backup, data, 0o600); err != nil {
		log.Printf("[SOCKS5] 备份旧版配置到 %s 失败: %v", backup, err)
		return
	}
	log.Printf("[SOCKS5] 旧版配置已备份到 %s", backup)
}

// sanitizeInstance 逐字段校验台账里的配置，坏掉的字段退回默认值而不是整条丢弃：
// 用户改坏一个端口号，不该让整个实例连同它的出口线路配置一起消失。
func sanitizeInstance(cfg Instance) Instance {
	cfg = cfg.normalized()
	if cfg.Port != "" {
		if n, err := strconv.Atoi(cfg.Port); err != nil || n < 1 || n > 65535 {
			log.Printf("[SOCKS5] 配置文件里的端口 %q 不合法，改用 8091", cfg.Port)
			cfg.Port = "8091"
		}
	} else {
		cfg.Port = "8091"
	}
	if err := cfg.validateListen(); err != nil {
		log.Printf("[SOCKS5] 配置文件里的监听地址 %q 不合法，改用 %s", cfg.Listen, defaultListen)
		cfg.Listen = defaultListen
	}
	if cfg.LegacyOutboundIP != "" && net.ParseIP(cfg.LegacyOutboundIP) == nil {
		log.Printf("[SOCKS5] 配置文件里的出口 IP %q 不是合法 IP，已忽略", cfg.LegacyOutboundIP)
		cfg.LegacyOutboundIP = ""
	}
	if dns, err := NormalizeDNSAddr(cfg.DNS); err != nil {
		log.Printf("[SOCKS5] 配置文件里的代理 DNS %q 无效: %v，改用系统 DNS", cfg.DNS, err)
		cfg.DNS = ""
	} else {
		cfg.DNS = dns
	}
	return cfg.normalized() // Name 可能因为端口回退而需要重算
}

// persistLocked 把全部实例写回台账。需持有 m.mu。
//
// 写的是 Manager 自己那份 configs 快照，不去读各 Server 的字段——
// 那样要拿 Server.mu，而调用方经常正是某个持有自己 Server.mu 的实例，
// 会立刻死锁。加锁纪律见 manager.go 文件头。
func (m *Manager) persistLocked() {
	if m.path == "" {
		return
	}
	list := make([]Instance, 0, len(m.configs))
	for _, id := range m.order {
		if cfg, ok := m.configs[id]; ok {
			list = append(list, cfg)
		}
	}

	data, err := json.MarshalIndent(configFile{
		Version:   configVersion,
		SavedAt:   time.Now(),
		Instances: list,
	}, "", "  ")
	if err != nil {
		log.Printf("[SOCKS5] 序列化配置失败: %v", err)
		return
	}
	if err := netutil.WriteFileAtomic(m.path, data, 0o600); err != nil {
		log.Printf("[SOCKS5] 写入配置失败 %s: %v", m.path, err)
	}
}

// ApplyFlags 把命令行给的监听地址/端口/代理 DNS 合进**主实例**的配置。
// 只有真填了的才覆盖——否则每次带默认参数启动都会把后台调好的值冲掉。
//
// 只作用于主实例：命令行参数是单实例时代留下来的，多实例只走 Web 界面与接口。
func (m *Manager) ApplyFlags(listen, port, dns string) error {
	s := m.Primary()
	if s == nil {
		return nil
	}
	cfg := s.Config()
	changed := false

	if v := strings.TrimSpace(listen); v != "" {
		cfg.Listen, changed = v, true
	}
	if v := strings.TrimSpace(port); v != "" {
		cfg.Port, changed = v, true
	}
	if v := strings.TrimSpace(dns); v != "" {
		cfg.DNS, changed = v, true
	}

	if !changed {
		return nil
	}
	return s.SetConfig(cfg)
}
