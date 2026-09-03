package netconfig

// Wi-Fi 配置档的存取：一个 SSID 一份网卡配置，存成 JSON，
// 默认与路由台账放在同一目录，便于一起备份。

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"nettool/internal/netutil"
)

const profileVersion = 1

// defaultProfileName 是默认档（兜底）在没起名字时用的名称
const defaultProfileName = "其他 Wi-Fi"

type profileFile struct {
	Version  int       `json:"version"`
	SavedAt  time.Time `json:"saved_at"`
	Profiles []Profile `json:"profiles"`
}

// ProfileStore 是全部 Wi-Fi 配置档，按 SSID 索引
type ProfileStore struct {
	mu       sync.Mutex
	profiles map[string]Profile
	path     string
}

// Profiles 是本进程唯一的配置档仓库
var Profiles = &ProfileStore{profiles: make(map[string]Profile)}

// ResolveProfileFile 决定配置档文件落在哪里：显式指定 > 路由台账同目录
func ResolveProfileFile(flagVal, routeState string) string {
	if flagVal != "" {
		if err := netutil.EnsureStateDir(flagVal); err != nil {
			log.Printf("[NetConfig] 无法使用指定的配置档文件 %s: %v，本次运行不持久化 Wi-Fi 配置档", flagVal, err)
			return ""
		}
		return flagVal
	}
	if routeState == "" {
		log.Printf("[NetConfig] 未启用持久化，Wi-Fi 配置档只存在于内存中")
		return ""
	}
	path := filepath.Join(filepath.Dir(routeState), "net-profiles.json")
	if err := netutil.EnsureStateDir(path); err != nil {
		log.Printf("[NetConfig] 配置档文件 %s 不可写: %v，本次运行不持久化", path, err)
		return ""
	}
	return path
}

func (s *ProfileStore) Load(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = path
	if path == "" {
		return 0
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[NetConfig] 读取配置档失败 %s: %v", path, err)
		}
		return 0
	}
	if len(data) == 0 {
		return 0
	}

	var state profileFile
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("[NetConfig] 配置档文件损坏 %s: %v（本次忽略，不会覆盖）", path, err)
		s.path = "" // 别用空数据把用户的配置覆盖掉
		return 0
	}
	for _, p := range state.Profiles {
		s.profiles[p.SSID] = p
	}
	return len(s.profiles)
}

// Path 返回配置档文件路径，空串表示没有持久化
func (s *ProfileStore) Path() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path
}

// persistLocked 调用方必须已持有 s.mu
func (s *ProfileStore) persistLocked() {
	if s.path == "" {
		return
	}
	data, err := json.MarshalIndent(profileFile{
		Version:  profileVersion,
		SavedAt:  time.Now(),
		Profiles: s.listLocked(),
	}, "", "  ")
	if err != nil {
		log.Printf("[NetConfig] 序列化配置档失败: %v", err)
		return
	}
	if err := netutil.WriteFileAtomic(s.path, data, 0o600); err != nil {
		log.Printf("[NetConfig] 写入配置档失败 %s: %v", s.path, err)
	}
}

func (s *ProfileStore) listLocked() []Profile {
	list := make([]Profile, 0, len(s.profiles))
	for _, p := range s.profiles {
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].SSID < list[j].SSID })
	return list
}

func (s *ProfileStore) List() []Profile {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listLocked()
}

func (s *ProfileStore) Get(ssid string) (Profile, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.profiles[ssid]
	return p, ok
}

// matchKind 说明一份配置档是"怎么"被选中的。调用方需要区分它们：
// 按指纹或 SSID 命中的是"这个网络专属的配置"，而 matchDefault 只是兜底——
// 所有没单独配置的 Wi-Fi 都会落到同一份默认档上，看起来像"自动切换不工作了"。
type matchKind int

const (
	matchNone        matchKind = iota // 没有任何配置档可用
	matchSSID                         // 按 SSID 精确命中
	matchFingerprint                  // 按系统给的网络指纹命中
	matchDefault                      // 都没命中，用的是兜底的默认档
)

// match 找出当前 Wi-Fi 对应的配置档
func (s *ProfileStore) match(id wifiIdentity) (Profile, bool) {
	p, kind := s.matchDetail(id)
	return p, kind != matchNone
}

// matchDetail 找出当前 Wi-Fi 对应的配置档，并说明是怎么命中的：
// 优先按 SSID 精确匹配，SSID 读不到（或没记 SSID）时按系统给的网络指纹匹配，
// 都对不上才退到默认档。
func (s *ProfileStore) matchDetail(id wifiIdentity) (Profile, matchKind) {
	if id.empty() {
		return Profile{}, matchNone // 没连 Wi-Fi 就不该套用任何配置档，默认档也不行
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if id.SSID != "" {
		if p, ok := s.profiles[id.SSID]; ok {
			return p, matchSSID
		}
	}
	if id.NetworkID != "" {
		for _, p := range s.listLocked() {
			if p.NetworkID == id.NetworkID {
				return p, matchFingerprint
			}
		}
	}
	// 都对不上就用默认档（"其他 Wi-Fi"），没有默认档才算真的没匹配
	if p, ok := s.defaultProfileLocked(); ok {
		return p, matchDefault
	}
	return Profile{}, matchNone
}

// unboundCount 数一数有多少份"只认 SSID、没绑指纹"的配置档。
//
// 这个数字只在系统不给读 SSID 时才有意义（macOS 14 起的隐私限制）：那种情况下
// 这些配置档**永远匹配不到任何网络**，所有 Wi-Fi 都会落到默认档上，表现出来就是
// "自动切换只生效了一次，之后再也不动"。界面据此给出提示。
func (s *ProfileStore) unboundCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, p := range s.profiles {
		if !p.IsDefault && p.NetworkID == "" {
			n++
		}
	}
	return n
}

// bindNetworkID 把系统给的网络指纹记到某份配置档上，让它之后能被自动匹配到。
// 已经绑过别的指纹就不动——那是用户自己绑的，不该被覆盖。
func (s *ProfileStore) bindNetworkID(ssid, networkID string) bool {
	if ssid == "" || networkID == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.profiles[ssid]
	if !ok || p.IsDefault || p.NetworkID != "" {
		return false
	}
	p.NetworkID = networkID
	p.UpdatedAt = time.Now()
	s.profiles[ssid] = p
	s.persistLocked()
	return true
}

// defaultProfileLocked 调用方必须已持有 s.mu
func (s *ProfileStore) defaultProfileLocked() (Profile, bool) {
	for _, p := range s.listLocked() {
		if p.IsDefault {
			return p, true
		}
	}
	return Profile{}, false
}

// Save 新增或覆盖一个 SSID 的配置档
func (s *ProfileStore) Save(p Profile) (Profile, error) {
	p.SSID = strings.TrimSpace(p.SSID)
	if p.SSID == "" {
		if !p.IsDefault {
			return p, fmt.Errorf("SSID 不能为空")
		}
		p.SSID = defaultProfileName // 默认档不针对某个具体 Wi-Fi，给它一个固定名字
	}
	if strings.TrimSpace(p.Service) == "" {
		return p, fmt.Errorf("请选择要配置的网卡（网络服务）")
	}
	settings, err := ValidateSettings(p.Settings)
	if err != nil {
		return p, err
	}
	p.Settings = settings

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if old, ok := s.profiles[p.SSID]; ok {
		p.CreatedAt = old.CreatedAt
		p.LastAppliedAt = old.LastAppliedAt
		if p.NetworkID == "" {
			p.NetworkID = old.NetworkID // 编辑时没带指纹就沿用原来的
		}
	} else {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	p.LastError = ""
	if p.IsDefault {
		p.NetworkID = "" // 默认档是兜底的，不该绑到某个具体网络上
		// 默认档只能有一个，新的顶掉旧的
		for k, other := range s.profiles {
			if k != p.SSID && other.IsDefault {
				other.IsDefault = false
				s.profiles[k] = other
			}
		}
	}
	s.profiles[p.SSID] = p
	s.persistLocked()
	return p, nil
}

func (s *ProfileStore) Delete(ssid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.profiles[ssid]; !ok {
		return false
	}
	delete(s.profiles, ssid)
	s.persistLocked()
	return true
}

func (s *ProfileStore) SetEnabled(ssid string, enabled bool) (Profile, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.profiles[ssid]
	if !ok {
		return p, false
	}
	p.Enabled = enabled
	p.UpdatedAt = time.Now()
	s.profiles[ssid] = p
	s.persistLocked()
	return p, true
}

// markApplied 记录一次下发结果
func (s *ProfileStore) markApplied(ssid string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.profiles[ssid]
	if !ok {
		return
	}
	if err != nil {
		p.LastError = err.Error()
	} else {
		now := time.Now()
		p.LastAppliedAt = &now
		p.LastError = ""
	}
	s.profiles[ssid] = p
	s.persistLocked()
}
