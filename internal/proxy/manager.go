package proxy

// 多实例管理：实例的增删改查与启停，以及"哪个端口被谁占了"这类跨实例的判断。
//
// 加锁的纪律（很重要，多实例之后这里很容易写出死锁）：
//   - 允许的顺序只有 Server.mu → Manager.mu，绝不反过来。
//   - 因此 Manager 永远不去拿任何 Server 的锁。它自己留一份 configs 快照，
//     由各实例在配置变动时同步过来，落盘和端口冲突检查都只读这份快照。

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"nettool/internal/sockopt"
)

// defaultListen 是新实例以及旧台账里没有 listen 字段时的监听地址
const defaultListen = "127.0.0.1"

// Instance 是一个代理实例的配置，也是台账与接口共用的形状
type Instance struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Port string `json:"port"`
	// Listen 是监听地址，空等于 127.0.0.1。默认只听本机是有意的：
	// SOCKS5 这边没有任何客户端鉴权（conf.Rules 用的是 socks5.PermitAll），
	// 绑 0.0.0.0 就成了一台谁都能用的开放代理，出口 IP 记的是机主。
	// 路由器上要给局域网设备用，把它显式改成 0.0.0.0。
	Listen string `json:"listen,omitempty"`
	// UplinkID 是本实例的出口，空表示走系统默认线路。
	// 出口只有这一个来源：走哪个网关是路由查询决定的，而 mark 决定查哪张表。
	UplinkID  string    `json:"uplink_id,omitempty"`
	DNS       string    `json:"dns,omitempty"`
	Running   bool      `json:"running"` // 用户的开关意愿，不是此刻的实况
	CreatedAt time.Time `json:"created_at"`

	// LegacyOutboundIP 只用于读旧配置：以前是靠绑定源地址来"指定网关"的，
	// 但绑源地址并不能决定走哪个网关（同一网卡上的多个地址通常仍走同一条默认
	// 路由）。载入时会把它翻译成一条出口线路，然后清空，之后再也不写回文件。
	LegacyOutboundIP string `json:"outbound_ip,omitempty"`
}

func (c Instance) normalized() Instance {
	c.ID = strings.TrimSpace(c.ID)
	c.Name = strings.TrimSpace(c.Name)
	c.Port = strings.TrimSpace(c.Port)
	c.Listen = strings.TrimSpace(c.Listen)
	if c.Listen == "" {
		c.Listen = defaultListen
	}
	c.UplinkID = strings.TrimSpace(c.UplinkID)
	c.DNS = strings.TrimSpace(c.DNS)
	c.LegacyOutboundIP = strings.TrimSpace(c.LegacyOutboundIP)
	if c.Name == "" {
		c.Name = "代理 " + c.Port
	}
	return c
}

func (c Instance) validatePort() error {
	if c.Port == "" {
		return fmt.Errorf("端口不能为空")
	}
	n, err := strconv.Atoi(c.Port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("端口 %q 不合法", c.Port)
	}
	return nil
}

func (c Instance) validateListen() error {
	if net.ParseIP(c.Listen) == nil {
		return fmt.Errorf("监听地址 %q 不是合法 IP", c.Listen)
	}
	return nil
}

// UplinkLookup 是 proxy 需要从 uplink 包拿到的全部东西。
// 用小接口而不是直接依赖 uplink 单例，测试里就能塞一个假的进来。
type UplinkLookup interface {
	// DialOptions 给出拨号时要施加的出口约束（socket 标记、源地址、源端口段）
	DialOptions(uplinkID string) (sockopt.Egress, error)
	// EnsureForSourceIP 只在载入旧配置时用一次，把老的「绑定出口 IP」翻译成线路
	EnsureForSourceIP(sourceIP, name string) (string, error)
}

// Manager 持有全部代理实例
type Manager struct {
	mu      sync.Mutex
	path    string   // 台账文件，空表示本次运行不持久化
	order   []string // 稳定的展示顺序
	servers map[string]*Server
	configs map[string]Instance // 落盘快照，见文件头的加锁纪律
	uplinks UplinkLookup
}

func NewManager() *Manager {
	return &Manager{
		servers: make(map[string]*Server),
		configs: make(map[string]Instance),
	}
}

// Default 是本进程的代理实例集合
var Default = NewManager()

// SetUplinks 接上出口线路查询。没接的话，绑定了线路的实例会拒绝启动。
func (m *Manager) SetUplinks(u UplinkLookup) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.uplinks = u
}

func (m *Manager) uplinkLookup() UplinkLookup {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.uplinks
}

// List 返回全部实例，按创建顺序
func (m *Manager) List() []*Server {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Server, 0, len(m.servers))
	for _, id := range m.order {
		if s, ok := m.servers[id]; ok {
			out = append(out, s)
		}
	}
	return out
}

func (m *Manager) Get(id string) (*Server, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.servers[id]
	return s, ok
}

// Primary 返回主实例，供保持兼容的老接口使用（/api/status 等）。
// 没有任何实例时返回 nil，调用方要判空。
func (m *Manager) Primary() *Server {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range m.order {
		if s, ok := m.servers[id]; ok {
			return s
		}
	}
	return nil
}

func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.servers)
}

// Add 新建一个实例（只落配置，不自动启动）
func (m *Manager) Add(cfg Instance) (*Server, error) {
	cfg = cfg.normalized()
	if err := cfg.validatePort(); err != nil {
		return nil, err
	}

	m.mu.Lock()
	if err := m.checkPortFreeLocked("", cfg.Port); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	cfg.ID = m.nextIDLocked()
	cfg.CreatedAt = time.Now()
	cfg.Running = false
	s := m.newServerLocked(cfg)
	m.mu.Unlock()

	// 走 SetConfig 而不是直接塞进去：端口冲突、出口线路、DNS 的校验都在那儿，
	// 存进一份启动时才报错的配置对用户没有任何好处
	if err := s.SetConfig(cfg); err != nil {
		m.Delete(cfg.ID)
		return nil, err
	}
	log.Printf("[SOCKS5] 新建实例「%s」（端口 %s）", cfg.Name, cfg.Port)
	return s, nil
}

// newServerLocked 需持有 m.mu
func (m *Manager) newServerLocked(cfg Instance) *Server {
	s := &Server{mgr: m, id: cfg.ID, stats: newStats(), createdAt: cfg.CreatedAt}
	s.applyConfigLocked(cfg)
	s.wantRunning = cfg.Running
	m.servers[cfg.ID] = s
	m.configs[cfg.ID] = cfg
	m.order = append(m.order, cfg.ID)
	return s
}

// Delete 删除一个实例，先把它停掉
func (m *Manager) Delete(id string) error {
	s, ok := m.Get(id)
	if !ok {
		return fmt.Errorf("代理实例 %s 不存在", id)
	}
	name := s.Config().Name
	if err := s.Stop(); err != nil {
		log.Printf("[SOCKS5] 停止实例「%s」时出错: %v", name, err)
	}

	m.mu.Lock()
	delete(m.servers, id)
	delete(m.configs, id)
	for i, x := range m.order {
		if x == id {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	m.persistLocked()
	m.mu.Unlock()

	log.Printf("[SOCKS5] 已删除实例「%s」", name)
	return nil
}

// sync 由实例在配置变动时调用，把最新配置同步进落盘快照并写盘。
// 调用方可能正持有 Server.mu，这里只拿 Manager.mu，符合文件头的加锁纪律。
func (m *Manager) sync(cfg Instance) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.servers[cfg.ID]; !ok {
		return // 已经被删掉了，别把它写回台账
	}
	m.configs[cfg.ID] = cfg
	m.persistLocked()
}

// checkPortFree 检查端口有没有被别的实例占用。exceptID 是自己（改配置时用）。
//
// 单独查一遍是为了给出人话：不查的话用户只会看到 bind: address already in use，
// 看不出是被自己的哪个实例占了。
func (m *Manager) checkPortFree(exceptID, port string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.checkPortFreeLocked(exceptID, port)
}

func (m *Manager) checkPortFreeLocked(exceptID, port string) error {
	for id, cfg := range m.configs {
		if id == exceptID {
			continue
		}
		if cfg.Port == port {
			return fmt.Errorf("端口 %s 已被实例「%s」占用", port, cfg.Name)
		}
	}
	return nil
}

// nextIDLocked 生成不与现有实例冲突的 ID。需持有 m.mu。
func (m *Manager) nextIDLocked() string {
	maxN := 0
	for id := range m.servers {
		if n, err := strconv.Atoi(strings.TrimPrefix(id, "p")); err == nil && n > maxN {
			maxN = n
		}
	}
	return "p" + strconv.Itoa(maxN+1)
}

// TotalsSnapshot 汇总全部实例的流量与连接数，供界面顶部的统计卡使用
func (m *Manager) TotalsSnapshot() map[string]interface{} {
	var in, out, total int64
	active, running := 0, 0
	servers := m.List()
	for _, s := range servers {
		snap := s.Stats().Snapshot()
		in += snap["total_bytes_in"].(int64)
		out += snap["total_bytes_out"].(int64)
		total += snap["total_connections"].(int64)
		active += snap["active_connections_count"].(int)
		if s.Running() {
			running++
		}
	}
	return map[string]interface{}{
		"total_bytes_in":           in,
		"total_bytes_out":          out,
		"total_connections":        total,
		"active_connections_count": active,
		"instances":                len(servers),
		"running_instances":        running,
	}
}

// StartSaved 按各实例保存下来的开关意愿把它们拉起来，供进程启动时调用。
// force 为真时无条件启动全部实例（对应 -start-proxy）。
func (m *Manager) StartSaved(force bool) {
	for _, s := range m.List() {
		cfg := s.Config()
		if !force && !s.WasRunning() {
			log.Printf("[SOCKS5] 实例「%s」上次退出时是停止的，本次不自动启动（端口 %s），可在 Web 后台点击启动",
				cfg.Name, cfg.Port)
			continue
		}
		if err := s.StartCurrent(); err != nil {
			// 起不来只提示一声，让 Web 后台还进得去、用户能改完配置再启动。
			// 这里不 Fatal：多实例下一个实例起不来不该拖垮整个进程。
			log.Printf("[SOCKS5] 启动实例「%s」失败: %v，该实例保持停止", cfg.Name, err)
		}
	}
}
