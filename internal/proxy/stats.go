package proxy

// 流量与连接统计：go-socks5 不提供任何观测点，所以在 Listener 和 Conn 两层各包一手，
// 连接进出的字节数、当前还活着哪些隧道都从这里出。

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ConnectionInfo 是一条正在转发的隧道
type ConnectionInfo struct {
	ID         string    `json:"id"`
	ClientAddr string    `json:"client_addr"`
	TargetAddr string    `json:"target_addr"`
	BytesIn    int64     `json:"bytes_in"`  // 下行：代理发给客户端的字节数
	BytesOut   int64     `json:"bytes_out"` // 上行：客户端发给代理的字节数
	StartTime  time.Time `json:"start_time"`
}

// StatsManager 是一个代理实例的统计口径。每个实例一份：多实例共用一份的话，
// 连接数、流量会混在一起，SetTarget 更会串台（见下）。
type StatsManager struct {
	mu                sync.Mutex
	totalBytesIn      int64
	totalBytesOut     int64
	totalConnections  int64
	activeConnections map[string]*ConnectionInfo
	// byClient 按客户端地址索引，供 SetTarget 回填目标用。
	// 同一个客户端地址同时只可能有一条活跃连接（四元组唯一），新的覆盖旧的。
	byClient map[string]*ConnectionInfo
}

func newStats() *StatsManager {
	return &StatsManager{
		activeConnections: make(map[string]*ConnectionInfo),
		byClient:          make(map[string]*ConnectionInfo),
	}
}

func (s *StatsManager) AddConnection(id, client, target string) *ConnectionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	atomic.AddInt64(&s.totalConnections, 1)
	conn := &ConnectionInfo{
		ID:         id,
		ClientAddr: client,
		TargetAddr: target,
		StartTime:  time.Now(),
	}
	s.activeConnections[id] = conn
	s.byClient[client] = conn
	return conn
}

// SetTarget 按客户端地址回填这条连接的目标。Accept 的时候还不知道客户端要连哪儿，
// 要等 SOCKS5 握手把目标发过来才知道，那时只能靠客户端地址对上号。
//
// 走索引而不是线性扫：早先那版扫的是全局 map 里第一个地址相符的连接，客户端
// 临时端口被复用时会命中一条陈旧连接，多实例下更会把目标写到别的实例的连接上。
func (s *StatsManager) SetTarget(clientAddr, target string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.byClient[clientAddr]; ok {
		c.TargetAddr = target
	}
}

func (s *StatsManager) RemoveConnection(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.activeConnections[id]; ok {
		// 只在索引仍指向自己时才删：同一个客户端地址已经被新连接占用的话，
		// 删掉会让新连接的目标再也回填不上
		if cur, ok := s.byClient[c.ClientAddr]; ok && cur == c {
			delete(s.byClient, c.ClientAddr)
		}
	}
	delete(s.activeConnections, id)
}

func (s *StatsManager) AddBytes(in, out int64) {
	if in > 0 {
		atomic.AddInt64(&s.totalBytesIn, in)
	}
	if out > 0 {
		atomic.AddInt64(&s.totalBytesOut, out)
	}
}

// Snapshot 拷一份当前统计供接口输出。连接还在跑，直接编码指针会和流量计数、
// 目标回填打架，所以逐条复制。
func (s *StatsManager) Snapshot() map[string]interface{} {
	s.mu.Lock()
	active := make([]ConnectionInfo, 0, len(s.activeConnections))
	for _, c := range s.activeConnections {
		active = append(active, ConnectionInfo{
			ID:         c.ID,
			ClientAddr: c.ClientAddr,
			TargetAddr: c.TargetAddr,
			BytesIn:    atomic.LoadInt64(&c.BytesIn),
			BytesOut:   atomic.LoadInt64(&c.BytesOut),
			StartTime:  c.StartTime,
		})
	}
	s.mu.Unlock()
	// map 遍历顺序是随机的，不排一下界面每 2 秒刷新时行序会乱跳
	sort.Slice(active, func(i, j int) bool { return active[i].StartTime.Before(active[j].StartTime) })

	return map[string]interface{}{
		"total_bytes_in":           atomic.LoadInt64(&s.totalBytesIn),
		"total_bytes_out":          atomic.LoadInt64(&s.totalBytesOut),
		"total_connections":        atomic.LoadInt64(&s.totalConnections),
		"active_connections_count": len(active),
		"active_connections":       active,
	}
}

// MonitoredConn 在真实连接外面包一层，用来记字节数
type MonitoredConn struct {
	net.Conn
	info  *ConnectionInfo
	stats *StatsManager  // 所属实例的统计口径
	owner *statsListener // 停止代理时用来主动断开这条隧道
}

// 注意方向：包住的是客户端那一侧的连接，所以从这条 socket 读到的字节
// 是客户端发上来的（上行），写出去的才是客户端收到的（下行）。
// 统计口径按用户视角记，别按 socket 视角记，否则界面上下行会反过来。
func (mc *MonitoredConn) Read(b []byte) (int, error) {
	n, err := mc.Conn.Read(b)
	if n > 0 {
		atomic.AddInt64(&mc.info.BytesOut, int64(n))
		mc.stats.AddBytes(0, int64(n))
	}
	return n, err
}

func (mc *MonitoredConn) Write(b []byte) (int, error) {
	n, err := mc.Conn.Write(b)
	if n > 0 {
		atomic.AddInt64(&mc.info.BytesIn, int64(n))
		mc.stats.AddBytes(int64(n), 0)
	}
	return n, err
}

func (mc *MonitoredConn) Close() error {
	mc.stats.RemoveConnection(mc.info.ID)
	if mc.owner != nil {
		mc.owner.forget(mc)
	}
	return mc.Conn.Close()
}

// statsListener 在 Accept 时登记连接，并持有全部在跑的隧道以便停止代理时逐一断开
type statsListener struct {
	net.Listener
	connCounter *int64
	stats       *StatsManager

	mu     sync.Mutex
	conns  map[*MonitoredConn]struct{}
	closed bool
}

func (sl *statsListener) Accept() (net.Conn, error) {
	c, err := sl.Listener.Accept()
	if err != nil {
		return nil, err
	}

	id := fmt.Sprintf("conn-%d", atomic.AddInt64(sl.connCounter, 1))
	clientAddr := c.RemoteAddr().String()
	info := sl.stats.AddConnection(id, clientAddr, "握手中…")
	mc := &MonitoredConn{Conn: c, info: info, stats: sl.stats, owner: sl}

	sl.mu.Lock()
	if sl.closed {
		// 与停止操作赛跑时抢到的连接，直接丢弃
		sl.mu.Unlock()
		mc.Close()
		return nil, net.ErrClosed
	}
	sl.conns[mc] = struct{}{}
	sl.mu.Unlock()

	return mc, nil
}

func (sl *statsListener) forget(mc *MonitoredConn) {
	sl.mu.Lock()
	delete(sl.conns, mc)
	sl.mu.Unlock()
}

// shutdown 关掉监听口并断开还在跑的隧道。只关监听口的话已建立的连接会一直
// 转发下去，用户点了「停止」却发现流量还在走，那不叫停止。
func (sl *statsListener) shutdown() error {
	err := sl.Listener.Close()

	sl.mu.Lock()
	sl.closed = true
	live := make([]*MonitoredConn, 0, len(sl.conns))
	for c := range sl.conns {
		live = append(live, c)
	}
	sl.conns = make(map[*MonitoredConn]struct{})
	sl.mu.Unlock()

	for _, c := range live {
		c.Close()
	}
	return err
}
