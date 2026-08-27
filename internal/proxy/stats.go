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
	BytesIn    int64     `json:"bytes_in"`  // Download
	BytesOut   int64     `json:"bytes_out"` // Upload
	StartTime  time.Time `json:"start_time"`
}

type StatsManager struct {
	mu                sync.Mutex
	totalBytesIn      int64
	totalBytesOut     int64
	totalConnections  int64
	activeConnections map[string]*ConnectionInfo
}

// Stats 是全局唯一的统计口径，进程整个生命周期内累加，代理重启不清零
var Stats = &StatsManager{
	activeConnections: make(map[string]*ConnectionInfo),
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
	return conn
}

// SetTarget 按客户端地址回填这条连接的目标。Accept 的时候还不知道客户端要连哪儿，
// 要等 SOCKS5 握手把目标发过来才知道，那时只能靠客户端地址对上号。
func (s *StatsManager) SetTarget(clientAddr, target string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.activeConnections {
		if c.ClientAddr == clientAddr {
			c.TargetAddr = target
			return
		}
	}
}

func (s *StatsManager) RemoveConnection(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	owner *statsListener // 停止代理时用来主动断开这条隧道
}

func (mc *MonitoredConn) Read(b []byte) (int, error) {
	n, err := mc.Conn.Read(b)
	if n > 0 {
		atomic.AddInt64(&mc.info.BytesIn, int64(n))
		Stats.AddBytes(int64(n), 0)
	}
	return n, err
}

func (mc *MonitoredConn) Write(b []byte) (int, error) {
	n, err := mc.Conn.Write(b)
	if n > 0 {
		atomic.AddInt64(&mc.info.BytesOut, int64(n))
		Stats.AddBytes(0, int64(n))
	}
	return n, err
}

func (mc *MonitoredConn) Close() error {
	Stats.RemoveConnection(mc.info.ID)
	if mc.owner != nil {
		mc.owner.forget(mc)
	}
	return mc.Conn.Close()
}

// statsListener 在 Accept 时登记连接，并持有全部在跑的隧道以便停止代理时逐一断开
type statsListener struct {
	net.Listener
	connCounter *int64

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
	info := Stats.AddConnection(id, clientAddr, "握手中…")
	mc := &MonitoredConn{Conn: c, info: info, owner: sl}

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
