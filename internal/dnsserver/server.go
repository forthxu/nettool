package dnsserver

// 服务生命周期：监听 UDP+TCP、启停、以及界面上的「测试解析」。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"lan_router_socks5/internal/netutil"
)

// Server 是一个可反复启停的本地 DNS 服务。配置与运行状态分开：
// 停着的时候也能改配置，改完点启动才生效。
type Server struct {
	mu          sync.Mutex
	settings    Settings
	engine      *engine
	udpConn     *net.UDPConn
	tcpLn       net.Listener
	startedAt   time.Time
	wantRunning bool // 用户的开关意愿，持久化后下次启动照着恢复
	stats       *stats
}

// Default 是本进程唯一的 DNS 服务实例
var Default = &Server{settings: defaultSettings(), stats: newStats()}

func (s *Server) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udpConn != nil || s.tcpLn != nil
}

func (s *Server) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings
}

func (s *Server) StartedAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startedAt
}

// SetConfig 校验并保存配置：服务在跑就带新配置重启，停着就只记下来
func (s *Server) SetConfig(in Settings) error {
	cleaned, err := validateSettings(in)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	running := s.udpConn != nil || s.tcpLn != nil
	old := s.settings
	s.settings = cleaned
	if running {
		s.stopLocked()
		if err := s.startLocked(); err != nil {
			// 新配置起不来就退回旧的，别把用户晾在"服务没了"的状态
			s.settings = old
			if backErr := s.startLocked(); backErr != nil {
				log.Printf("[DNS] 回滚到旧配置也失败了: %v", backErr)
			}
			return err
		}
	}
	s.persistLocked()

	names := make(map[string]bool, len(cleaned.Upstreams))
	for _, u := range cleaned.Upstreams {
		names[u.Name] = true
	}
	s.stats.keepOnly(names)
	return nil
}

func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.udpConn == nil && s.tcpLn == nil {
		if err := s.startLocked(); err != nil {
			return err
		}
	}
	s.wantRunning = true
	s.persistLocked()
	return nil
}

// Stop 停止服务；已经停止时只把「下次别自动起」这个意愿落盘
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.udpConn != nil || s.tcpLn != nil {
		log.Printf("[DNS] 停止 DNS 服务 %s", net.JoinHostPort(s.settings.Listen, s.settings.Port))
		s.stopLocked()
	}
	s.wantRunning = false
	s.persistLocked()
}

// WasRunning 报告上次退出前 DNS 服务是开着的——启动时据此决定要不要自动拉起
func (s *Server) WasRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.wantRunning
}

// startLocked 需持有 s.mu
func (s *Server) startLocked() error {
	addr := net.JoinHostPort(s.settings.Listen, s.settings.Port)

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("监听地址 %s 无效: %v", addr, err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("监听 UDP %s 失败: %v（53 端口需要 root，且不能和系统自带的解析器抢）", addr, err)
	}
	tcpLn, err := net.Listen("tcp", addr)
	if err != nil {
		udpConn.Close()
		return fmt.Errorf("监听 TCP %s 失败: %v", addr, err)
	}

	eng := newEngine(s.settings, s.stats)
	s.engine, s.udpConn, s.tcpLn, s.startedAt = eng, udpConn, tcpLn, time.Now()

	go serveUDP(udpConn, eng)
	go serveTCP(tcpLn, eng)

	log.Printf("[DNS] DNS 服务已启动: %s（UDP+TCP），上游 %d 个，策略 %s",
		addr, len(s.settings.Upstreams), s.settings.Strategy)
	return nil
}

// stopLocked 需持有 s.mu
func (s *Server) stopLocked() {
	if s.udpConn != nil {
		s.udpConn.Close()
		s.udpConn = nil
	}
	if s.tcpLn != nil {
		s.tcpLn.Close()
		s.tcpLn = nil
	}
	if s.engine != nil {
		s.engine.cache.purge()
		s.engine = nil
	}
	s.startedAt = time.Time{}
}

// CacheSize 报告当前缓存了多少条，停止时为 0
func (s *Server) CacheSize() int {
	s.mu.Lock()
	eng := s.engine
	s.mu.Unlock()
	if eng == nil {
		return 0
	}
	return eng.cache.len()
}

func (s *Server) PurgeCache() {
	s.mu.Lock()
	eng := s.engine
	s.mu.Unlock()
	if eng != nil {
		eng.cache.purge()
	}
}

// StatsSnapshot 返回查询统计，供接口输出
func (s *Server) StatsSnapshot() map[string]interface{} { return s.stats.snapshot() }

// ResetStats 清空查询统计
func (s *Server) ResetStats() { s.stats.reset() }

func serveUDP(conn *net.UDPConn, eng *engine) {
	buf := make([]byte, udpBufSize)
	for {
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				continue
			}
			log.Printf("[DNS] UDP 读取出错: %v", err)
			return
		}
		req := make([]byte, n)
		copy(req, buf[:n])

		go func(req []byte, client *net.UDPAddr) {
			resp := eng.handle(req, client.String())
			if len(resp) == 0 {
				return
			}
			// 超过客户端能收的大小就只回一个 TC 标记，让它改走 TCP
			if max := udpBufferSize(req); len(resp) > max {
				var p dnsmessage.Parser
				if hdr, err := p.Start(req); err == nil {
					q, _ := p.Question()
					resp = truncatedResponse(hdr, q)
				}
			}
			if _, err := conn.WriteToUDP(resp, client); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Printf("[DNS] 回应 %s 失败: %v", client, err)
			}
		}(req, client)
	}
}

func serveTCP(ln net.Listener, eng *engine) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("[DNS] TCP 接受连接出错: %v", err)
			return
		}
		go handleTCPConn(conn, eng)
	}
}

// handleTCPConn 一条 TCP 连接上可以连着问多次，空闲一段时间再关
func handleTCPConn(conn net.Conn, eng *engine) {
	defer conn.Close()
	client := conn.RemoteAddr().String()

	for {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		n := int(lenBuf[0])<<8 | int(lenBuf[1])
		if n < 12 || n > 65535 {
			return
		}
		req := make([]byte, n)
		if _, err := io.ReadFull(conn, req); err != nil {
			return
		}

		resp := eng.handle(req, client)
		if len(resp) == 0 {
			return
		}
		out := make([]byte, 2+len(resp))
		out[0] = byte(len(resp) >> 8)
		out[1] = byte(len(resp))
		copy(out[2:], resp)

		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

// TestQuery 在界面上点「测试」时用：走真实的上游选择逻辑，但不碰缓存和统计，
// 服务没启动时也能测——临时搭一个 engine 就行。
func (s *Server) TestQuery(name, qtype, upstreamName string) (map[string]interface{}, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("域名不能为空")
	}
	bare := strings.ToLower(strings.Trim(name, "."))
	if !netutil.IsValidDomain(bare) {
		return nil, fmt.Errorf("%q 不是合法域名", name)
	}

	t, ok := queryTypes[strings.ToUpper(strings.TrimSpace(qtype))]
	if qtype == "" {
		t, ok = dnsmessage.TypeA, true
	}
	if !ok {
		return nil, fmt.Errorf("不支持的记录类型 %q", qtype)
	}

	s.mu.Lock()
	eng := s.engine
	settings := s.settings
	s.mu.Unlock()
	if eng == nil {
		eng = newEngine(settings, newStats())
	}

	ups := selectUpstreams(settings.Upstreams, bare)
	if upstreamName != "" {
		ups = nil
		for _, u := range settings.Upstreams {
			if u.Name == upstreamName {
				ups = append(ups, u)
			}
		}
		if len(ups) == 0 {
			return nil, fmt.Errorf("找不到名为 %q 的上游", upstreamName)
		}
	}

	// 静态记录会拦在上游前面，测试时也要如实反映
	if ips := matchHosts(settings.Hosts, bare, t); len(ips) > 0 {
		texts := make([]string, 0, len(ips))
		for _, ip := range ips {
			texts = append(texts, ip.String())
		}
		return map[string]interface{}{
			"name": bare, "type": typeName(t), "upstream": "本地静态记录",
			"status": "NOERROR", "answer": strings.Join(texts, ", "), "cost_ms": 0,
		}, nil
	}
	if len(ups) == 0 {
		return nil, fmt.Errorf("没有可用的上游 DNS，请先添加一个")
	}

	qname, err := dnsmessage.NewName(fqdn(bare))
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x2b2b, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: qname, Type: t, Class: dnsmessage.ClassINET}},
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), eng.timeout)
	defer cancel()

	started := time.Now()
	raw, used, err := eng.query(ctx, ups, packed)
	cost := time.Since(started).Milliseconds()
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"name": bare, "type": typeName(t), "upstream": used,
		"status": "NOERROR", "answer": "", "cost_ms": cost,
	}
	var reply dnsmessage.Message
	if err := reply.Unpack(raw); err != nil {
		result["answer"] = fmt.Sprintf("上游返回了 %d 字节，但解析失败: %v", len(raw), err)
		return result, nil
	}
	result["status"] = rcodeName(reply.Header.RCode)
	result["answer"] = summarizeAnswers(reply.Answers)
	return result, nil
}
