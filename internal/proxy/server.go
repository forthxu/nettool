// Package proxy 提供 SOCKS5 代理服务：多实例启停、出口线路绑定、上游 DNS，
// 以及按实例的连接与流量统计。配置与运行状态是分开的——
// 实例停着的时候也能改配置。
//
// 出口只有「出口线路」这一个来源（internal/uplink）。本包不决定走哪个网关，
// 只负责在拨号时把线路要求的东西施加上去——Linux 是 socket 上的 fwmark，
// macOS 是源地址 + 段内的一个源端口（PF 按它选网关），Windows 是绑网卡。
// 早先那种"绑定本机源 IP 来指定网关"的做法已经去掉了：光绑源地址决定不了网关，
// 同一块网卡上的多个地址通常仍走同一条默认路由。
//
// 多实例的意义：每个实例监听不同端口、绑定不同的出口线路（internal/uplink），
// 于是"8091 走电信、8092 走联通"这种事才成立。实例之间除了共用一份台账文件，
// 运行时是完全隔离的：各有各的监听口、统计、拨号器。
package proxy

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/armon/go-socks5"

	"nettool/internal/netiface"
	"nettool/internal/sockopt"
)

// Server 是一个可反复启停的 SOCKS5 实例。改配置时若正在运行会带新配置重启。
type Server struct {
	mu   sync.Mutex
	mgr  *Manager // 用于落盘与端口占用检查
	id   string
	name string

	port     string
	listen   string // 监听地址，默认 127.0.0.1；绑 0.0.0.0 就是一台无鉴权的公开代理
	uplinkID string // 绑定的出口线路，空表示走系统默认线路
	dns      string // 代理解析域名用的上游 DNS，空表示用系统的

	createdAt   time.Time
	startedAt   time.Time // 最近一次启动的时间，改配置重启会刷新
	wantRunning bool      // 用户的开关意愿，持久化后下次启动照着恢复
	listener    *statsListener
	closeChan   chan struct{}
	stats       *StatsManager
}

func (p *Server) ID() string { return p.id }

// Stats 返回本实例的统计口径
func (p *Server) Stats() *StatsManager { return p.stats }

// Start 用给定配置启动本实例
func (p *Server) Start(cfg Instance) error {
	p.mu.Lock()
	if err := p.startLocked(cfg); err != nil {
		p.mu.Unlock()
		return err
	}
	p.wantRunning = true
	snapshot := p.configLocked()
	p.mu.Unlock()

	p.sync(snapshot)
	return nil
}

// StartCurrent 用已保存的配置启动，供 Web 后台的「启动」按钮使用
func (p *Server) StartCurrent() error {
	p.mu.Lock()
	if err := p.startLocked(p.configLocked()); err != nil {
		p.mu.Unlock()
		return err
	}
	p.wantRunning = true
	snapshot := p.configLocked()
	p.mu.Unlock()

	p.sync(snapshot)
	return nil
}

// Stop 停止本实例并断开现有连接；已经停止时只把「下次别自动起」这个意愿落盘
func (p *Server) Stop() error {
	p.mu.Lock()
	if p.listener == nil {
		if !p.wantRunning {
			p.mu.Unlock()
			return nil
		}
		p.wantRunning = false
		snapshot := p.configLocked()
		p.mu.Unlock()
		p.sync(snapshot)
		return nil
	}
	log.Printf("[SOCKS5] 停止实例「%s」（端口 %s）", p.name, p.port)
	err := p.stopLocked()
	p.wantRunning = false
	snapshot := p.configLocked()
	p.mu.Unlock()

	p.sync(snapshot)
	return err
}

func (p *Server) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.listener != nil
}

// SetConfig 只改配置：实例在跑就带新配置重启，停着就先记下来，下次启动时生效。
func (p *Server) SetConfig(cfg Instance) error {
	p.mu.Lock()

	if p.listener != nil {
		if err := p.startLocked(cfg); err != nil {
			p.mu.Unlock()
			return err
		}
		snapshot := p.configLocked()
		p.mu.Unlock()
		p.sync(snapshot)
		return nil
	}

	// 停止状态下也要校验，免得存进去一个启动时才报错的配置
	norm, err := p.validate(cfg)
	if err != nil {
		p.mu.Unlock()
		return err
	}
	p.applyConfigLocked(norm)
	snapshot := p.configLocked()
	p.mu.Unlock()

	p.sync(snapshot)
	return nil
}

// Config 返回本实例当前的配置
func (p *Server) Config() Instance {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.configLocked()
}

func (p *Server) configLocked() Instance {
	return Instance{
		ID: p.id, Name: p.name, Port: p.port, Listen: p.listen, UplinkID: p.uplinkID,
		DNS: p.dns, Running: p.wantRunning, CreatedAt: p.createdAt,
	}
}

func (p *Server) applyConfigLocked(cfg Instance) {
	cfg = cfg.normalized() // 旧台账里没有 listen 字段，这里补上默认值
	p.name, p.port, p.listen, p.uplinkID, p.dns = cfg.Name, cfg.Port, cfg.Listen, cfg.UplinkID, cfg.DNS
}

func (p *Server) StartedAt() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.startedAt
}

// WasRunning 报告上次退出前本实例是开着的——启动时据此决定要不要自动拉起
func (p *Server) WasRunning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.wantRunning
}

// sync 把最新配置同步给 Manager 并落盘。调用时**不能**持有 p.mu：
// Manager 会拿自己的锁，而允许的顺序只有 Server.mu → Manager.mu。
func (p *Server) sync(cfg Instance) {
	if p.mgr != nil {
		p.mgr.sync(cfg)
	}
}

// validate 校验一份配置并返回归一化之后的版本。校验失败时不能动已在运行的实例，
// 所以所有会报错的检查都要在这里做完。
func (p *Server) validate(cfg Instance) (Instance, error) {
	cfg = cfg.normalized()
	if cfg.ID == "" {
		cfg.ID = p.id
	}
	if err := cfg.validatePort(); err != nil {
		return cfg, err
	}
	if err := cfg.validateListen(); err != nil {
		return cfg, err
	}
	// 端口冲突要给出实例名，否则用户只会看到一句看不懂的 bind: address already in use
	if p.mgr != nil {
		if err := p.mgr.checkPortFree(p.id, cfg.Port); err != nil {
			return cfg, err
		}
	}
	dns, err := NormalizeDNSAddr(cfg.DNS)
	if err != nil {
		return cfg, err
	}
	cfg.DNS = dns
	// 出口线路没生效时直接拒绝，不能退回默认线路：用户以为流量走了指定网关、
	// 实际却从默认出口跑掉，是最难排查的一种故障
	if _, err := p.egressFor(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// egressFor 把配置翻译成拨号时要施加的出口约束。
//
// 出口只有出口线路这一个来源。没绑线路就返回零值，拨号路径与不用本功能时完全
// 一致——让内核自己选路。
//
// 各平台施加的东西并不一样，都由 uplink 包决定：Linux 的 fwmark 模式只打 mark，
// 源地址和网关都交给路由表；macOS 的 PF 模式要绑源地址**和**段内的一个源端口，
// PF 规则正是按这两样匹配的；Windows 只绑网卡加源地址。
func (p *Server) egressFor(cfg Instance) (sockopt.Egress, error) {
	if cfg.UplinkID == "" {
		return sockopt.Egress{}, nil
	}
	if p.mgr == nil {
		return sockopt.Egress{}, fmt.Errorf("本进程未启用出口线路管理")
	}
	lookup := p.mgr.uplinkLookup()
	if lookup == nil {
		return sockopt.Egress{}, fmt.Errorf("本进程未启用出口线路管理")
	}
	return lookup.DialOptions(cfg.UplinkID)
}

// stopLocked 需持有 p.mu
func (p *Server) stopLocked() error {
	if p.listener == nil {
		return nil
	}
	if p.closeChan != nil {
		close(p.closeChan)
	}
	err := p.listener.shutdown()
	// 立即置空：后续步骤（如端口被占用）出错提前返回时，
	// 下一次 Start 不会再次 close 同一个已关闭的 channel 而 panic
	p.listener = nil
	p.closeChan = nil
	p.startedAt = time.Time{}
	return err
}

// startLocked 需持有 p.mu
func (p *Server) startLocked(cfg Instance) error {
	// 先把所有会失败的检查做完，校验失败时不动已在运行的实例
	cfg, err := p.validate(cfg)
	if err != nil {
		return err
	}
	egress, err := p.egressFor(cfg)
	if err != nil {
		return err
	}
	// 源地址要确认真的挂在本机某块网卡上，否则 bind 会在每次拨号时才失败
	if egress.SourceIP != "" {
		if _, err := netiface.ValidateOutbound(egress.SourceIP); err != nil {
			return err
		}
	}
	dialer, err := sockopt.NewDialer(egress, net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	})
	if err != nil {
		return err
	}

	p.stopLocked()

	conf := &socks5.Config{}
	conf.Rules = &targetRecorder{inner: socks5.PermitAll(), stats: p.stats}
	conf.Resolver = &resolver{dns: cfg.DNS, egress: egress}
	conf.Dial = dialer.DialContext

	srv, err := socks5.New(conf)
	if err != nil {
		return fmt.Errorf("创建 SOCKS5 服务失败: %v", err)
	}

	addr := net.JoinHostPort(cfg.Listen, cfg.Port)
	rawListener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("监听 %s 失败: %v", addr, err)
	}

	connIDCounter := int64(0)
	listener := &statsListener{
		Listener:    rawListener,
		connCounter: &connIDCounter,
		stats:       p.stats,
		conns:       make(map[*MonitoredConn]struct{}),
	}

	closeChan := make(chan struct{})
	// 记的是归一化之后的配置（DNS 只填 IP 会补上 :53），与真正交给 resolver 的
	// 那份一致；漏了这步的话运行中改代理 DNS 会立即生效，界面上却还显示旧值
	p.applyConfigLocked(cfg)
	p.startedAt = time.Now()
	p.listener = listener
	p.closeChan = closeChan

	go func() {
		log.Printf("[SOCKS5] 启动实例「%s」于 %s（出口: %s）", cfg.Name, addr, describeEgress(cfg, egress))
		if err := srv.Serve(listener); err != nil {
			select {
			case <-closeChan:
				return
			default:
				log.Printf("[SOCKS5] 实例「%s」出错: %v", cfg.Name, err)
			}
		}
	}()

	return nil
}

// describeEgress 只用于日志，说清楚这个实例的流量到底怎么出去
func describeEgress(cfg Instance, egress sockopt.Egress) string {
	if cfg.UplinkID == "" {
		return egress.String()
	}
	return "线路 " + cfg.UplinkID + " · " + egress.String()
}
