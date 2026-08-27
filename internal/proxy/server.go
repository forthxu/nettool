// Package proxy 提供 SOCKS5 代理服务：启停、出口 IP 绑定、上游 DNS，
// 以及连接与流量统计。配置与运行状态是分开的——代理停着的时候也能改配置。
package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/armon/go-socks5"

	"nettool/internal/netiface"
)

// Server 是一个可反复启停的 SOCKS5 服务。改配置时若正在运行会带新配置重启。
type Server struct {
	mu          sync.Mutex
	port        string
	outboundIP  string
	dns         string    // 代理解析域名用的上游 DNS，空表示用系统的
	startedAt   time.Time // 代理最近一次启动的时间，改配置重启会刷新
	wantRunning bool      // 用户的开关意愿，持久化后下次启动照着恢复
	listener    *statsListener
	closeChan   chan struct{}
}

// Default 是本进程唯一的代理实例
var Default = &Server{
	port:       "8091",
	outboundIP: "",
}

func (p *Server) Start(port, outboundIP, dns string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.startLocked(port, outboundIP, dns); err != nil {
		return err
	}
	p.wantRunning = true
	p.persistLocked()
	return nil
}

// StartCurrent 用已保存的配置启动，供 Web 后台的「启动」按钮使用
func (p *Server) StartCurrent() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.startLocked(p.port, p.outboundIP, p.dns); err != nil {
		return err
	}
	p.wantRunning = true
	p.persistLocked()
	return nil
}

// Stop 停止代理并断开现有连接；已经停止时只把「下次别自动起」这个意愿落盘
func (p *Server) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener == nil {
		if p.wantRunning {
			p.wantRunning = false
			p.persistLocked()
		}
		return nil
	}
	log.Printf("[SOCKS5] Stopping SOCKS5 proxy server on port %s", p.port)
	err := p.stopLocked()
	p.wantRunning = false
	p.persistLocked()
	return err
}

func (p *Server) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.listener != nil
}

// SetConfig 只改配置：代理在跑就带新配置重启，停着就先记下来，下次启动时生效。
func (p *Server) SetConfig(port, outboundIP, dns string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.listener != nil {
		if err := p.startLocked(port, outboundIP, dns); err != nil {
			return err
		}
		p.persistLocked()
		return nil
	}
	// 停止状态下也要校验，免得存进去一个启动时才报错的配置
	if outboundIP != "" {
		if _, err := netiface.ValidateOutbound(outboundIP); err != nil {
			return err
		}
	}
	dns, err := NormalizeDNSAddr(dns)
	if err != nil {
		return err
	}
	p.port = port
	p.outboundIP = outboundIP
	p.dns = dns
	p.persistLocked()
	return nil
}

func (p *Server) GetConfig() (port, outboundIP, dns string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.port, p.outboundIP, p.dns
}

func (p *Server) StartedAt() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.startedAt
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
func (p *Server) startLocked(port, outboundIP, dns string) error {
	// 先校验出口 IP 与 DNS，校验失败时不动已在运行的代理服务
	var localIP net.IP
	if outboundIP != "" {
		var err error
		localIP, err = netiface.ValidateOutbound(outboundIP)
		if err != nil {
			return err
		}
	}
	dns, err := NormalizeDNSAddr(dns)
	if err != nil {
		return err
	}

	p.stopLocked()

	conf := &socks5.Config{}
	conf.Rules = &targetRecorder{inner: socks5.PermitAll()}
	conf.Resolver = &resolver{dns: dns, outboundIP: localIP}

	var dialer *net.Dialer
	if outboundIP != "" {
		dialer = &net.Dialer{
			LocalAddr: &net.TCPAddr{IP: localIP},
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
	} else {
		dialer = &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
	}

	conf.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	srv, err := socks5.New(conf)
	if err != nil {
		return fmt.Errorf("failed to create SOCKS5 server: %v", err)
	}

	addr := fmt.Sprintf("0.0.0.0:%s", port)
	rawListener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", addr, err)
	}

	connIDCounter := int64(0)
	listener := &statsListener{
		Listener:    rawListener,
		connCounter: &connIDCounter,
		conns:       make(map[*MonitoredConn]struct{}),
	}

	closeChan := make(chan struct{})
	p.port = port
	p.outboundIP = outboundIP
	// 记的是归一化之后的（只填 IP 会补上 :53），与真正交给 resolver 的那份一致；
	// 漏了这行的话运行中改代理 DNS 会立即生效，界面上却还显示旧值
	p.dns = dns
	p.startedAt = time.Now()
	p.listener = listener
	p.closeChan = closeChan

	go func() {
		log.Printf("[SOCKS5] Starting SOCKS5 proxy server on %s (Outbound IP: %s)", addr, func() string {
			if outboundIP == "" {
				return "Default"
			}
			return outboundIP
		}())
		if err := srv.Serve(listener); err != nil {
			select {
			case <-closeChan:
				return
			default:
				log.Printf("[SOCKS5] Server error: %v", err)
			}
		}
	}()

	return nil
}
