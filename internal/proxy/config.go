package proxy

// 配置与开关状态持久化：默认和路由台账、DNS 配置放在同一目录，方便一并备份。
//
// 存的不只是端口/出口 IP/代理 DNS，还有「上次是开着还是关着」——
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

const configVersion = 1

type configFile struct {
	Version int       `json:"version"`
	SavedAt time.Time `json:"saved_at"`
	// Running 记的是用户的意愿而不是此刻的实况：点了启动为 true，点了停止为 false。
	// 启动失败（端口被占等）不会把它改掉，下次起来还会再试一次。
	Running    bool   `json:"running"`
	Port       string `json:"port"`
	OutboundIP string `json:"outbound_ip"`
	DNS        string `json:"dns"`
}

// configPath 为空表示本次运行不持久化
var configPath string

// ConfigPath 返回当前生效的配置文件路径
func ConfigPath() string { return configPath }

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

// Load 读入上次保存的配置与开关状态；文件不存在或损坏时保留默认值。
// 出口 IP 不在这里校验：网卡可能还没起来，真到启动那一步再报错更准确。
func (p *Server) Load(path string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	configPath = path
	if path == "" {
		return false
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[SOCKS5] 读取配置失败 %s: %v", path, err)
		}
		return false
	}
	if len(data) == 0 {
		return false
	}

	var state configFile
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("[SOCKS5] 配置文件损坏 %s: %v（本次忽略，不会覆盖）", path, err)
		configPath = "" // 别拿空配置把用户存的东西盖掉
		return false
	}

	if port := strings.TrimSpace(state.Port); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			log.Printf("[SOCKS5] 配置文件里的端口 %q 不合法，改用 %s", state.Port, p.port)
		} else {
			p.port = port
		}
	}
	if ip := strings.TrimSpace(state.OutboundIP); ip != "" {
		if net.ParseIP(ip) == nil {
			log.Printf("[SOCKS5] 配置文件里的出口 IP %q 不是合法 IP，已忽略", state.OutboundIP)
		} else {
			p.outboundIP = ip
		}
	}
	if dns, err := NormalizeDNSAddr(state.DNS); err != nil {
		log.Printf("[SOCKS5] 配置文件里的代理 DNS %q 无效: %v，改用系统 DNS", state.DNS, err)
	} else {
		p.dns = dns
	}
	p.wantRunning = state.Running
	return true
}

// WasRunning 报告上次退出前代理是开着的——启动时据此决定要不要自动拉起
func (p *Server) WasRunning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.wantRunning
}

// persistLocked 需持有 p.mu
func (p *Server) persistLocked() {
	if configPath == "" {
		return
	}
	data, err := json.MarshalIndent(configFile{
		Version:    configVersion,
		SavedAt:    time.Now(),
		Running:    p.wantRunning,
		Port:       p.port,
		OutboundIP: p.outboundIP,
		DNS:        p.dns,
	}, "", "  ")
	if err != nil {
		log.Printf("[SOCKS5] 序列化配置失败: %v", err)
		return
	}
	if err := netutil.WriteFileAtomic(configPath, data, 0o644); err != nil {
		log.Printf("[SOCKS5] 写入配置失败 %s: %v", configPath, err)
	}
}

// ApplyFlags 把命令行给的端口/出口 IP/代理 DNS 合进已载入的配置。
// 只有真填了的才覆盖——否则每次带默认参数启动都会把后台调好的值冲掉。
func ApplyFlags(port, outboundIP, dns string) error {
	curPort, curIP, curDNS := Default.GetConfig()
	changed := false

	if v := strings.TrimSpace(port); v != "" {
		curPort, changed = v, true
	}
	if v := strings.TrimSpace(outboundIP); v != "" {
		curIP, changed = v, true
	}
	if v := strings.TrimSpace(dns); v != "" {
		curDNS, changed = v, true
	}

	if !changed {
		return nil
	}
	return Default.SetConfig(curPort, curIP, curDNS)
}
