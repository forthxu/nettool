// 命令 lan_proxy 是一个局域网网络管理工具：SOCKS5 代理 + 多路由器网关调度 +
// 本地 DNS 服务 + 网卡配置管理 + 连通性诊断，全部通过内嵌的 Web 后台操作。
//
// 各业务分别在 internal/ 下：
//
//	internal/proxy      SOCKS5 代理与流量统计
//	internal/route      路由台账（下发、对账、按域名重新解析）
//	internal/dnsserver  本地 DNS 服务（UDP/TCP/DoT/DoH 上游、分流、缓存）
//	internal/netconfig  网卡 IP/掩码/网关/DNS 配置与 Wi-Fi 自动切换
//	internal/netdiag    ping 与 traceroute（可指定源 IP）
//	internal/netiface   本机网卡与网关探测
//	internal/api        HTTP 管理接口与 Web 前端托管
//
// 本文件只负责解析命令行参数、按顺序把它们装起来，然后开始服务。
package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"time"

	"lan_router_socks5/internal/api"
	"lan_router_socks5/internal/dnsserver"
	"lan_router_socks5/internal/netconfig"
	"lan_router_socks5/internal/proxy"
	"lan_router_socks5/internal/route"
)

//go:embed static/*
var staticFiles embed.FS

type options struct {
	socksPort       *string
	outboundIP      *string
	proxyDNS        *string
	proxyConfigFile *string
	apiPort         *string
	authUser        *string
	authPass        *string
	stateFile       *string
	restoreRoutes   *bool
	domainRefresh   *time.Duration
	startProxy      *bool

	netProfileFile *string
	wifiWatch      *time.Duration

	dnsConfigFile *string
	dnsPort       *string
	dnsListen     *string
	dnsUpstream   *string
	startDNS      *bool
}

func parseFlags() options {
	o := options{
		socksPort:       flag.String("socks-port", "", "SOCKS5 代理端口（留空沿用上次保存的值，默认 1080）"),
		outboundIP:      flag.String("outbound-ip", "", "SOCKS5 外发流量绑定的本机 IP（留空沿用上次保存的值）"),
		proxyDNS:        flag.String("dns", "", "代理解析域名用的上游 DNS（如 8.8.8.8 或 8.8.8.8:53），留空沿用上次保存的值"),
		proxyConfigFile: flag.String("proxy-config-file", "", "SOCKS5 代理配置文件路径（留空则与路由台账同目录）"),
		apiPort:         flag.String("api-port", "8080", "API management and Web UI port"),
		authUser:        flag.String("user", "", "Web UI & API username (leave empty for no auth)"),
		authPass:        flag.String("pass", "", "Web UI & API password (leave empty for no auth)"),
		stateFile:       flag.String("state-file", "", "路由台账文件路径（留空自动选择 /var/lib/lan-proxy/routes.json 等可写位置）"),
		restoreRoutes:   flag.Bool("restore-routes", false, "启动时自动重新下发台账中已失效的路由"),
		domainRefresh:   flag.Duration("domain-refresh", 5*time.Minute, "域名路由自动重新解析间隔（0 表示关闭）"),
		startProxy:      flag.Bool("start-proxy", false, "启动时无条件开启 SOCKS5 代理（不加则按上次退出时的开关状态恢复）"),

		netProfileFile: flag.String("net-profile-file", "", "Wi-Fi 网卡配置档文件路径（留空则与路由台账同目录）"),
		wifiWatch:      flag.Duration("wifi-watch", 30*time.Second, "检查当前 Wi-Fi SSID 的间隔，用于自动切换网卡配置（0 表示不自动切换）"),

		dnsConfigFile: flag.String("dns-config-file", "", "DNS 服务配置文件路径（留空则与路由台账同目录）"),
		dnsPort:       flag.String("dns-port", "", "本地 DNS 服务监听端口（留空沿用配置文件里的值，默认 53）"),
		dnsListen:     flag.String("dns-listen", "", "本地 DNS 服务监听地址（留空沿用配置文件里的值，默认 0.0.0.0）"),
		dnsUpstream:   flag.String("dns-upstream", "", "本地 DNS 服务的上游，逗号分隔，如 223.5.5.5,tls://dns.google,https://dns.google/dns-query（仅在配置文件里还没有上游时生效）"),
		startDNS:      flag.Bool("start-dns", false, "启动时无条件开启本地 DNS 服务（不加则按上次退出时的开关状态恢复）"),
	}
	flag.Parse()
	return o
}

func main() {
	opt := parseFlags()

	statePath := setupRoutes(opt)
	setupWiFi(opt, statePath)
	setupDNS(opt, statePath)
	setupProxy(opt, statePath)

	serveWeb(opt)
}

// setupRoutes 载入路由台账并与内核路由表对账，返回台账文件路径
// （Wi-Fi 配置档与 DNS 配置默认放在它旁边）。
func setupRoutes(opt options) string {
	statePath := route.ResolveStateFile(*opt.stateFile)
	if statePath != "" {
		log.Printf("[State] 路由台账文件: %s", statePath)
	}

	loaded, missing := route.Default.LoadState()
	// 上次运行之后网关可能换了网卡，先把作用域对上再判断哪些真的失效了
	if fixed, _ := route.Default.RescopeRoutes(); len(fixed) > 0 {
		missing = route.Default.MissingRoutes()
	}
	if len(missing) > 0 {
		if *opt.restoreRoutes {
			dests := make([]string, 0, len(missing))
			for _, r := range missing {
				dests = append(dests, r.Destination)
			}
			restored, failed := route.Default.RestoreRoutes(dests)
			log.Printf("[State] 自动重下: 成功 %d 条, 失败 %d 条", len(restored), len(failed))
		} else {
			log.Printf("[State] %d/%d 条台账路由当前未生效，可在 Web 后台点击「重新下发」，或加 -restore-routes 启动参数自动重建",
				len(missing), loaded)
		}
	}

	route.StartDomainRefresher(*opt.domainRefresh)
	return statePath
}

// setupWiFi 载入 Wi-Fi 网卡配置档并开始盯 SSID
// （没有启用的配置档时只是记录当前 SSID）
func setupWiFi(opt options, statePath string) {
	profilePath := netconfig.ResolveProfileFile(*opt.netProfileFile, statePath)
	if profilePath != "" {
		log.Printf("[NetConfig] Wi-Fi 配置档文件: %s", profilePath)
	}
	if n := netconfig.Profiles.Load(profilePath); n > 0 {
		log.Printf("[NetConfig] 载入 %d 个 Wi-Fi 配置档", n)
	}
	netconfig.StartWatcher(*opt.wifiWatch)
}

// setupDNS 载入本地 DNS 服务配置；命令行参数只是覆盖，最终以配置文件里存下来的为准。
// 开关状态同样跟着配置走：上次退出前开着就自动拉起来。
func setupDNS(opt options, statePath string) {
	loaded := dnsserver.Default.Load(dnsserver.ResolveConfigFile(*opt.dnsConfigFile, statePath))
	if path := dnsserver.ConfigPath(); path != "" {
		log.Printf("[DNS] DNS 配置文件: %s", path)
	}
	if err := dnsserver.ApplyFlags(*opt.dnsListen, *opt.dnsPort, *opt.dnsUpstream); err != nil {
		log.Fatalf("[DNS] 命令行 DNS 配置无效: %v", err)
	}

	s := dnsserver.Default.Settings()
	if !*opt.startDNS && !dnsserver.Default.WasRunning() {
		if loaded {
			log.Printf("[DNS] 上次退出时 DNS 服务是停止的，本次不自动启动（%s:%s），可在 Web 后台点击「启动 DNS」", s.Listen, s.Port)
		} else {
			log.Printf("[DNS] DNS 服务未启动（%s:%s），可在 Web 后台点击「启动 DNS」；之后每次启动都按上次的开关状态恢复", s.Listen, s.Port)
		}
		return
	}

	if err := dnsserver.Default.Start(); err != nil {
		// 显式要求启动却起不来才算致命；按上次状态恢复失败就只提示一声，
		// 让 Web 后台还能进得去，用户可以改完端口再启动
		if *opt.startDNS {
			log.Fatalf("[DNS] 启动 DNS 服务失败: %v", err)
		}
		log.Printf("[DNS] 按上次状态自动启动 DNS 服务失败: %v，服务保持停止", err)
	}
}

// setupProxy 载入代理配置与上次的开关状态：上次退出前开着就自动拉起来，
// 加 -start-proxy 则无条件启动
func setupProxy(opt options, statePath string) {
	loaded := proxy.Default.Load(proxy.ResolveConfigFile(*opt.proxyConfigFile, statePath))
	if path := proxy.ConfigPath(); path != "" {
		log.Printf("[SOCKS5] 代理配置文件: %s", path)
	}
	if err := proxy.ApplyFlags(*opt.socksPort, *opt.outboundIP, *opt.proxyDNS); err != nil {
		log.Fatalf("Invalid SOCKS5 proxy config: %v", err)
	}

	port, _, _ := proxy.Default.GetConfig()
	if !*opt.startProxy && !proxy.Default.WasRunning() {
		if loaded {
			log.Printf("[SOCKS5] 上次退出时代理是停止的，本次不自动启动（端口 %s），可在 Web 后台点击「启动代理」", port)
		} else {
			log.Printf("[SOCKS5] 代理未启动（端口 %s），可在 Web 后台点击「启动代理」；之后每次启动都按上次的开关状态恢复", port)
		}
		return
	}

	if err := proxy.Default.StartCurrent(); err != nil {
		if *opt.startProxy {
			log.Fatalf("Failed to start SOCKS5 proxy: %v", err)
		}
		log.Printf("[SOCKS5] 按上次状态自动启动代理失败: %v，代理保持停止", err)
	}
}

// serveWeb 托管内嵌的前端与管理接口，直到进程退出
func serveWeb(opt options) {
	subFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("Failed to create sub filesystem: %v", err)
	}

	handler := api.Handler(api.Config{Static: subFS, User: *opt.authUser, Pass: *opt.authPass})
	addr := fmt.Sprintf("0.0.0.0:%s", *opt.apiPort)
	log.Printf("[Web UI & API] Management console running at http://%s", addr)

	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("[Web UI] Server error: %v", err)
	}
}
