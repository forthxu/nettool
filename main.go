// 命令 nettool 是一个局域网网络管理工具：SOCKS5 代理 + 多路由器网关调度 +
// 本地 DNS 服务 + 网卡配置管理 + 连通性诊断，全部通过内嵌的 Web 后台操作。
//
// 各业务分别在 internal/ 下：
//
//	internal/proxy      SOCKS5 代理与流量统计
//	internal/cftunnel   Cloudflare Tunnel（调 API 管云端隧道 + 托管 cloudflared）
//	internal/route      路由台账（下发、对账、按域名重新解析）
//	internal/uplink     出口线路（fwmark 策略路由，让不同代理实例走不同网关）
//	internal/sockopt    给出站 socket 打平台相关的出口标记
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
	"os"
	"os/signal"
	"syscall"
	"time"

	"nettool/internal/api"
	"nettool/internal/cftunnel"
	"nettool/internal/dnsserver"
	"nettool/internal/netconfig"
	"nettool/internal/proxy"
	"nettool/internal/route"
	"nettool/internal/uplink"
)

//go:embed static/*
var staticFiles embed.FS

type options struct {
	socksPort       *string
	proxyDNS        *string
	proxyConfigFile *string
	apiPort         *string
	authUser        *string
	authPass        *string
	stateFile       *string
	restoreRoutes   *bool
	domainRefresh   *time.Duration
	startProxy      *bool

	uplinkFile    *string
	uplinkDryRun  *bool
	uplinkCleanup *bool

	netProfileFile *string
	wifiWatch      *time.Duration

	dnsConfigFile *string
	dnsPort       *string
	dnsListen     *string
	dnsUpstream   *string
	startDNS      *bool

	cfTunnelFile  *string
	startCFTunnel *bool
}

func parseFlags() options {
	o := options{
		socksPort:       flag.String("socks-port", "", "SOCKS5 代理端口（留空沿用上次保存的值，默认 8091）"),
		proxyDNS:        flag.String("dns", "", "代理解析域名用的上游 DNS（如 8.8.8.8 或 8.8.8.8:53），留空沿用上次保存的值"),
		proxyConfigFile: flag.String("proxy-config-file", "", "SOCKS5 代理配置文件路径（留空则与路由台账同目录）"),
		apiPort:         flag.String("api-port", "8090", "API management and Web UI port"),
		authUser:        flag.String("user", "", "Web UI & API username (leave empty for no auth)"),
		authPass:        flag.String("pass", "", "Web UI & API password (leave empty for no auth)"),
		stateFile:       flag.String("state-file", "", "路由台账文件路径（留空自动选择：Linux/macOS 用 /var/lib/nettool/routes.json，Windows 用 %ProgramData%\\nettool\\routes.json，都不可写则退到用户目录）"),
		restoreRoutes:   flag.Bool("restore-routes", false, "启动时自动重新下发台账中已失效的路由"),
		domainRefresh:   flag.Duration("domain-refresh", 5*time.Minute, "域名路由自动重新解析间隔（0 表示关闭）"),
		startProxy:      flag.Bool("start-proxy", false, "启动时无条件开启 SOCKS5 代理（不加则按上次退出时的开关状态恢复）"),

		uplinkFile:    flag.String("uplink-file", "", "出口线路台账文件路径（留空则与路由台账同目录）"),
		uplinkDryRun:  flag.Bool("uplink-dry-run", false, "只打印出口线路将要下发的 ip 命令而不真的执行，用于确认不会动到别人的规则"),
		uplinkCleanup: flag.Bool("uplink-cleanup", false, "清掉本程序装过的全部 ip rule 与路由表后退出（卸载时用，不删台账）"),

		netProfileFile: flag.String("net-profile-file", "", "Wi-Fi 网卡配置档文件路径（留空则与路由台账同目录）"),
		wifiWatch:      flag.Duration("wifi-watch", 30*time.Second, "检查当前 Wi-Fi SSID 的间隔，用于自动切换网卡配置（0 表示不自动切换）"),

		dnsConfigFile: flag.String("dns-config-file", "", "DNS 服务配置文件路径（留空则与路由台账同目录）"),
		dnsPort:       flag.String("dns-port", "", "本地 DNS 服务监听端口（留空沿用配置文件里的值，默认 53）"),
		dnsListen:     flag.String("dns-listen", "", "本地 DNS 服务监听地址（留空沿用配置文件里的值，默认 0.0.0.0）"),
		dnsUpstream:   flag.String("dns-upstream", "", "本地 DNS 服务的上游，逗号分隔，如 223.5.5.5,tls://dns.google,https://dns.google/dns-query（仅在配置文件里还没有上游时生效）"),
		startDNS:      flag.Bool("start-dns", false, "启动时无条件开启本地 DNS 服务（不加则按上次退出时的开关状态恢复）"),

		cfTunnelFile:  flag.String("cftunnel-file", "", "Cloudflare Tunnel 配置文件路径（留空则与路由台账同目录；里面有 API Token 与连接器令牌，权限 0600）"),
		startCFTunnel: flag.Bool("start-cftunnel", false, "启动时无条件拉起全部 Cloudflare Tunnel 连接器（不加则按上次退出时的开关状态恢复）"),
	}
	flag.Parse()
	return o
}

func main() {
	opt := parseFlags()

	statePath := setupRoutes(opt)
	setupUplinks(opt, statePath) // 必须在 setupProxy 之前：代理实例要绑到出口线路上
	setupWiFi(opt, statePath)
	setupDNS(opt, statePath)
	setupProxy(opt, statePath)
	setupCFTunnel(opt, statePath)

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

// setupUplinks 载入出口线路台账并与内核对账。
//
// 必须在 setupProxy 之前跑：代理实例可能绑定了某条线路，线路没生效时实例会拒绝
// 启动（而不是悄悄从默认网关出去）。
//
// 对账包含清扫残留：内核里的 ip rule 和路由表在进程被 SIGKILL 之后仍然留着，
// 拦不住也清不掉，开机时对着台账扫一遍是唯一可靠的时机。所以退出时不做清理，
// 要彻底清掉请用 -uplink-cleanup。
func setupUplinks(opt options, statePath string) {
	uplink.DryRun = *opt.uplinkDryRun
	if uplink.DryRun {
		log.Printf("[Uplink] dry-run 模式：只打印将要执行的 ip 命令，不会真的下发")
	}

	path := uplink.ResolveStateFile(*opt.uplinkFile, statePath)
	if path != "" {
		log.Printf("[Uplink] 出口线路台账文件: %s", path)
	}
	uplink.Default.Load(path)

	if *opt.uplinkCleanup {
		if err := uplink.Default.Cleanup(); err != nil {
			log.Fatalf("[Uplink] 清理失败: %v", err)
		}
		log.Printf("[Uplink] 已清掉本程序装过的 ip rule 与路由表（台账保留），进程退出")
		os.Exit(0)
	}

	c := uplink.Default.Capability()
	if c.PerGatewaySameInterface {
		log.Printf("[Uplink] 出口绑定方式: %s，可区分同一块网卡上的多个网关", c.Mode)
	} else {
		log.Printf("[Uplink] 出口绑定方式: %s，只能按网卡区分出口，同一块网卡上的两个网关分不开", c.Mode)
	}

	uplink.Default.Reconcile()

	// 对账之后再报告检查项：suppress_prefixlength 是否可用要等第一次下发才知道，
	// 而它一旦缺席，"路由管理"里的目标路由对绑了出口的实例就全部失效——
	// 这种静默失效必须在启动日志里说出来。
	for _, chk := range uplink.Default.Capability().Checks {
		if chk.OK {
			continue
		}
		msg := fmt.Sprintf("[Uplink] 注意: %s 不可用", chk.Name)
		if chk.Detail != "" {
			msg += " —— " + chk.Detail
		}
		if chk.Remedy != "" {
			msg += "（处理办法: " + chk.Remedy + "）"
		}
		log.Print(msg)
	}
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

// setupProxy 载入代理实例与各自上次的开关状态：上次退出前开着的就自动拉起来，
// 加 -start-proxy 则无条件启动全部实例。
//
// 必须在 setupUplinks 之后：绑定了出口线路的实例要能查到线路是否已经生效，
// 没生效时它会拒绝启动，而不是悄悄从默认网关出去。
func setupProxy(opt options, statePath string) {
	proxy.Default.SetUplinks(uplink.Default)
	proxy.Default.Load(proxy.ResolveConfigFile(*opt.proxyConfigFile, statePath))
	if path := proxy.Default.ConfigPath(); path != "" {
		log.Printf("[SOCKS5] 代理配置文件: %s", path)
	}
	// 命令行参数只作用于主实例：它们是单实例时代留下来的，多实例只走 Web 界面
	if err := proxy.Default.ApplyFlags(*opt.socksPort, *opt.proxyDNS); err != nil {
		log.Fatalf("[SOCKS5] 命令行代理配置无效: %v", err)
	}

	proxy.Default.StartSaved(*opt.startProxy)
}

// setupCFTunnel 载入 Cloudflare Tunnel 台账，并按各隧道上次的开关状态把
// cloudflared 连接器拉起来。
//
// 这是唯一一个会 fork 子进程的模块，所以顺手在这里挂上退出信号的处理：连接器是
// 独立进程，本进程直接死掉的话它们会变成孤儿继续挂着隧道，下次启动就成了同一条
// 隧道跑两个连接器。收到 SIGTERM/SIGINT 时先把它们收掉再退出。
func setupCFTunnel(opt options, statePath string) {
	cftunnel.Default.Load(cftunnel.ResolveConfigFile(*opt.cfTunnelFile, statePath))
	if path := cftunnel.Default.ConfigPath(); path != "" {
		log.Printf("[CFTunnel] 隧道配置文件: %s", path)
	}

	cftunnel.Default.StartSaved(*opt.startCFTunnel)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sig
		log.Printf("[Main] 收到 %s，正在停止 cloudflared 连接器…", s)
		cftunnel.Default.StopAll()
		os.Exit(0)
	}()
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
