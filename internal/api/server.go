// Package api 把各业务包的能力接成 HTTP 管理接口，并托管内嵌的 Web 前端。
// 所有路径共用同一份 Basic Auth（用户名密码都为空时不鉴权）。
package api

import (
	"crypto/subtle"
	"io/fs"
	"log"
	"net/http"
)

// Config 是搭起管理服务所需的全部外部依赖
type Config struct {
	Static fs.FS  // 内嵌的前端静态文件
	User   string // 留空且 Pass 也为空时不鉴权
	Pass   string
}

// Handler 组装出完整的管理服务（前端 + API + 鉴权）
func Handler(cfg Config) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(cfg.Static)))

	// 路由与台账
	mux.HandleFunc("/api/routes", handleRoutes)
	mux.HandleFunc("/api/routes/restore", handleRestoreRoutes)
	mux.HandleFunc("/api/routes/refresh", handleRefreshDomain)
	mux.HandleFunc("/api/routes/pause", handlePauseRoutes)
	mux.HandleFunc("/api/system-routes", handleSystemRoutes)

	// 出口线路（策略路由）与本机能力自陈
	mux.HandleFunc("/api/uplinks", handleUplinks)
	mux.HandleFunc("/api/uplinks/apply", handleUplinkApply)
	mux.HandleFunc("/api/uplinks/check", handleUplinkCheck)
	mux.HandleFunc("/api/uplinks/kernel", handleUplinkKernel)
	mux.HandleFunc("/api/capabilities", handleCapabilities)

	// SOCKS5 代理
	mux.HandleFunc("/api/interfaces", handleInterfaces)
	mux.HandleFunc("/api/egress-ip", handleEgressIP)
	mux.HandleFunc("/api/stats", handleStats)
	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/proxy", handleProxyPower)
	mux.HandleFunc("/api/proxy/instances", handleProxyInstances)

	// 网卡配置与 Wi-Fi 配置档
	mux.HandleFunc("/api/net/interfaces", handleNetInterfaces)
	mux.HandleFunc("/api/net/apply", handleNetApply)
	mux.HandleFunc("/api/net/wifi", handleWiFiStatus)
	mux.HandleFunc("/api/net/wifi/profiles", handleWiFiProfiles)
	mux.HandleFunc("/api/net/wifi/apply", handleWiFiApply)

	// 连通性诊断（ping / traceroute）
	mux.HandleFunc("/api/diag/ping", handleDiagPing)
	mux.HandleFunc("/api/diag/traceroute", handleDiagTraceroute)
	mux.HandleFunc("/api/diag/job", handleDiagJob)
	mux.HandleFunc("/api/diag/stop", handleDiagStop)

	// Cloudflare Tunnel（云端隧道管理 + 本地 cloudflared 连接器）
	mux.HandleFunc("/api/cftunnel", handleCFTunnel)
	mux.HandleFunc("/api/cftunnel/settings", handleCFSettings)
	mux.HandleFunc("/api/cftunnel/token", handleCFToken)
	mux.HandleFunc("/api/cftunnel/verify", handleCFVerify)
	mux.HandleFunc("/api/cftunnel/sync", handleCFSync)
	mux.HandleFunc("/api/cftunnel/tunnels", handleCFTunnels)
	mux.HandleFunc("/api/cftunnel/discover", handleCFDiscover)
	mux.HandleFunc("/api/cftunnel/import", handleCFImport)
	mux.HandleFunc("/api/cftunnel/power", handleCFPower)
	mux.HandleFunc("/api/cftunnel/logs", handleCFLogs)
	mux.HandleFunc("/api/cftunnel/ingress", handleCFIngress)
	mux.HandleFunc("/api/cftunnel/zones", handleCFZones)
	mux.HandleFunc("/api/cftunnel/dns", handleCFDNS)
	mux.HandleFunc("/api/cftunnel/binary", handleCFBinary)
	mux.HandleFunc("/api/cftunnel/quick", handleCFQuick)

	// 本地 DNS 服务
	mux.HandleFunc("/api/dns", handleDNSConfig)
	mux.HandleFunc("/api/dns/power", handleDNSPower)
	mux.HandleFunc("/api/dns/stats", handleDNSStats)
	mux.HandleFunc("/api/dns/query", handleDNSQuery)

	if cfg.User == "" && cfg.Pass == "" {
		log.Printf("[Security] Web UI & API running without authentication")
		return mux
	}
	log.Printf("[Security] Web UI & API authentication enabled (User: %s)", cfg.User)
	return basicAuth(mux, cfg.User, cfg.Pass)
}

// basicAuth 给所有路径套一层 Basic Auth
func basicAuth(next http.Handler, user, pass string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		// 用固定时间比较，避免从响应快慢上试出密码
		userMatch := subtle.ConstantTimeCompare([]byte(u), []byte(user)) == 1
		passMatch := subtle.ConstantTimeCompare([]byte(p), []byte(pass)) == 1
		if !ok || !userMatch || !passMatch {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted Access"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// methodNotAllowed 是各 handler 里重复出现的那句拒绝，统一在这里
func methodNotAllowed(w http.ResponseWriter) {
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}
