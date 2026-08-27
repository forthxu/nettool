package api

// /api/dns* —— 本地 DNS 服务的配置、启停、统计与「测试解析」。

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"lan_router_socks5/internal/dnsserver"
)

func dnsStatusPayload() map[string]interface{} {
	running := dnsserver.Default.Running()
	startedAt := dnsserver.Default.StartedAt()

	payload := map[string]interface{}{
		"running":        running,
		"settings":       dnsserver.Default.Settings(),
		"config_file":    dnsserver.ConfigPath(),
		"cache_entries":  dnsserver.Default.CacheSize(),
		"started_at":     nil,
		"uptime_seconds": 0,
		"server_time":    time.Now(),
	}
	if running && !startedAt.IsZero() {
		payload["started_at"] = startedAt
		payload["uptime_seconds"] = int(time.Since(startedAt).Seconds())
	}
	return payload
}

func handleDNSConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(dnsStatusPayload())

	case http.MethodPost:
		var req dnsserver.Settings
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := dnsserver.Default.SetConfig(req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		payload := dnsStatusPayload()
		payload["status"] = "success"
		json.NewEncoder(w).Encode(payload)

	default:
		methodNotAllowed(w)
	}
}

// handleDNSPower 单独控制启停，和保存配置分开：先把上游配好再点启动
func handleDNSPower(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var req struct {
		Action string `json:"action"` // start | stop
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch req.Action {
	case "start":
		if err := dnsserver.Default.Start(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "stop":
		dnsserver.Default.Stop()
	default:
		http.Error(w, `action must be "start" or "stop"`, http.StatusBadRequest)
		return
	}

	payload := dnsStatusPayload()
	payload["status"] = "success"
	json.NewEncoder(w).Encode(payload)
}

func handleDNSStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		payload := dnsserver.Default.StatsSnapshot()
		payload["running"] = dnsserver.Default.Running()
		payload["cache_entries"] = dnsserver.Default.CacheSize()
		json.NewEncoder(w).Encode(payload)

	case http.MethodDelete: // 清空统计和缓存
		dnsserver.Default.ResetStats()
		dnsserver.Default.PurgeCache()
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})

	default:
		methodNotAllowed(w)
	}
}

func handleDNSQuery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var req struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Upstream string `json:"upstream"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result, err := dnsserver.Default.TestQuery(req.Name, req.Type, strings.TrimSpace(req.Upstream))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	result["status_code"] = "success"
	json.NewEncoder(w).Encode(result)
}
