package api

// SOCKS5 代理相关接口：状态与配置、启停、流量统计、出口探测、可选出口网卡。

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"nettool/internal/netiface"
	proxysrv "nettool/internal/proxy"
)

// processStartedAt 是进程本身的启动时间，代理重启不影响它
var processStartedAt = time.Now()

func handleInterfaces(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	_, outboundIP, _ := proxysrv.Default.GetConfig()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"interfaces":  netiface.List(),
		"outbound_ip": outboundIP,
	})
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	json.NewEncoder(w).Encode(proxysrv.Stats.Snapshot())
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(proxyStatusPayload())

	case http.MethodPost:
		var req struct {
			SocksPort  string `json:"socks_port"`
			OutboundIP string `json:"outbound_ip"`
			DNS        string `json:"dns"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.SocksPort == "" {
			http.Error(w, "socks_port is required", http.StatusBadRequest)
			return
		}
		if req.OutboundIP != "" {
			if _, err := netiface.ValidateOutbound(req.OutboundIP); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		// 代理停着的时候只存配置，不会被动拉起来
		if _, err := proxysrv.NormalizeDNSAddr(req.DNS); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := proxysrv.Default.SetConfig(req.SocksPort, req.OutboundIP, req.DNS); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		payload := proxyStatusPayload()
		payload["status"] = "success"
		json.NewEncoder(w).Encode(payload)

	default:
		methodNotAllowed(w)
	}
}

// proxyStatusPayload 汇总代理的开关状态与配置。代理停止时 started_at 为空，
// 运行时长归零，前端据此显示「已停止」。
func proxyStatusPayload() map[string]interface{} {
	port, outboundIP, dns := proxysrv.Default.GetConfig()
	running := proxysrv.Default.Running()
	startedAt := proxysrv.Default.StartedAt()

	payload := map[string]interface{}{
		"running":             running,
		"proxy_state":         map[bool]string{true: "running", false: "stopped"}[running],
		"socks_port":          port,
		"outbound_ip":         outboundIP,
		"dns":                 dns,
		"started_at":          nil, // 代理最近一次启动（改配置会重启）
		"uptime_seconds":      0,
		"process_started_at":  processStartedAt, // 进程启动，代理开关不影响
		"process_uptime_secs": int(time.Since(processStartedAt).Seconds()),
		"server_time":         time.Now(),
	}
	if running && !startedAt.IsZero() {
		payload["started_at"] = startedAt
		payload["uptime_seconds"] = int(time.Since(startedAt).Seconds())
	}
	return payload
}

// handleProxyPower 单独控制代理的启停，与保存配置分开：
// 默认不启动，用户改好端口和出口 IP 再点启动。
func handleProxyPower(w http.ResponseWriter, r *http.Request) {
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
		if err := proxysrv.Default.StartCurrent(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "stop":
		if err := proxysrv.Default.Stop(); err != nil {
			// 监听口关闭出错不影响"已停止"这个结果，如实回报即可
			log.Printf("[SOCKS5] 停止代理时出错: %v", err)
		}
	default:
		http.Error(w, `action must be "start" or "stop"`, http.StatusBadRequest)
		return
	}

	payload := proxyStatusPayload()
	payload["status"] = "success"
	json.NewEncoder(w).Encode(payload)
}

// 出口探测服务：与 README 中的
// curl --socks5-hostname 127.0.0.1:<port> 'https://myip.ipip.net/' 等价
const egressCheckURL = "https://myip.ipip.net/"

var egressIPPattern = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)

// handleEgressIP 真的通过本机 SOCKS5 端口发一次请求，用来确认"绑定的出口 IP
// 到底有没有生效"——只看本地配置是看不出来的。
func handleEgressIP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	port, outboundIP, _ := proxysrv.Default.GetConfig()
	proxyAddr := net.JoinHostPort("127.0.0.1", port)
	command := fmt.Sprintf("curl --socks5-hostname %s '%s'", proxyAddr, egressCheckURL)

	respond := func(status int, payload map[string]interface{}) {
		payload["socks_port"] = port
		payload["bound_outbound_ip"] = outboundIP
		payload["command"] = command
		payload["checked_at"] = time.Now()
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(payload)
	}

	if !proxysrv.Default.Running() {
		respond(http.StatusConflict, map[string]interface{}{
			"ok": false, "error": "代理当前处于停止状态，请先启动代理再检测",
		})
		return
	}

	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		respond(http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "error": fmt.Sprintf("创建 SOCKS5 客户端失败: %v", err),
		})
		return
	}
	ctxDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		respond(http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "error": "SOCKS5 客户端不支持带超时的连接",
		})
		return
	}

	client := &http.Client{
		Transport: &http.Transport{DialContext: ctxDialer.DialContext},
		Timeout:   15 * time.Second,
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, egressCheckURL, nil)
	if err != nil {
		respond(http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	req.Header.Set("User-Agent", "curl/8.0")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[Egress] 出口探测失败 (端口 %s, 绑定 %s): %v", port, outboundIP, err)
		respond(http.StatusBadGateway, map[string]interface{}{
			"ok":    false,
			"error": fmt.Sprintf("经由本机 SOCKS5 请求失败: %v", err),
		})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		respond(http.StatusBadGateway, map[string]interface{}{
			"ok": false, "error": fmt.Sprintf("读取响应失败: %v", err),
		})
		return
	}

	raw := strings.TrimSpace(string(body))
	egressIP := egressIPPattern.FindString(raw)
	log.Printf("[Egress] 出口探测成功 (端口 %s, 绑定 %s): %s", port, outboundIP, raw)

	respond(http.StatusOK, map[string]interface{}{
		"ok":        true,
		"egress_ip": egressIP,
		"raw":       raw,
	})
}
