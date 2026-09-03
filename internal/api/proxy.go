package api

// SOCKS5 代理相关接口：实例的增删改查与启停、状态与配置、流量统计、出口探测。
// 本机网卡列表也在这儿（/api/interfaces），供出口线路挑网关用。
//
// 兼容性：/api/status、/api/proxy、/api/stats、/api/egress-ip 这几个老接口全部保留，
// 不带 id 时作用于主实例（order 里的第一个），README 里的 curl 例子和用户脚本照常能用。
// 带上 ?id= 或请求体里的 id 就是多实例用法。

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

// resolveInstance 找出请求指定的实例；没指定就用主实例。
func resolveInstance(id string) (*proxysrv.Server, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		s := proxysrv.Default.Primary()
		if s == nil {
			return nil, fmt.Errorf("当前没有任何代理实例")
		}
		return s, nil
	}
	s, ok := proxysrv.Default.Get(id)
	if !ok {
		return nil, fmt.Errorf("代理实例 %s 不存在", id)
	}
	return s, nil
}

func handleInterfaces(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"interfaces": netiface.List(),
	})
}

// handleStats 返回某个实例的连接与流量，并附上全部实例的汇总供顶部统计卡使用。
// totals 是新增字段，不带 id 时的其余内容与改造前一致。
func handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	payload := map[string]interface{}{"totals": proxysrv.Default.TotalsSnapshot()}
	if s, err := resolveInstance(r.URL.Query().Get("id")); err == nil {
		for k, v := range s.Stats().Snapshot() {
			payload[k] = v
		}
		payload["id"] = s.ID()
	}
	json.NewEncoder(w).Encode(payload)
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		s, err := resolveInstance(r.URL.Query().Get("id"))
		if err != nil {
			// 一个实例都没有也要给出可渲染的响应，前端据此显示空列表
			json.NewEncoder(w).Encode(map[string]interface{}{
				"instances":           instanceViews(),
				"process_started_at":  processStartedAt,
				"process_uptime_secs": int(time.Since(processStartedAt).Seconds()),
				"server_time":         time.Now(),
			})
			return
		}
		json.NewEncoder(w).Encode(proxyStatusPayload(s))

	case http.MethodPost:
		var req struct {
			ID        string  `json:"id"`
			Name      string  `json:"name"`
			SocksPort string  `json:"socks_port"`
			Listen    *string `json:"listen"`    // 指针：没传就保持原样，别把用户设的 0.0.0.0 悄悄改回本机
			UplinkID  *string `json:"uplink_id"` // 指针：区分"没传"和"传了空串（解绑）"
			DNS       string  `json:"dns"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s, err := resolveInstance(req.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if req.SocksPort == "" {
			http.Error(w, "socks_port is required", http.StatusBadRequest)
			return
		}

		cfg := s.Config()
		cfg.Port = req.SocksPort
		cfg.DNS = req.DNS
		if req.Name != "" {
			cfg.Name = req.Name
		}
		if req.Listen != nil {
			cfg.Listen = *req.Listen
		}
		if req.UplinkID != nil {
			cfg.UplinkID = *req.UplinkID
		}
		// 校验都在 SetConfig 里（端口冲突、出口线路是否生效、DNS），
		// 这里不重复一遍，免得两处规则慢慢走偏
		if err := s.SetConfig(cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		payload := proxyStatusPayload(s)
		payload["status"] = "success"
		json.NewEncoder(w).Encode(payload)

	default:
		methodNotAllowed(w)
	}
}

// instanceView 是一个实例在列表里的样子：配置 + 此刻的运行状态
type instanceView struct {
	proxysrv.Instance
	IsRunning     bool   `json:"is_running"`
	StartedAt     *int64 `json:"started_at_unix,omitempty"`
	UptimeSeconds int    `json:"uptime_seconds"`
	ActiveConns   int    `json:"active_connections"`
	BytesIn       int64  `json:"bytes_in"`
	BytesOut      int64  `json:"bytes_out"`
}

func instanceViews() []instanceView {
	servers := proxysrv.Default.List()
	views := make([]instanceView, 0, len(servers))
	for _, s := range servers {
		snap := s.Stats().Snapshot()
		v := instanceView{
			Instance:    s.Config(),
			IsRunning:   s.Running(),
			ActiveConns: snap["active_connections_count"].(int),
			BytesIn:     snap["total_bytes_in"].(int64),
			BytesOut:    snap["total_bytes_out"].(int64),
		}
		if started := s.StartedAt(); v.IsRunning && !started.IsZero() {
			unix := started.Unix()
			v.StartedAt = &unix
			v.UptimeSeconds = int(time.Since(started).Seconds())
		}
		views = append(views, v)
	}
	return views
}

// proxyStatusPayload 汇总某个实例的开关状态与配置，并带上全部实例的列表。
// 实例停止时 started_at 为空、运行时长归零，前端据此显示「已停止」。
func proxyStatusPayload(s *proxysrv.Server) map[string]interface{} {
	cfg := s.Config()
	running := s.Running()
	startedAt := s.StartedAt()

	payload := map[string]interface{}{
		"id":                  s.ID(),
		"name":                cfg.Name,
		"running":             running,
		"proxy_state":         map[bool]string{true: "running", false: "stopped"}[running],
		"socks_port":          cfg.Port,
		"listen":              cfg.Listen,
		"egress_check_url":    egressCheckURL,
		"uplink_id":           cfg.UplinkID,
		"dns":                 cfg.DNS,
		"started_at":          nil, // 本实例最近一次启动（改配置会重启）
		"uptime_seconds":      0,
		"process_started_at":  processStartedAt, // 进程启动，代理开关不影响
		"process_uptime_secs": int(time.Since(processStartedAt).Seconds()),
		"server_time":         time.Now(),
		"instances":           instanceViews(),
	}
	if running && !startedAt.IsZero() {
		payload["started_at"] = startedAt
		payload["uptime_seconds"] = int(time.Since(startedAt).Seconds())
	}
	return payload
}

// handleProxyPower 单独控制实例的启停，与保存配置分开：
// 默认不启动，用户改好端口和出口再点启动。
func handleProxyPower(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var req struct {
		ID     string `json:"id"`
		Action string `json:"action"` // start | stop
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s, err := resolveInstance(req.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	switch req.Action {
	case "start":
		if err := s.StartCurrent(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "stop":
		if err := s.Stop(); err != nil {
			// 监听口关闭出错不影响"已停止"这个结果，如实回报即可
			log.Printf("[SOCKS5] 停止实例时出错: %v", err)
		}
	default:
		http.Error(w, `action must be "start" or "stop"`, http.StatusBadRequest)
		return
	}

	payload := proxyStatusPayload(s)
	payload["status"] = "success"
	json.NewEncoder(w).Encode(payload)
}

// handleProxyInstances 是实例本身的增删：改配置仍然走 /api/status。
func handleProxyInstances(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(map[string]interface{}{
			"instances": instanceViews(),
			"totals":    proxysrv.Default.TotalsSnapshot(),
		})

	case http.MethodPost:
		var cfg proxysrv.Instance
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s, err := proxysrv.Default.Add(cfg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		payload := proxyStatusPayload(s)
		payload["status"] = "success"
		json.NewEncoder(w).Encode(payload)

	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			http.Error(w, "id 不能为空", http.StatusBadRequest)
			return
		}
		if proxysrv.Default.Count() <= 1 {
			http.Error(w, "至少要保留一个代理实例", http.StatusBadRequest)
			return
		}
		if err := proxysrv.Default.Delete(id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success", "id": id, "instances": instanceViews(),
		})

	default:
		methodNotAllowed(w)
	}
}

// 出口探测服务：与 README 中的
// curl --socks5-hostname 127.0.0.1:<port> 'https://myip.ipip.net/' 等价。
//
// 这是本程序唯一一个会主动连第三方的功能，而且只在用户点「检测出口」时才发。
// 换一家（或换成自建的回显服务）用 -egress-check-url，或环境变量
// NETTOOL_EGRESS_CHECK_URL。
var egressCheckURL = "https://myip.ipip.net/"

// SetEgressCheckURL 覆盖出口探测用的地址，空串表示沿用默认
func SetEgressCheckURL(u string) {
	if u = strings.TrimSpace(u); u != "" {
		egressCheckURL = u
	}
}

var egressIPPattern = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)

// handleEgressIP 真的通过某个实例的 SOCKS5 端口发一次请求，用来确认
// "这个实例的出口到底有没有生效"——只看本地配置是看不出来的。
//
// 注意它的局限：两个网关同属一个 ISP 时，出口公网 IP 是一样的，分不出差别。
// 那种情况要用「路由管理 → 出口线路」里的验证按钮（ip route get ... mark）。
func handleEgressIP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	s, err := resolveInstance(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	cfg := s.Config()
	proxyAddr := net.JoinHostPort("127.0.0.1", cfg.Port)
	command := fmt.Sprintf("curl --socks5-hostname %s '%s'", proxyAddr, egressCheckURL)

	respond := func(status int, payload map[string]interface{}) {
		payload["id"] = s.ID()
		payload["name"] = cfg.Name
		payload["socks_port"] = cfg.Port
		payload["uplink_id"] = cfg.UplinkID
		payload["command"] = command
		payload["checked_at"] = time.Now()
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(payload)
	}

	if !s.Running() {
		respond(http.StatusConflict, map[string]interface{}{
			"ok": false, "error": "该实例当前处于停止状态，请先启动再检测",
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
		log.Printf("[Egress] 实例「%s」出口探测失败 (端口 %s): %v", cfg.Name, cfg.Port, err)
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
	// 只记「成功了」，不把探到的公网 IP 写进日志：日志经常被收集、被贴进
	// issue，机主的真实出口 IP 不该跟着一起走。结果照常回给发起请求的人。
	log.Printf("[Egress] 实例「%s」出口探测成功 (端口 %s)", cfg.Name, cfg.Port)

	respond(http.StatusOK, map[string]interface{}{
		"ok":        true,
		"egress_ip": egressIP,
		"raw":       raw,
	})
}
