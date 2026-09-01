package api

// /api/cftunnel* —— Cloudflare Tunnel 的账号设置、隧道增删启停、ingress 规则、
// DNS 记录、cloudflared 安装与快速隧道。
//
// 路径风格与 /api/uplinks* 一致：资源 id 走查询参数或请求体，不用路径通配符。

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"nettool/internal/cftunnel"
)

// cfOverview 是「CF 隧道」页一次要的全部东西
func cfOverview() map[string]interface{} {
	payload := map[string]interface{}{
		"settings":    cftunnel.Default.SettingsView(),
		"binary":      cftunnel.Default.BinaryStatus(),
		"install":     cftunnel.Default.InstallState(),
		"tunnels":     cftunnel.Default.Tunnels(),
		"quick":       cftunnel.Default.QuickStatus(),
		"config_file": cftunnel.Default.ConfigPath(),
		"server_time": time.Now(),
	}
	if at := cftunnel.Default.SyncedAt(); !at.IsZero() {
		payload["synced_at"] = at
	}
	return payload
}

func writeCFOverview(w http.ResponseWriter) {
	payload := cfOverview()
	payload["status"] = "success"
	json.NewEncoder(w).Encode(payload)
}

func handleCFTunnel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	json.NewEncoder(w).Encode(cfOverview())
}

// handleCFSettings 保存账号级配置。api_token 留空表示不动已存的那份——界面上
// 显示的是脱敏值，用户没改它的时候不该把 Token 冲掉。
func handleCFSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var req struct {
		cftunnel.Settings
		ClearToken bool `json:"clear_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := cftunnel.Default.SetSettings(req.Settings, req.ClearToken); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeCFOverview(w)
}

// handleCFToken 把明文 API Token 交给界面上的小眼睛。
//
// 别处一律只给脱敏值（token_masked），这里是唯一的例外——换机器时总得能把它抄出来。
// 注意它不比这个界面上的别的东西更该被信任：没配 -user/-pass 时整个管理面本来就是
// 敞开的，谁能打开这个页面谁就能改隧道、下 DNS。真要放在不可信网络上，请开认证。
func handleCFToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store") // 别让它落进任何中间缓存
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	token, err := cftunnel.Default.RevealToken()
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "api_token": token})
}

// handleCFVerify 验证 Token 并返回它能访问的账号列表
func handleCFVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var req struct {
		APIToken string `json:"api_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	accounts, err := cftunnel.Default.VerifyToken(req.APIToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	payload := cfOverview()
	payload["status"] = "success"
	payload["accounts"] = accounts
	json.NewEncoder(w).Encode(payload)
}

// handleCFSync 拉云端隧道列表。返回的 remote 里包含本地还没接管的那些。
func handleCFSync(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	list, err := cftunnel.Default.Sync()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	payload := cfOverview()
	payload["status"] = "success"
	payload["remote"] = list
	json.NewEncoder(w).Encode(payload)
}

// handleCFTunnels 新建（云端创建）/ 接管 / 删除隧道
func handleCFTunnels(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodPost:
		var req struct {
			Name string `json:"name"`
			CFID string `json:"cf_id"` // 填了就是接管已有的，没填就是新建
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var err error
		if strings.TrimSpace(req.CFID) != "" {
			_, err = cftunnel.Default.Adopt(req.CFID, req.Name)
		} else {
			_, err = cftunnel.Default.Create(req.Name)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeCFOverview(w)

	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			http.Error(w, "id 不能为空", http.StatusBadRequest)
			return
		}
		// remote=1 时连云端的隧道一起删，默认只解除本地接管
		remote := r.URL.Query().Get("remote") == "1"
		if err := cftunnel.Default.Delete(id, remote); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeCFOverview(w)

	default:
		methodNotAllowed(w)
	}
}

// handleCFDiscover 扫出本机已经在用、还没接管的隧道。
// 只读文件不联网，所以没配 API Token 也能用。
func handleCFDiscover(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	// dir 可以给多次，让用户把自己那个非标准目录补进来
	extra := r.URL.Query()["dir"]
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "success",
		"candidates": cftunnel.Default.Discover(extra),
	})
}

// handleCFImport 导入一条本机已有的隧道：凭证文件用来接管（不联网、不要
// API Token），config 文件里的规则搬到云端（这一步要 Token，留空则跳过）。
func handleCFImport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var req struct {
		CredentialsPath string `json:"credentials_path"`
		ConfigPath      string `json:"config_path"`
		Name            string `json:"name"` // 可选，扫描时从 config 认出来的名字
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, msg, err := cftunnel.Default.Import(req.CredentialsPath, req.ConfigPath, req.Name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	payload := cfOverview()
	payload["status"] = "success"
	payload["message"] = msg
	json.NewEncoder(w).Encode(payload)
}

// handleCFPower 启停某条隧道的本地连接器
func handleCFPower(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var req struct {
		ID     string `json:"id"`
		Action string `json:"action"` // start | stop | refresh-token
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var err error
	switch req.Action {
	case "start":
		err = cftunnel.Default.Start(req.ID)
	case "stop":
		err = cftunnel.Default.Stop(req.ID)
	case "refresh-token":
		err = cftunnel.Default.RefreshToken(req.ID)
	default:
		http.Error(w, `action must be "start", "stop" or "refresh-token"`, http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeCFOverview(w)
}

// handleCFLogs 取连接器输出。after 是上次拿到的最大序号，只回增量。
func handleCFLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	id := strings.TrimSpace(r.URL.Query().Get("id"))

	var lines []cftunnel.LogLine
	if id == "quick" {
		lines = cftunnel.Default.QuickLogs(after)
	} else {
		var err error
		if lines, err = cftunnel.Default.Logs(id, after); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"id": id, "lines": lines})
}

// handleCFIngress 读写某条隧道的 ingress 规则（存在 Cloudflare 那边）
func handleCFIngress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		rules, err := cftunnel.Default.Ingress(strings.TrimSpace(r.URL.Query().Get("id")))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "ingress": rules})

	case http.MethodPost:
		var req struct {
			ID      string                 `json:"id"`
			Ingress []cftunnel.IngressRule `json:"ingress"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rules, note, err := cftunnel.Default.SetIngress(req.ID, req.Ingress)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		payload := map[string]interface{}{"status": "success", "ingress": rules}
		if note != "" {
			payload["message"] = note
		}
		json.NewEncoder(w).Encode(payload)

	default:
		methodNotAllowed(w)
	}
}

// handleCFZones 列出账号下的域名，给「下 DNS 记录」用
func handleCFZones(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	zones, err := cftunnel.Default.Zones(r.URL.Query().Get("refresh") == "1")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "zones": zones})
}

// handleCFDNS 把一个域名的 CNAME 指到隧道上（POST），或者把它删掉（DELETE）。
//
// 删规则不碰 DNS，两边是分开的，所以删记录得单独调一次。
func handleCFDNS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodPost:
		var req struct {
			ID       string `json:"id"`
			Hostname string `json:"hostname"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		msg, err := cftunnel.Default.AttachDNS(req.ID, req.Hostname)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "message": msg})

	case http.MethodDelete:
		msg, err := cftunnel.Default.DetachDNS(
			strings.TrimSpace(r.URL.Query().Get("id")),
			strings.TrimSpace(r.URL.Query().Get("hostname")))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "message": msg})

	default:
		methodNotAllowed(w)
	}
}

// handleCFBinary 查看 / 安装 cloudflared
func handleCFBinary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(map[string]interface{}{
			"binary":  cftunnel.Default.BinaryStatus(),
			"install": cftunnel.Default.InstallState(),
		})

	case http.MethodPost: // 触发下载，立刻返回，进度靠轮询上面那个 GET
		if err := cftunnel.Default.InstallBinary(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "success",
			"install": cftunnel.Default.InstallState(),
		})

	default:
		methodNotAllowed(w)
	}
}

// handleCFQuick 启停快速隧道（TryCloudflare，不需要账号）
func handleCFQuick(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var req struct {
		Action string `json:"action"` // start | stop
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch req.Action {
	case "start":
		if err := cftunnel.Default.StartQuick(req.Target); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	case "stop":
		cftunnel.Default.StopQuick()
	default:
		http.Error(w, `action must be "start" or "stop"`, http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"quick":  cftunnel.Default.QuickStatus(),
	})
}
