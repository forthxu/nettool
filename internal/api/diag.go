package api

// /api/diag/* —— ping 与 traceroute。两者都是后台任务：POST 起一个任务立刻返回，
// 前端拿着任务 ID 轮询增量结果，这样每一包 / 每一跳都能边跑边看。

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"nettool/internal/netdiag"
)

func handleDiagPing(w http.ResponseWriter, r *http.Request) {
	startDiag(w, r, netdiag.KindPing)
}

func handleDiagTraceroute(w http.ResponseWriter, r *http.Request) {
	startDiag(w, r, netdiag.KindTrace)
}

func startDiag(w http.ResponseWriter, r *http.Request, kind string) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var opts netdiag.Options
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	job, err := netdiag.Start(kind, opts)
	if err != nil {
		// 套接字开不出来通常是权限问题，和"参数填错了"分开回，前端好给不同的提示
		status := http.StatusBadRequest
		if errors.Is(err, netdiag.ErrICMPUnavailable) {
			status = http.StatusForbidden
		}
		http.Error(w, err.Error(), status)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "job": job.Snapshot()})
}

// handleDiagJob 按 id 取任务；只给 kind 时取该类诊断最近的一次，
// 这样刷新页面后不用前端自己记 ID 也能接着看。
func handleDiagJob(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	id := strings.TrimSpace(r.URL.Query().Get("id"))
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))

	var job *netdiag.Job
	switch {
	case id != "":
		job = netdiag.Get(id)
	case kind != "":
		job = netdiag.Latest(kind)
	default:
		http.Error(w, "id 或 kind 至少要给一个", http.StatusBadRequest)
		return
	}

	// 没有任务不算错：页面刚打开、还没点过诊断就是这个状态
	if job == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"found": false})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"found": true, "job": job.Snapshot()})
}

func handleDiagStop(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !netdiag.Stop(strings.TrimSpace(req.ID)) {
		http.Error(w, "没有这个诊断任务（可能已经被新的诊断挤掉了）", http.StatusNotFound)
		return
	}

	payload := map[string]interface{}{"status": "success"}
	if job := netdiag.Get(req.ID); job != nil {
		payload["job"] = job.Snapshot()
	}
	json.NewEncoder(w).Encode(payload)
}
