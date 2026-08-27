package api

// /api/routes* —— 路由台账的增删改查、重新解析、暂停/恢复、重新下发。

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"nettool/internal/route"
)

func handleRoutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		listRoutes(w)
	case http.MethodPost:
		addRoute(w, r)
	case http.MethodDelete:
		deleteRoute(w, r)
	default:
		methodNotAllowed(w)
	}
}

func listRoutes(w http.ResponseWriter) {
	routes := route.Default.ListRoutes()
	kernel, kernelErr := route.KernelTable()

	// 台账里的每一条都标出当前是否还在内核路由表中
	type routeView struct {
		route.Rule
		Status string `json:"status"` // active / missing / unknown
	}
	views := make([]routeView, 0, len(routes))
	for _, r := range routes {
		status := "unknown"
		if r.Paused {
			status = "paused" // 暂停的本来就不在内核里，不算失效
		} else if kernelErr == nil {
			status = "missing"
			if route.KernelHasRoute(kernel, r.Destination, r.Gateway) {
				status = "active"
			}
		}
		views = append(views, routeView{Rule: r, Status: status})
	}

	// Linux 上还能反向找出"内核里带本程序标记、但台账里没有"的漏网之鱼
	orphans := make([]route.KernelRoute, 0)
	if kernelErr == nil {
		for _, kr := range kernel {
			if !kr.Ours {
				continue
			}
			if !containsDestination(routes, kr.Destination) {
				orphans = append(orphans, kr)
			}
		}
	}

	payload := map[string]interface{}{
		"routes":                 views,
		"orphans":                orphans,
		"state_file":             route.StateFile(),
		"domain_refresh_seconds": int(route.RefreshInterval().Seconds()),
		"domains":                route.Default.ListDomainEntries(),
	}
	if kernelErr != nil {
		payload["reconcile_error"] = kernelErr.Error()
	}
	json.NewEncoder(w).Encode(payload)
}

func addRoute(w http.ResponseWriter, r *http.Request) {
	var rule route.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if rule.Destination == "" || rule.Gateway == "" {
		http.Error(w, "destination and gateway are required", http.StatusBadRequest)
		return
	}
	if net.ParseIP(rule.Gateway) == nil {
		http.Error(w, fmt.Sprintf("网关 %q 不是合法的 IP 地址", rule.Gateway), http.StatusBadRequest)
		return
	}

	result, err := route.Default.AddTarget(rule.Destination, rule.Gateway, rule.Interface)
	if err != nil {
		// 解析/校验类错误属于用户输入问题，下发失败才是系统问题
		status := http.StatusBadRequest
		if result != nil {
			status = http.StatusInternalServerError
			if len(result.Failed) > 0 {
				http.Error(w, result.Failed[0].Error, status)
				return
			}
		}
		http.Error(w, err.Error(), status)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(result)
}

func deleteRoute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Destination string `json:"destination"`
		Domain      string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Domain != "" {
		deleted, err := route.Default.DeleteDomain(req.Domain)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success", "domain": req.Domain, "deleted": deleted,
		})
		return
	}

	if req.Destination == "" {
		http.Error(w, "destination is required", http.StatusBadRequest)
		return
	}
	if err := route.Default.DeleteRoute(req.Destination); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "route deleted"})
}

func containsDestination(routes []route.Rule, dest string) bool {
	for _, r := range routes {
		if r.Destination == dest {
			return true
		}
	}
	return false
}

// handleRefreshDomain 重新解析域名，让路由跟上最新的 A 记录。
func handleRefreshDomain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Domain == "" {
		http.Error(w, "domain is required", http.StatusBadRequest)
		return
	}

	result, err := route.Default.RefreshDomain(req.Domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(result)
}

// handlePauseRoutes 暂停/恢复路由：暂停即从内核撤下但保留台账记录。
// 可按单条 destination、按 domain，或 all=true 全部操作。
func handlePauseRoutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var req struct {
		Destination string `json:"destination"`
		Domain      string `json:"domain"`
		All         bool   `json:"all"`
		Paused      bool   `json:"paused"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var changed []string
	var failed []route.OpError

	switch {
	case req.Domain != "":
		var err error
		changed, failed, err = route.Default.SetDomainPaused(req.Domain, req.Paused)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
	case req.All:
		changed, failed = route.Default.SetPaused(nil, req.Paused)
	case req.Destination != "":
		changed, failed = route.Default.SetPaused([]string{req.Destination}, req.Paused)
	default:
		http.Error(w, "需要指定 destination、domain 或 all", http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"paused":  req.Paused,
		"changed": changed,
		"failed":  failed,
	})
}

// handleRestoreRoutes 把台账里已失效的路由重新下发（机器重启后内核路由会丢）。
func handleRestoreRoutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var req struct {
		Destinations []string `json:"destinations"`
	}
	// 允许空 body，表示重下全部
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	// 先把作用域对上：作用域错的路由内核里"看着还在"，只重下发是修不好的
	rescoped, rescopeFailed := route.Default.RescopeRoutes()
	restored, failed := route.Default.RestoreRoutes(req.Destinations)
	failed = append(failed, rescopeFailed...)

	rescopedDests := make([]string, 0, len(rescoped))
	for _, r := range rescoped {
		rescopedDests = append(rescopedDests, r.Destination)
	}

	status := http.StatusOK
	if len(restored) == 0 && len(rescoped) == 0 && len(failed) > 0 {
		status = http.StatusInternalServerError
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"restored": restored,
		"rescoped": rescopedDests,
		"failed":   failed,
	})
}

func handleSystemRoutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"routes": route.SystemRoutes(),
	})
}
