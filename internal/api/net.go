package api

// /api/net/* —— 网卡当前配置、直接下发配置、Wi-Fi 配置档的增删改与立即应用。

import (
	"encoding/json"
	"net/http"
	"runtime"
	"strings"

	"nettool/internal/netconfig"
)

func handleNetInterfaces(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	list, err := netconfig.ListNICs()
	payload := map[string]interface{}{
		"os":         runtime.GOOS,
		"interfaces": list,
	}
	if err != nil {
		payload["error"] = err.Error()
	}
	json.NewEncoder(w).Encode(payload)
}

func handleNetApply(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var req struct {
		Service string `json:"service"`
		Device  string `json:"device"`
		netconfig.Settings
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Service) == "" {
		http.Error(w, "service 不能为空", http.StatusBadRequest)
		return
	}
	if _, err := netconfig.ValidateSettings(req.Settings); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	target := netconfig.Target{Device: req.Device, Service: req.Service}
	if err := netconfig.Apply(target, req.Settings); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	list, _ := netconfig.ListNICs()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "success",
		"applied":    netconfig.Describe(req.Settings),
		"interfaces": list,
	})
}

func handleWiFiStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	// 界面刷新时顺带探一次 SSID，但不在这里自动切换：切换只由后台轮询触发，
	// 免得刷个页面就把网卡配置改了
	netconfig.CheckWiFi(netconfig.CheckObserve)

	payload := netconfig.Monitor.Status()
	payload["profiles"] = netconfig.Profiles.List()
	payload["profile_file"] = netconfig.Profiles.Path()
	// 告诉界面当前这个 Wi-Fi 命中的是哪一档（可能是兜底的默认档）
	payload["matched_ssid"] = netconfig.Monitor.MatchedSSID()
	json.NewEncoder(w).Encode(payload)
}

func handleWiFiProfiles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodPost:
		saveWiFiProfile(w, r)
	case http.MethodDelete:
		deleteWiFiProfile(w, r)
	default:
		methodNotAllowed(w)
	}
}

func saveWiFiProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SSID      string             `json:"ssid"`
		NetworkID string             `json:"network_id"`
		IsDefault bool               `json:"is_default"`
		Service   string             `json:"service"`
		Device    string             `json:"device"`
		Enabled   *bool              `json:"enabled"`
		Settings  netconfig.Settings `json:"settings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 只改启用开关时不必带完整配置
	if req.Enabled != nil && req.Settings.Method == "" {
		p, ok := netconfig.Profiles.SetEnabled(strings.TrimSpace(req.SSID), *req.Enabled)
		if !ok {
			http.Error(w, "配置档不存在", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "profile": p})
		return
	}

	p := netconfig.Profile{
		SSID: req.SSID, NetworkID: strings.TrimSpace(req.NetworkID), IsDefault: req.IsDefault,
		Service: req.Service, Device: req.Device, Settings: req.Settings, Enabled: true,
	}
	if req.Enabled != nil {
		p.Enabled = *req.Enabled
	}
	saved, err := netconfig.Profiles.Save(p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "profile": saved})
}

func deleteWiFiProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SSID string `json:"ssid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !netconfig.Profiles.Delete(strings.TrimSpace(req.SSID)) {
		http.Error(w, "配置档不存在", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func handleWiFiApply(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var req struct {
		SSID string `json:"ssid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ssid := strings.TrimSpace(req.SSID)
	if ssid == "" {
		http.Error(w, "ssid 不能为空", http.StatusBadRequest)
		return
	}

	if err := netconfig.ApplyProfileForSSID(ssid, true); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	list, _ := netconfig.ListNICs()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "success",
		"interfaces": list,
		"profiles":   netconfig.Profiles.List(),
	})
}
