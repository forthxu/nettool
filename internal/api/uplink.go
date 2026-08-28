package api

// /api/uplinks* —— 出口线路的增删改查、重新下发、验证，以及本机能力自陈。
//
// 路径风格与 /api/routes* 保持一致：资源 id 走查询参数或请求体，不用路径通配符。

import (
	"encoding/json"
	"net/http"
	"strings"

	"nettool/internal/uplink"
)

func handleUplinks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(map[string]interface{}{
			"uplinks":    uplink.Default.List(),
			"capability": uplink.Default.Capability(),
		})

	case http.MethodPost:
		var spec uplink.Spec
		if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		u, err := uplink.Default.Add(spec)
		if err != nil {
			// 下发失败时线路已经进了台账（带着错误信息），把它一并回给前端，
			// 用户能看到这条线路、改完再点「重新下发」，而不是凭空消失
			writeUplinkError(w, u, err)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "uplink": u})

	case http.MethodPut:
		var req struct {
			ID string `json:"id"`
			uplink.Spec
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.ID == "" {
			http.Error(w, "id 不能为空", http.StatusBadRequest)
			return
		}
		u, err := uplink.Default.Update(req.ID, req.Spec)
		if err != nil {
			writeUplinkError(w, u, err)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "uplink": u})

	case http.MethodDelete:
		id := uplinkID(r)
		if id == "" {
			http.Error(w, "id 不能为空", http.StatusBadRequest)
			return
		}
		if err := uplink.Default.Delete(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "id": id})

	default:
		methodNotAllowed(w)
	}
}

// handleUplinkApply 重新下发一条线路：网关换了、被别的程序清掉了、
// 或者上次因为缺权限没装上，改好之后从这里重试。
func handleUplinkApply(w http.ResponseWriter, r *http.Request) {
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
	u, err := uplink.Default.Apply(req.ID)
	if err != nil {
		writeUplinkError(w, u, err)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "uplink": u})
}

// handleUplinkCheck 问内核："打上这条线路标记的流量，你到底会送到哪儿？"
//
// 这是唯一能证明"同一网段的两个网关真的被分开了"的确定性检查——不联网、不发流量。
// 公网 IP 探测在两个网关同属一个 ISP 时是分不出差别的，只能作为旁证。
func handleUplinkCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	id := uplinkID(r)
	if id == "" {
		http.Error(w, "id 不能为空", http.StatusBadRequest)
		return
	}
	u, ok := uplink.Default.Get(id)
	if !ok {
		http.Error(w, "出口线路 "+id+" 不存在", http.StatusNotFound)
		return
	}

	result, err := uplink.Default.Verify(id, strings.TrimSpace(r.URL.Query().Get("target")))
	payload := map[string]interface{}{
		"ok":               err == nil,
		"uplink":           u,
		"result":           result,
		"expected_gateway": u.Gateway,
	}
	if err != nil {
		payload["error"] = err.Error()
	}
	json.NewEncoder(w).Encode(payload)
}

// handleUplinkKernel 原样返回内核里的策略路由现状，对标 /api/system-routes。
// 排查"规则到底装上没有、有没有被别人挤掉"时，这是最直接的一手材料。
func handleUplinkKernel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	json.NewEncoder(w).Encode(uplink.Default.KernelDump())
}

// handleCapabilities 本机能力自陈。前端只需要看 per_gateway_same_interface：
// 为 false 时必须明确告诉用户"同一块网卡上的两个网关分不开"，不能含糊过去。
func handleCapabilities(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	json.NewEncoder(w).Encode(uplink.Default.Capability())
}

// uplinkID 从查询参数里取 id，与 /api/diag/job?id= 的风格一致
func uplinkID(r *http.Request) string {
	return strings.TrimSpace(r.URL.Query().Get("id"))
}

// writeUplinkError 回报一个"操作失败、但线路本身可能已经进了台账"的结果。
// 用 200 而不是 500：前端要拿到这条线路好把它画出来并显示错误原因。
func writeUplinkError(w http.ResponseWriter, u uplink.Uplink, err error) {
	if u.ID == "" {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "error", "error": err.Error(), "uplink": u,
	})
}
