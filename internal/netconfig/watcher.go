package netconfig

// 按 SSID 自动切换网卡配置：后台定时看一眼当前连的是哪个 Wi-Fi，
// 换网了就把对应配置档下发下去。

import (
	"fmt"
	"log"
	"sync"
	"time"

	"lan_router_socks5/internal/netutil"
	"lan_router_socks5/internal/route"
)

// SwitchRecord 是最近一次切换的结果，给界面看的
type SwitchRecord struct {
	SSID    string    `json:"ssid"`
	Service string    `json:"service"`
	Detail  string    `json:"detail"`
	OK      bool      `json:"ok"`
	At      time.Time `json:"at"`
}

type Watcher struct {
	mu         sync.Mutex
	interval   time.Duration
	current    wifiIdentity // 最近一次探测到的网络，纯展示用
	acted      string       // 最近一次已经处理过的网络，用来判断"换网了没有"
	checkedAt  time.Time
	lastSwitch *SwitchRecord
}

// Monitor 是本进程唯一的 Wi-Fi 监视器
var Monitor = &Watcher{}

// Status 汇总当前 Wi-Fi 与最近一次切换，供接口输出
func (w *Watcher) Status() map[string]interface{} {
	w.mu.Lock()
	defer w.mu.Unlock()

	errText := ""
	if w.current.Err != nil {
		errText = w.current.Err.Error()
	}
	m := map[string]interface{}{
		"watch_interval_seconds": int(w.interval.Seconds()),
		"current_ssid":           w.current.SSID,
		"current_network_id":     w.current.NetworkID,
		"current_label":          w.current.label(),
		"ssid_source":            w.current.Source,
		"ssid_error":             errText,
		"last_switch":            w.lastSwitch,
		"checked_at":             nil,
		// 已经检测到换网、但后台轮询还没来得及处理
		"pending_switch": w.interval > 0 && !w.current.empty() && w.current.key() != w.acted,
	}
	if !w.checkedAt.IsZero() {
		m["checked_at"] = w.checkedAt
	}
	return m
}

// MatchedSSID 返回当前 Wi-Fi 命中的是哪一档（可能是兜底的默认档），没有则空串
func (w *Watcher) MatchedSSID() string {
	id := w.identity()
	if id.empty() {
		return ""
	}
	if p, ok := Profiles.match(id); ok {
		return p.SSID
	}
	return ""
}

func (w *Watcher) record(id wifiIdentity) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.current, w.checkedAt = id, time.Now()
}

func (w *Watcher) recordSwitch(r SwitchRecord) {
	w.mu.Lock()
	defer w.mu.Unlock()
	r.At = time.Now()
	w.lastSwitch = &r
}

func (w *Watcher) identity() wifiIdentity {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.current
}

// actedKey 是"最近一次已经处理过的网络"。它必须和展示用的 current 分开：
// 界面每 10 秒拉一次 /api/net/wifi 也会刷新 current，如果拿 current 判断
// "换网了没有"，界面轮询就会把换网这件事先吃掉，后台轮询再看时已经"没变化"了，
// 于是永远不触发切换。
func (w *Watcher) actedKey() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.acted
}

func (w *Watcher) markActed(key string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.acted = key
}

// CheckMode 决定一次探测要不要跟着下发配置
type CheckMode int

const (
	CheckObserve CheckMode = iota // 只刷新展示状态（界面拉取时用）
	CheckSeed                     // 启动时的第一次探测：记下当前网络但不下发
	CheckSwitch                   // 后台轮询：换网了就套用配置档
)

// StartWatcher 定期查看当前 SSID，换网时自动套用对应配置档。
// interval 为 0 表示只做一次探测、不自动切换。
func StartWatcher(interval time.Duration) {
	Monitor.mu.Lock()
	Monitor.interval = interval
	Monitor.mu.Unlock()

	// 启动时先探一次：界面上立刻能看到当前 Wi-Fi，同时把它记成"已处理"，
	// 免得程序一起来就把网卡配置改掉（要下发可以在界面点「立即应用」）
	go CheckWiFi(CheckSeed)

	if interval <= 0 {
		log.Printf("[WiFi] 按 SSID 自动切换网卡配置: 已关闭")
		return
	}
	log.Printf("[WiFi] 按 SSID 自动切换网卡配置: 每 %s 检查一次", interval)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			CheckWiFi(CheckSwitch)
		}
	}()
}

// CheckWiFi 读取当前 Wi-Fi，并按 mode 决定要不要跟着切换配置。
func CheckWiFi(mode CheckMode) {
	checkWiFiWith(currentWiFi(), mode)
}

// checkWiFiWith 是 CheckWiFi 去掉"读系统"那步的版本，便于测试
func checkWiFiWith(id wifiIdentity, mode CheckMode) {
	Monitor.record(id)

	switch mode {
	case CheckObserve:
		return
	case CheckSeed:
		Monitor.markActed(id.key())
		return
	}

	prev := Monitor.actedKey()
	if id.empty() || id.key() == prev {
		return
	}
	log.Printf("[WiFi] 当前 Wi-Fi: %s（上一次: %s）", id.label(), netutil.OrDash(prev))

	p, ok := Profiles.match(id)
	if !ok {
		Monitor.recordSwitch(SwitchRecord{SSID: id.label(), Detail: "没有匹配的配置档，未做改动", OK: true})
		Monitor.markActed(id.key())
		return
	}
	if err := applyProfile(p, false); err != nil {
		// 下发失败就不记成已处理，下一轮再试一次（网卡刚连上时偶尔会失败）
		return
	}
	Monitor.markActed(id.key())
}

// ApplyProfileForSSID 按名字找到配置档并下发，供界面「立即应用」使用
func ApplyProfileForSSID(ssid string, force bool) error {
	p, ok := Profiles.Get(ssid)
	if !ok {
		return fmt.Errorf("Wi-Fi %q 没有对应的配置档", ssid)
	}
	return applyProfile(p, force)
}

// applyProfile 把配置档下发下去。force 为真时即使当前配置已经一致也重新下发
// （界面上手动点「立即应用」的场景）。
func applyProfile(p Profile, force bool) error {
	ssid := p.SSID
	if !p.Enabled && !force {
		Monitor.recordSwitch(SwitchRecord{SSID: ssid, Service: p.Service, OK: true,
			Detail: "配置档已停用，未切换"})
		return nil
	}

	// 已经是目标配置就别重下发了——下发会让网卡断一下
	if !force {
		if cfgs, err := ListNICs(); err == nil {
			for _, c := range cfgs {
				if c.Service == p.Service && sameSettings(c, p.Settings) {
					Monitor.recordSwitch(SwitchRecord{SSID: ssid, Service: p.Service, OK: true,
						Detail: "当前配置已符合配置档，无需切换"})
					log.Printf("[WiFi] %s 的配置已符合配置档，跳过", ssid)
					return nil
				}
			}
		}
	}

	err := Apply(Target{Device: p.Device, Service: p.Service}, p.Settings)
	Profiles.markApplied(ssid, err)
	if err != nil {
		Monitor.recordSwitch(SwitchRecord{SSID: ssid, Service: p.Service, OK: false, Detail: err.Error()})
		log.Printf("[WiFi] 套用 %s 的配置档失败: %v", ssid, err)
		return err
	}
	Monitor.recordSwitch(SwitchRecord{SSID: ssid, Service: p.Service, OK: true,
		Detail: "已套用: " + Describe(p.Settings)})
	log.Printf("[WiFi] 已按配置档切换 %s -> %s (%s)", ssid, p.Service, Describe(p.Settings))

	// 改完网卡配置，网关很可能换了网卡，自定义路由的作用域要跟着对一遍；
	// 等几秒让新配置在系统里落定再查
	go func() {
		time.Sleep(5 * time.Second)
		route.Default.RescopeRoutes()
	}()
	return nil
}
