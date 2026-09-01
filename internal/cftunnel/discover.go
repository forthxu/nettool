package cftunnel

// 扫出本机已经在用的隧道，让「我早就配好了」的人一键接管、把规则搬到云端。
//
// 线索有两条，分别对应 cloudflared 留下的两种文件：
//
//	~/.cloudflared/<UUID>.json   `cloudflared tunnel create` 生成的凭证，一个文件一条隧道
//	某处的 config.yml            用户自己写的，里面有 credentials-file 指回上面那个
//
// 从凭证出发能找全隧道，但找不到规则；从 config 出发能拿到规则，可它爱放哪放哪
// （见过 /opt/... 这种）。所以两边都扫，再按 credentials-file 配对，
// 配不上的在界面上留一个手填路径的口子。

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Candidate 是一条「可以导入」的隧道
type Candidate struct {
	TunnelID        string `json:"tunnel_id"`
	Name            string `json:"name"`
	CredentialsPath string `json:"credentials_path"`
	ConfigPath      string `json:"config_path,omitempty"`
	IngressCount    int    `json:"ingress_count"`
	Hostnames       string `json:"hostnames,omitempty"` // 逗号分隔，给界面一眼看出是哪条
	// Adopted 表示本工具已经接管过它了，界面上按钮要变灰
	Adopted bool `json:"adopted"`
	// Problem 非空表示这条导不进来（凭证读不动、FedRAMP 环境等）
	Problem string `json:"problem,omitempty"`
}

// configSearchDirs 是找 config.yml 的地方。
//
// 前两个是 cloudflared 自己的默认位置，后面几个是把它当服务跑时的常见去处。
// 用户自定义的目录扫不到，界面上因此保留了手填路径。
func configSearchDirs() []string {
	dirs := []string{}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".cloudflared"))
	}
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			dirs = append(dirs, filepath.Join(pd, "cloudflared"))
		}
		return dirs
	}
	return append(dirs, "/etc/cloudflared", "/usr/local/etc/cloudflared", "/opt/cloudflared")
}

// credentialsDirs 是找凭证文件的地方，比 config 少：cloudflared 只往这两处写
func credentialsDirs() []string {
	dirs := []string{}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".cloudflared"))
	}
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			dirs = append(dirs, filepath.Join(pd, "cloudflared"))
		}
		return dirs
	}
	return append(dirs, "/etc/cloudflared")
}

// configExts 是可能的配置文件后缀。用户的那份叫 .config，不是标准写法，
// 但既然见过就认下来。
var configExts = map[string]bool{".yml": true, ".yaml": true, ".config": true, ".conf": true}

// scannedConfig 是扫到的一份配置文件
type scannedConfig struct {
	path string
	cfg  cfdConfig
}

// scanConfigs 把各目录里能解析的配置文件都读出来。
// extraDirs 让调用方补上非标准位置（比如用户手填的那个目录）。
func scanConfigs(extraDirs []string) []scannedConfig {
	var out []scannedConfig
	seen := map[string]bool{}

	for _, dir := range append(configSearchDirs(), extraDirs...) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !configExts[strings.ToLower(filepath.Ext(e.Name()))] {
				continue
			}
			path := filepath.Join(dir, e.Name())
			if seen[path] {
				continue
			}
			seen[path] = true

			cfg, err := readCFDConfig(path)
			// 没有 tunnel 也没有 ingress 的多半不是隧道配置（cloudflared 的
			// 全局 config.yml 也可能只有 loglevel 之类），跳过
			if err != nil || (cfg.Tunnel == "" && len(cfg.Ingress) == 0) {
				continue
			}
			out = append(out, scannedConfig{path: path, cfg: cfg})
		}
	}
	return out
}

// Discover 扫出本机可以导入的隧道。extraDirs 是额外要看的目录，凭证和 config
// 都在里面找——用户把两样东西放在一起是常态。
//
// 不联网、只读文件，所以随时可以点。
func (m *Manager) Discover(extraDirs []string) []Candidate {
	configs := scanConfigs(extraDirs)

	m.mu.Lock()
	adopted := make(map[string]bool, len(m.tunnels))
	for _, t := range m.tunnels {
		adopted[t.CFID] = true
	}
	m.mu.Unlock()

	var out []Candidate
	seen := map[string]bool{}

	for _, dir := range append(credentialsDirs(), extraDirs...) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || strings.ToLower(filepath.Ext(e.Name())) != ".json" {
				continue
			}
			path := filepath.Join(dir, e.Name())
			if seen[path] {
				continue
			}
			seen[path] = true

			c := Candidate{CredentialsPath: path}
			cred, err := readCredentialsFile(path)
			if err != nil {
				// 同目录下可能有别的 json（cert.pem 旁边偶尔有杂物），
				// 读不出隧道字段的直接跳过，不当成"有问题的候选"去烦用户
				continue
			}
			c.TunnelID = cred.TunnelID
			c.Adopted = adopted[cred.TunnelID]
			if _, err := tokenFromCredentials(cred); err != nil {
				c.Problem = err.Error()
			}

			// 配对：找 credentials-file 指向这个文件、或 tunnel 就是这个 UUID 的配置
			if sc, ok := matchConfig(configs, path, cred.TunnelID); ok {
				c.ConfigPath = sc.path
				c.IngressCount = len(sc.cfg.Ingress)
				c.Hostnames = joinHostnames(sc.cfg.Ingress)
				if looksLikeTunnelName(sc.cfg.Tunnel) {
					c.Name = sc.cfg.Tunnel
				}
			}
			if c.Name == "" {
				c.Name = cred.TunnelID
			}
			out = append(out, c)
		}
	}
	return dedupeCandidates(out)
}

// dedupeCandidates 把同一条隧道的多份凭证收成一条。
//
// 同一个 UUID 的凭证文件出现在两个目录里是常事（拷过一份到服务目录），但界面上
// 列成两行、其中一行还没配上 config，点错了规则就迁不过来。留配着 config 的那份。
func dedupeCandidates(in []Candidate) []Candidate {
	out := make([]Candidate, 0, len(in))
	at := make(map[string]int, len(in))
	for _, c := range in {
		i, seen := at[c.TunnelID]
		if !seen {
			at[c.TunnelID] = len(out)
			out = append(out, c)
			continue
		}
		if out[i].ConfigPath == "" && c.ConfigPath != "" {
			out[i] = c
		}
	}
	return out
}

// matchConfig 找出属于某条隧道的配置文件
func matchConfig(configs []scannedConfig, credPath, tunnelID string) (scannedConfig, bool) {
	for _, sc := range configs {
		if sc.cfg.CredentialsFile != "" && sameFile(sc.cfg.CredentialsFile, credPath) {
			return sc, true
		}
	}
	// 没写 credentials-file 的配置（靠 cloudflared 自己按 UUID 找）退一步按隧道 ID 配
	for _, sc := range configs {
		if sc.cfg.Tunnel == tunnelID {
			return sc, true
		}
	}
	return scannedConfig{}, false
}

// sameFile 判断两个路径是不是同一个文件。先比 inode（软链、/var 与
// /private/var 这类等价路径都能对上），比不了再退回字符串。
func sameFile(a, b string) bool {
	if a == b {
		return true
	}
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(fa, fb)
}

func joinHostnames(rules []IngressRule) string {
	var names []string
	for _, r := range rules {
		if r.Hostname != "" {
			names = append(names, r.Hostname)
		}
	}
	return strings.Join(names, ", ")
}
