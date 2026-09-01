package cftunnel

// cloudflared 二进制的探测与一键安装。
//
// 本工具自己是单二进制、无外部依赖的，但 Cloudflare 的连接器协议没有公开实现，
// 只能调官方的 cloudflared。所以这里做两件事：把它找出来（PATH / 托管目录 /
// 用户指定的路径），找不到就从 GitHub Releases 拉一份放到状态目录旁边。

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// defaultDownloadBase 是官方发布地址。latest 是一个会 302 到具体版本的固定入口，
// 所以不用先查一次「最新版本号是多少」。
const defaultDownloadBase = "https://github.com/cloudflare/cloudflared/releases/latest/download/"

// assetName 给出本平台该下载哪个文件，以及它是不是 tar.gz。
//
// Cloudflare 对各平台的打包方式不一致：Linux 与 Windows 直接放裸二进制，
// macOS 只提供 .tgz。第二个返回值就是这个区别。
func assetName(goos, goarch string) (name string, targz bool, err error) {
	switch goos {
	case "linux":
		switch goarch {
		case "amd64", "arm64", "386", "arm":
			return "cloudflared-linux-" + goarch, false, nil
		}
	case "darwin":
		switch goarch {
		case "amd64", "arm64":
			return "cloudflared-darwin-" + goarch + ".tgz", true, nil
		}
	case "windows":
		switch goarch {
		case "amd64", "386":
			return "cloudflared-windows-" + goarch + ".exe", false, nil
		}
	}
	return "", false, fmt.Errorf("Cloudflare 没有为 %s/%s 提供 cloudflared，请自行编译后在上面填绝对路径", goos, goarch)
}

// downloadURL 拼出下载地址。base 允许换成镜像，但一定要以 / 结尾——
// 用户填 https://mirror/dir 时最后一段会被当成文件名替换掉。
func downloadURL(base, goos, goarch string) (string, bool, error) {
	name, targz, err := assetName(goos, goarch)
	if err != nil {
		return "", false, err
	}
	if base == "" {
		base = defaultDownloadBase
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return base + name, targz, nil
}

// managedPath 是一键安装装到哪儿：配置文件旁边的 bin/ 目录。
// 没有持久化目录时返回空，此时只能用 PATH 里现成的。
func (m *Manager) managedPath() string {
	m.mu.Lock()
	path := m.path
	m.mu.Unlock()
	if path == "" {
		return ""
	}
	name := "cloudflared"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(filepath.Dir(path), "bin", name)
}

// BinaryStatus 是「本机有没有 cloudflared」的完整回答
type BinaryStatus struct {
	Path    string `json:"path"`              // 实际会用哪个，空表示没找到
	Source  string `json:"source"`            // configured | managed | path
	Version string `json:"version,omitempty"` // cloudflared --version 的第一行
	Error   string `json:"error,omitempty"`
	Managed string `json:"managed_path,omitempty"` // 一键安装会装到哪儿
	Found   bool   `json:"found"`
}

// versionCache 缓存 --version 的结果。界面会不停轮询状态，每次都 fork 一个进程
// 太浪费；用「路径 + 大小 + 修改时间」当键，换了文件自然就失效。
var versionCache sync.Map

func binaryVersion(path string) (string, error) {
	key := path
	if fi, err := os.Stat(path); err == nil {
		key = fmt.Sprintf("%s|%d|%d", path, fi.Size(), fi.ModTime().UnixNano())
	}
	if v, ok := versionCache.Load(key); ok {
		return v.(string), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s --version 跑不起来: %v", path, err)
	}
	v := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	versionCache.Store(key, v)
	return v, nil
}

// BinaryStatus 按「用户指定 > 托管目录 > PATH」的顺序找 cloudflared
func (m *Manager) BinaryStatus() BinaryStatus {
	m.mu.Lock()
	configured := m.settings.BinaryPath
	m.mu.Unlock()

	st := BinaryStatus{Managed: m.managedPath()}

	switch {
	case configured != "":
		st.Path, st.Source = configured, "configured"
		if _, err := os.Stat(configured); err != nil {
			st.Error = fmt.Sprintf("指定的路径不可用: %v", err)
			return st
		}
	case st.Managed != "" && fileExists(st.Managed):
		st.Path, st.Source = st.Managed, "managed"
	default:
		p, err := exec.LookPath("cloudflared")
		if err != nil {
			st.Source = "path"
			st.Error = "PATH 里没有 cloudflared，可以点「下载安装」或在上面填绝对路径"
			return st
		}
		st.Path, st.Source = p, "path"
	}

	v, err := binaryVersion(st.Path)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	st.Version, st.Found = v, true
	return st
}

// binaryPath 是启动进程时用的那个路径，找不到就报错
func (m *Manager) binaryPath() (string, error) {
	st := m.BinaryStatus()
	if !st.Found {
		if st.Error != "" {
			return "", fmt.Errorf("%s", st.Error)
		}
		return "", fmt.Errorf("本机没有可用的 cloudflared")
	}
	return st.Path, nil
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

// InstallState 是一键安装的进度。界面轮询它。
type InstallState struct {
	Running    bool   `json:"running"`
	URL        string `json:"url,omitempty"`
	Downloaded int64  `json:"downloaded"`
	Total      int64  `json:"total"` // 0 表示服务端没给 Content-Length
	Error      string `json:"error,omitempty"`
	// Note 是装完之后要提醒的话（目前只有"新版本要重启连接器才生效"）
	Note string `json:"note,omitempty"`
	Done bool   `json:"done"`
	// 同 Status.StartedAt：零值时间配 omitempty 不生效，要指针
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

type installer struct {
	mu    sync.Mutex
	state InstallState
}

func (i *installer) snapshot() InstallState {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.state
}

func (i *installer) progress(n int64) {
	i.mu.Lock()
	i.state.Downloaded += n
	i.mu.Unlock()
}

func (i *installer) setTotal(n int64) {
	i.mu.Lock()
	i.state.Total = n
	i.mu.Unlock()
}

func (i *installer) finish(err error, note string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	now := time.Now()
	i.state.Running = false
	i.state.Done = err == nil
	i.state.FinishedAt = &now
	if err != nil {
		i.state.Error = err.Error()
		return
	}
	i.state.Note = note
}

// InstallBinary 在后台下载 cloudflared。立刻返回，进度看 InstallState。
func (m *Manager) InstallBinary() error {
	dest := m.managedPath()
	if dest == "" {
		return fmt.Errorf("没有可写的状态目录，无法一键安装；请手动装好 cloudflared 后在上面填绝对路径")
	}

	m.mu.Lock()
	base := m.settings.DownloadURL
	m.mu.Unlock()
	url, targz, err := downloadURL(base, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}

	m.install.mu.Lock()
	if m.install.state.Running {
		m.install.mu.Unlock()
		return fmt.Errorf("正在下载中，请稍候")
	}
	m.install.state = InstallState{Running: true, URL: url}
	m.install.mu.Unlock()

	go func() {
		// 装到托管目录后 BinaryStatus 自然就找到它了，不用改配置
		err := downloadBinary(url, dest, targz, m.install.progress, m.install.setTotal)
		note := ""
		if err != nil {
			log.Printf("[CFTunnel] 下载 cloudflared 失败: %v", err)
		} else {
			log.Printf("[CFTunnel] 已安装 cloudflared 到 %s", dest)
			// 已经在跑的连接器用的还是旧的那份程序（Windows 上换掉的是文件名，
			// Unix 上换掉的是目录项，两边正在跑的进程都不受影响），得说一声
			if n := m.runningOnManaged(); n > 0 {
				note = fmt.Sprintf("新版本已装好，但有 %d 个连接器还在用旧版本运行，重启它们才会换过去。", n)
			}
		}
		m.install.finish(err, note)
	}()
	return nil
}

// runningOnManaged 数一数此刻有多少个连接器（含快速隧道）跑的是托管目录里那份
// cloudflared。用户指定了绝对路径时托管目录根本用不上，直接算 0。
func (m *Manager) runningOnManaged() int {
	m.mu.Lock()
	configured := m.settings.BinaryPath
	procs := make([]*process, 0, len(m.procs)+1)
	for _, p := range m.procs {
		procs = append(procs, p)
	}
	if m.quickProc != nil {
		procs = append(procs, m.quickProc)
	}
	m.mu.Unlock()

	if configured != "" {
		return 0
	}
	n := 0
	for _, p := range procs {
		if p.Running() {
			n++
		}
	}
	return n
}

// InstallState 返回一键安装的当前进度
func (m *Manager) InstallState() InstallState { return m.install.snapshot() }

// downloadBinary 下载并落盘：先写临时文件、校验能跑，再原子换上去。
// 中途失败不会留下一个装了一半、点了启动就报错的 cloudflared。
func downloadBinary(url, dest string, targz bool, onProgress, onTotal func(int64)) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("建目录失败: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("下载失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载 %s 返回 HTTP %d", url, resp.StatusCode)
	}
	if onTotal != nil && resp.ContentLength > 0 {
		onTotal(resp.ContentLength)
	}

	tmp, err := os.CreateTemp(filepath.Dir(dest), "cloudflared-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // 成功时已经改名走了，Remove 失败无所谓

	body := io.Reader(&progressReader{r: resp.Body, onRead: onProgress})
	if targz {
		err = extractTarGz(body, tmp)
	} else {
		_, err = io.Copy(tmp, body)
	}
	tmp.Close()
	if err != nil {
		return err
	}

	if err := os.Chmod(tmpName, 0o755); err != nil {
		return err
	}
	// 先确认下下来的东西真的能跑，再换上去：拉到半个文件或一个 HTML 错误页时，
	// 这一步会拦住它，而不是等用户点启动才发现
	if _, err := binaryVersion(tmpName); err != nil {
		return fmt.Errorf("下载到的文件不是可用的 cloudflared: %v", err)
	}
	return replaceBinary(tmpName, dest)
}

// replaceBinary 把新下载的程序换到 dest。
//
// 直接改名在 Unix 上一步到位，覆盖一个正在跑的二进制也没问题——进程握着的是
// inode，改的是目录项。Windows 不行：正在运行的 exe 被系统锁住，覆盖它会得到
// 拒绝访问，于是升级永远要先停隧道。
//
// 但 Windows 允许把锁住的文件本身改名（锁的是文件内容，不是路径）。所以退一步：
// 先把旧的挪到 .old，再把新的放上去。挪走的那份等下次安装时清理——那时它多半
// 已经没人用了，删得掉。
func replaceBinary(tmp, dest string) error {
	if err := os.Rename(tmp, dest); err == nil {
		return nil
	} else if !fileExists(dest) {
		return err // 目标不存在还失败，那就不是被占用，是真出事了
	}

	old := dest + ".old"
	os.Remove(old) // 上一次留下的；删不掉说明还在跑，下面改名会盖掉它
	if err := os.Rename(dest, old); err != nil {
		return fmt.Errorf("无法替换 %s（可能正被运行中的连接器占用，停掉隧道后重试）: %v", dest, err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.Rename(old, dest) // 放回去，别留下一个没有 cloudflared 的托管目录
		return err
	}
	os.Remove(old) // 没在跑的话这里就清掉了，留着也不影响下次
	return nil
}

// extractTarGz 从 macOS 的 .tgz 里取出 cloudflared 那一项
func extractTarGz(r io.Reader, w io.Writer) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("解压失败: %v", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("压缩包里没有找到 cloudflared")
		}
		if err != nil {
			return fmt.Errorf("解包失败: %v", err)
		}
		if h.Typeflag != tar.TypeReg || filepath.Base(h.Name) != "cloudflared" {
			continue
		}
		_, err = io.Copy(w, tr)
		return err
	}
}

// progressReader 边读边报进度
type progressReader struct {
	r      io.Reader
	onRead func(int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 && p.onRead != nil {
		p.onRead(int64(n))
	}
	return n, err
}
