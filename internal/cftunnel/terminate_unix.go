//go:build !windows

package cftunnel

import (
	"os"
	"syscall"
)

// terminate 请进程自己收摊。cloudflared 收到 SIGTERM 会先把已经建立的连接优雅
// 关掉再退出，直接 Kill 的话正在传的请求会断在半路。
func terminate(p *os.Process) error {
	return p.Signal(syscall.SIGTERM)
}
