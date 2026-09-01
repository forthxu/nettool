package cftunnel

import "os"

// terminate 在 Windows 上只能强杀：这个平台没有信号，os/exec 起来的子进程
// 也收不到 Ctrl+C（那要走控制台事件，且会波及同一控制台里的所有进程）。
func terminate(p *os.Process) error {
	return p.Kill()
}
