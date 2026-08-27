// Package netutil 收纳几个被多个业务包共用的小工具：域名校验、状态文件的原子写入、
// 以及界面/日志里常用的占位符处理。放这里是为了避免路由、DNS、网卡三个包互相引用。
package netutil

import (
	"os"
	"path/filepath"
	"strings"
)

// IsValidDomain 判断是不是一个能拿去解析的域名（不含协议、端口、路径）
func IsValidDomain(target string) bool {
	if len(target) > 253 || !strings.Contains(target, ".") {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(target, "."), ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			isAlnum := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
			if !isAlnum && r != '-' && r != '_' {
				return false
			}
		}
	}
	return true
}

// EnsureStateDir 确认某个状态文件真的可写：建好目录，再试写一次。
// 不试写的话，"目录能建但文件写不了"要等到第一次保存才暴露。
func EnsureStateDir(path string) error {
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	return f.Close()
}

// WriteFileAtomic 先写临时文件再原子替换，避免掉电/崩溃留下半个文件。
// 路由台账、DNS 配置、Wi-Fi 配置档三处的持久化都走它。
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// OrDash 把空串换成 "-"，日志里好认
func OrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
