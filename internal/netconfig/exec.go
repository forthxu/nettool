package netconfig

// 本包所有的外部命令都从这里走，为的只有一件事：**加超时**。
//
// 按 SSID 自动切换是靠一个后台 goroutine 定时轮询的（见 watcher.go），它是串行的：
// 一次检查卡住，后面的检查就再也不会发生，表现出来正是"自动切换只生效了一次，
// 之后再也不动"。而这里调用的命令全都可能卡住——networksetup 在网卡状态变化
// 期间、nmcli 在 NetworkManager 忙的时候、ubus 在 OpenWrt 上等 netifd，都遇得到。
// 宁可这一轮报错、下一轮重来，也不能把整个监视器闷死。

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// cmdTimeout 是单条命令的上限。这些命令正常都是百毫秒级返回，给到 20 秒是为了
// 容忍 networksetup 下发时网卡重协商那几秒，再久就一定是卡住了。
const cmdTimeout = 20 * time.Second

// runCombined 执行命令并返回合并后的输出（stdout+stderr），失败时输出也一并带回，
// 因为系统工具常常把真正的原因打在 stderr 上。
func runCombined(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if ctx.Err() != nil {
		return text, fmt.Errorf("%s 执行超过 %s 未返回，已放弃", name, cmdTimeout)
	}
	if err != nil {
		if text == "" {
			text = err.Error()
		}
		return text, fmt.Errorf("%s", text)
	}
	return text, nil
}

// runOut 只取标准输出。解析 JSON 之类的场景要用它，免得警告信息混进去。
func runOut(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return "", fmt.Errorf("%s 执行超过 %s 未返回，已放弃", name, cmdTimeout)
	}
	if err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return stdout.String(), fmt.Errorf("%s", detail)
	}
	return stdout.String(), nil
}

// runStdin 执行命令并往它的标准输入喂一段文本（scutil 就是这么用的）
func runStdin(input, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	if ctx.Err() != nil {
		return "", fmt.Errorf("%s 执行超过 %s 未返回，已放弃", name, cmdTimeout)
	}
	return stdout.String(), err
}
