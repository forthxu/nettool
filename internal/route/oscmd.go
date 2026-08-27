package route

// 与操作系统打交道的部分：拼路由命令、执行、判断错误类型。
// 命令拼装单独拆成纯函数，因为真正执行需要 root，只有这样才能被测试覆盖。

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strings"

	"nettool/internal/netiface"
)

// linuxRouteProto 是自定义路由协议号，用于标记"本程序下发"，
// 台账丢了也能用 ip route show proto 210 认出来
const linuxRouteProto = "210"

// execOSRoute 下发/删除内核路由。dest 必须是 normalizeDestination 归一化后的
// CIDR：域名解析出来的是 /32 主机路由，各平台的写法与网段路由并不相同。
func execOSRoute(action, dest, gateway, iface string) error {
	// 老台账里的记录没有作用域网卡，删除/重下时补一次，保证与添加时用的一致
	if iface == "" {
		iface = scopeInterface(gateway)
	}

	cmd, err := buildRouteCmd(runtime.GOOS, action, dest, gateway, iface)
	if err != nil {
		return err
	}

	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}

	// busybox 等精简版 ip 命令可能不认 proto 参数，去掉标记重试一次
	if runtime.GOOS == "linux" && action == "add" && strings.Contains(strings.ToLower(string(output)), "proto") {
		log.Printf("[Router] ip 不支持 proto 标记，去掉后重试: %s", strings.TrimSpace(string(output)))
		args := cmd.Args[1 : len(cmd.Args)-2] // 去掉末尾的 proto <N>
		retry := exec.Command("ip", args...)
		if retryOut, retryErr := retry.CombinedOutput(); retryErr == nil {
			return nil
		} else {
			output, err = retryOut, retryErr
		}
	}

	return fmt.Errorf("%s (output: %s)", err, string(output))
}

// buildRouteCmd 组装各平台的路由命令
func buildRouteCmd(osName, action, dest, gateway, iface string) (*exec.Cmd, error) {
	ip, ipNet, err := net.ParseCIDR(dest)
	if err != nil {
		return nil, fmt.Errorf("非法的路由目标 %q: %v", dest, err)
	}
	ones, _ := ipNet.Mask.Size()
	isHost := ones == 32

	var cmd *exec.Cmd
	switch osName {
	case "linux":
		// ip route 本身就接受 CIDR，主机路由写成 x.x.x.x/32 即可
		verb := "add"
		if action != "add" {
			verb = "del"
		}
		args := []string{"route", verb, dest, "via", gateway}
		if verb == "add" {
			if iface != "" {
				args = append(args, "dev", iface)
			}
			// 打上标记，日后 ip route show proto 210 就能认出是本程序加的
			args = append(args, "proto", linuxRouteProto)
		}
		cmd = exec.Command("ip", args...)
	case "darwin":
		verb := "add"
		if action != "add" {
			verb = "delete"
		}
		args := []string{"-n", verb}
		if isHost {
			args = append(args, "-host", ip.String(), gateway)
		} else {
			args = append(args, "-net", dest, gateway)
		}
		// 不加 -ifscope 的话，这条全局路由会被 en0 作用域里从默认路由克隆出来的
		// 表项（WASCLONED）压掉：路由表里看得见，实际流量却还是走默认网关。
		if iface != "" {
			args = append(args, "-ifscope", iface)
		}
		cmd = exec.Command("route", args...)
	case "windows":
		mask := net.IP(ipNet.Mask).String()
		if action == "add" {
			cmd = exec.Command("route", "ADD", ipNet.IP.String(), "MASK", mask, gateway)
		} else {
			cmd = exec.Command("route", "DELETE", ipNet.IP.String(), "MASK", mask, gateway)
		}
	default:
		return nil, fmt.Errorf("unsupported operating system: %s", osName)
	}

	return cmd, nil
}

// isRouteMissingError 判断"内核里本来就没有这条路由"这类错误。
// macOS: not in table；Linux: RTNETLINK answers: No such process。
func isRouteMissingError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not in table") || strings.Contains(msg, "no such process") ||
		strings.Contains(msg, "element not found")
}

// isRouteExistsError 判断"这条路由内核里已经有了"这类错误。
// macOS/Linux 都是 File exists，Windows 是 The object already exists。
func isRouteExistsError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "file exists") || strings.Contains(msg, "already exists")
}

// scopeInterface 判断网关应当归属哪块网卡。
//
// macOS 只有把路由加进网卡作用域（-ifscope）才不会被默认路由克隆出来的表项压掉，
// 所以必须先确定网卡。同一网段可能同时存在于多块网卡上（例如 en0 和 en7 都是
// 192.168.10.0/24），此时优先选"系统配置里上游路由器正好就是该网关"的那块。
// 其他系统不需要作用域，返回空串。
func scopeInterface(gateway string) string {
	if runtime.GOOS != "darwin" {
		return ""
	}

	gw := net.ParseIP(gateway)
	if gw == nil {
		return ""
	}

	var fallback string
	for _, iface := range netiface.List() {
		if iface.Loopback {
			continue
		}
		// 系统就是把这个网关配给这块网卡的，最可靠
		if iface.Gateway == gateway {
			return iface.Name
		}
		if fallback != "" {
			continue
		}
		if _, ipNet, err := net.ParseCIDR(iface.CIDR); err == nil && ipNet.Contains(gw) {
			fallback = iface.Name // 网段能覆盖该网关，作为备选
		}
	}
	return fallback
}

// SystemRoutes 原样返回系统路由表，供界面上"看一眼当前路由"用
func SystemRoutes() []string {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("ip", "route", "show")
	case "darwin":
		cmd = exec.Command("netstat", "-nr")
	case "windows":
		cmd = exec.Command("route", "print")
	default:
		return []string{"Unsupported OS for system routes"}
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return []string{fmt.Sprintf("Failed to get system routes: %v", err)}
	}

	var result []string
	for _, line := range strings.Split(string(output), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
