package proxy

// 域名解析与目标记录：两个都是挂在 go-socks5 上的钩子。

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/armon/go-socks5"

	"nettool/internal/sockopt"
)

// resolver 让代理自己按指定的上游 DNS 解析域名，而且查询本身也从绑定的
// 出口发出去——这才是关键：客户端用 --socks5-hostname 时域名是交给代理解析的，
// 如果代理还用系统 DNS（在被污染的网络里），拿到的就是假地址，哪怕流量出口在国外
// 也连不上。留空则维持系统解析。
type resolver struct {
	dns string // host:port
	// egress 是所属实例的出口约束。DNS 查询也必须照样施加——漏了的话域名解析会
	// 从默认网关出去，而数据连接走的是指定线路，既泄漏了查询、解析结果也可能不对。
	//
	// macOS 的 PF 模式下这一点尤其容易漏：查询走的是 UDP:53，而 PF 规则是按
	// 源端口段匹配的，UDP socket 不绑段内端口就匹配不上。sockopt.Dialer 会按
	// network 给出正确类型的 LocalAddr，renderPFRules 也为 UDP 单独写了一条规则。
	egress sockopt.Egress
}

func (r *resolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	res := net.DefaultResolver
	if r.dns != "" {
		d, err := sockopt.NewDialer(r.egress, net.Dialer{Timeout: 5 * time.Second})
		if err != nil {
			return ctx, nil, fmt.Errorf("解析 %s 失败: 出口配置不可用: %v", name, err)
		}
		res = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, r.dns)
			},
		}
	}

	ips, err := res.LookupIP(ctx, "ip4", name)
	if err != nil || len(ips) == 0 {
		// 没有 A 记录时再试 IPv6，别把只有 AAAA 的域名判死
		ips6, err6 := res.LookupIP(ctx, "ip", name)
		if err6 != nil || len(ips6) == 0 {
			if err == nil {
				err = err6
			}
			return ctx, nil, fmt.Errorf("解析 %s 失败: %v", name, err)
		}
		return ctx, ips6[0], nil
	}
	return ctx, ips[0], nil
}

// NormalizeDNSAddr 允许只填 IP，自动补 :53
func NormalizeDNSAddr(dns string) (string, error) {
	dns = strings.TrimSpace(dns)
	if dns == "" {
		return "", nil
	}
	if _, _, err := net.SplitHostPort(dns); err == nil {
		return dns, nil
	}
	if net.ParseIP(dns) == nil {
		return "", fmt.Errorf("代理 DNS %q 不是合法的 IP 或 IP:端口", dns)
	}
	return net.JoinHostPort(dns, "53"), nil
}

// targetRecorder 借 RuleSet 这个钩子把"这条连接要去哪儿"记下来。
// go-socks5 不会把请求目标透给 listener，只有这里能同时拿到客户端地址和目标地址。
type targetRecorder struct {
	inner socks5.RuleSet
	stats *StatsManager // 所属实例的统计口径，不能写到别的实例的连接上
}

func (t *targetRecorder) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	if req != nil && req.RemoteAddr != nil && req.DestAddr != nil {
		t.stats.SetTarget(req.RemoteAddr.Address(), describeTarget(req.DestAddr))
	}
	return t.inner.Allow(ctx, req)
}

// describeTarget 优先显示客户端请求的那个域名（--socks5-hostname 的情况），
// 并带上实际解析到的 IP；客户端直接给 IP 时就只有 IP。
func describeTarget(dest *socks5.AddrSpec) string {
	if dest.FQDN == "" {
		return dest.Address()
	}
	hostPort := net.JoinHostPort(dest.FQDN, strconv.Itoa(dest.Port))
	if len(dest.IP) > 0 {
		return hostPort + " (" + dest.IP.String() + ")"
	}
	return hostPort
}
