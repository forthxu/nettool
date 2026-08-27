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
)

// resolver 让代理自己按指定的上游 DNS 解析域名，而且查询本身也从绑定的
// 出口 IP 发出去——这才是关键：客户端用 --socks5-hostname 时域名是交给代理解析的，
// 如果代理还用系统 DNS（在被污染的网络里），拿到的就是假地址，哪怕流量出口在国外
// 也连不上。留空则维持系统解析。
type resolver struct {
	dns        string // host:port
	outboundIP net.IP
}

func (r *resolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	res := net.DefaultResolver
	if r.dns != "" {
		res = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: dnsLocalAddr(network, r.outboundIP)}
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

// dnsLocalAddr 把 DNS 查询也绑到出口 IP 上，UDP 和 TCP 要用各自的地址类型
func dnsLocalAddr(network string, ip net.IP) net.Addr {
	if ip == nil {
		return nil
	}
	if strings.HasPrefix(network, "udp") {
		return &net.UDPAddr{IP: ip}
	}
	return &net.TCPAddr{IP: ip}
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
}

func (t *targetRecorder) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	if req != nil && req.RemoteAddr != nil && req.DestAddr != nil {
		Stats.SetTarget(req.RemoteAddr.Address(), describeTarget(req.DestAddr))
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
