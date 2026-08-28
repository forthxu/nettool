package sockopt

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestEgressValidate(t *testing.T) {
	cases := []struct {
		name string
		e    Egress
		ok   bool
	}{
		{"零值", Egress{}, true},
		{"只打 mark（Linux fwmark 模式）", Egress{Options: Options{Mark: 0x40000000}}, true},
		{"绑网卡+源地址（按网卡模式）", Egress{Options: Options{IfIndex: 3}, SourceIP: "192.168.1.5"}, true},
		{"完整的 PF 模式", Egress{Options: Options{IfIndex: 3}, SourceIP: "192.168.1.5", PortStart: 20000, PortEnd: 20255}, true},
		// 下面这条是 macOS 路径上最危险的配置错误：PF 规则按"源 IP + 源端口段"
		// 一起匹配，只绑端口不绑地址的包匹配不上，会静默从默认网关出去
		{"有端口段没源地址", Egress{PortStart: 20000, PortEnd: 20255}, false},
		{"端口段反了", Egress{SourceIP: "192.168.1.5", PortStart: 20255, PortEnd: 20000}, false},
		{"端口段落进特权端口", Egress{SourceIP: "192.168.1.5", PortStart: 80, PortEnd: 443}, false},
		{"端口越界", Egress{SourceIP: "192.168.1.5", PortStart: 65000, PortEnd: 70000}, false},
		{"源地址不是 IP", Egress{SourceIP: "eth0"}, false},
	}
	for _, c := range cases {
		err := c.e.Validate()
		if (err == nil) != c.ok {
			t.Errorf("%s: Validate() = %v, 期望 ok=%v", c.name, err, c.ok)
		}
	}
}

func TestEgressEmpty(t *testing.T) {
	if !(Egress{}).Empty() {
		t.Error("零值应当是空的")
	}
	// 只限定源端口段也算「有出口约束」——macOS 的 PF 模式就靠它区分实例
	if (Egress{SourceIP: "192.168.1.5", PortStart: 20000, PortEnd: 20255}).Empty() {
		t.Error("限定了源端口段就不是空的")
	}
	if (Egress{Options: Options{Mark: 1}}).Empty() {
		t.Error("打了 mark 就不是空的")
	}
}

// TestDialerBindsPortInRange 验证拨号真的把源端口绑进了指定段里。
// 这是 macOS 那条路径的根基：PF 规则按源端口段匹配，端口没落进段里，
// 规则就匹配不上，流量会静默从默认网关出去。
func TestDialerBindsPortInRange(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起测试监听失败: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	const start, end = 24000, 24007
	d, err := NewDialer(Egress{SourceIP: "127.0.0.1", PortStart: start, PortEnd: end},
		net.Dialer{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("构造拨号器失败: %v", err)
	}

	ctx := context.Background()
	seen := make(map[int]bool)
	for i := 0; i < 4; i++ {
		conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("第 %d 次拨号失败: %v", i+1, err)
		}
		port := conn.LocalAddr().(*net.TCPAddr).Port
		conn.Close()
		if port < start || port > end {
			t.Fatalf("源端口 %d 落在段 %d-%d 之外", port, start, end)
		}
		seen[port] = true
	}
	// 轮转而不是每次都用同一个口：固定一个口的话，一条连接还在 TIME_WAIT
	// 里就会把后续拨号全挡住
	if len(seen) < 2 {
		t.Errorf("连续拨号应当在段内轮转端口，实际只用到 %d 个", len(seen))
	}
}

// TestDialerRetriesWhenPortTaken：段内某个端口被占着时要换下一个，而不是失败。
// 这里把段缩到 2 个口并先占掉一个，逼出重试路径。
func TestDialerRetriesWhenPortTaken(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起测试监听失败: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	const start, end = 24100, 24101
	// 占住段里的第一个口
	blocker, err := net.Listen("tcp", "127.0.0.1:24100")
	if err != nil {
		t.Skipf("端口 24100 已被别的进程占用，跳过: %v", err)
	}
	defer blocker.Close()

	d, err := NewDialer(Egress{SourceIP: "127.0.0.1", PortStart: start, PortEnd: end},
		net.Dialer{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("构造拨号器失败: %v", err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("段内还有空闲端口时不该失败: %v", err)
	}
	defer conn.Close()
	if port := conn.LocalAddr().(*net.TCPAddr).Port; port != 24101 {
		t.Errorf("应当换到段内空闲的 24101，实际用了 %d", port)
	}
}

// TestDialerWithoutPortRangeIsPlain 没有端口段时行为要和裸 net.Dialer 一致：
// 不绑端口，由内核分配临时端口。绝大多数用户（Linux fwmark、不绑出口）走的
// 都是这条路径，不能让它有任何额外行为。
func TestDialerWithoutPortRangeIsPlain(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起测试监听失败: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()

	d, err := NewDialer(Egress{}, net.Dialer{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("零值出口应当能构造拨号器: %v", err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	defer conn.Close()
	if port := conn.LocalAddr().(*net.TCPAddr).Port; port >= 20000 && port < 36384 {
		t.Logf("源端口 %d 恰好落在 PF 端口段范围内（内核临时分配，属正常）", port)
	}
}

// TestLocalAddrMatchesNetwork：UDP 用错地址类型 net.Dialer 会直接报
// mismatched local address type。代理自己的 DNS 查询正是 UDP，漏了就全查不动。
func TestLocalAddrMatchesNetwork(t *testing.T) {
	ip := net.ParseIP("192.168.1.5")
	if a, ok := localAddr("udp4", ip, 20000).(*net.UDPAddr); !ok || a.Port != 20000 || !a.IP.Equal(ip) {
		t.Errorf("udp 应返回带端口的 *net.UDPAddr，得到 %#v", localAddr("udp4", ip, 20000))
	}
	if a, ok := localAddr("tcp4", ip, 20000).(*net.TCPAddr); !ok || a.Port != 20000 || !a.IP.Equal(ip) {
		t.Errorf("tcp 应返回带端口的 *net.TCPAddr，得到 %#v", localAddr("tcp4", ip, 20000))
	}
	if localAddr("tcp4", nil, 0) != nil {
		t.Error("既没源地址也没端口时不该指定 LocalAddr")
	}
}

func TestEgressString(t *testing.T) {
	cases := []struct {
		e    Egress
		want string
	}{
		{Egress{}, "默认线路"},
		{Egress{Options: Options{Mark: 0x41000000}}, "mark=0x41000000"},
		{Egress{Options: Options{IfIndex: 5}, SourceIP: "192.168.1.5", PortStart: 20000, PortEnd: 20255},
			"ifindex=5 src=192.168.1.5 sport=20000-20255"},
	}
	for _, c := range cases {
		if got := c.e.String(); got != c.want {
			t.Errorf("String() = %q, 期望 %q", got, c.want)
		}
	}
}
