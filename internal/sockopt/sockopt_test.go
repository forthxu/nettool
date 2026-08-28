package sockopt

import "testing"

// TestUnicastIfValue 锁死 Windows IP_UNICAST_IF 的网络字节序转换。
// 这个函数只在 Windows 构建里被调用，但放在无 build tag 的文件里就能在
// 开发机上验证——字节序搞错在 Windows 上表现为 connect 时 WSAENOBUFS，
// 现场极难判断，宁可在这里锁住。
func TestUnicastIfValue(t *testing.T) {
	cases := []struct {
		idx  int
		want int
	}{
		{0, 0},
		{1, 0x01000000},
		{7, 0x07000000},
		{12, 0x0c000000},
		{0x0102, 0x02010000},
	}
	for _, c := range cases {
		if got := unicastIfValue(c.idx); got != c.want {
			t.Errorf("unicastIfValue(%d) = 0x%08x, 期望 0x%08x", c.idx, got, c.want)
		}
	}
}

func TestOptionsEmpty(t *testing.T) {
	cases := []struct {
		name string
		o    Options
		want bool
	}{
		{"零值", Options{}, true},
		{"只有 mark", Options{Mark: 0x40000000}, false},
		{"只有网卡名", Options{IfName: "eth0"}, false},
		{"只有网卡索引", Options{IfIndex: 3}, false},
	}
	for _, c := range cases {
		if got := c.o.Empty(); got != c.want {
			t.Errorf("%s: Empty() = %v, 期望 %v", c.name, got, c.want)
		}
	}
}

// TestControlNilWhenEmpty 保证「没绑出口」的拨号路径与不用本包时完全一致：
// Dialer.Control 拿到的是 nil，标准库连回调都不会走。
func TestControlNilWhenEmpty(t *testing.T) {
	if Control(Options{}) != nil {
		t.Fatal("Options 为零值时 Control 应返回 nil")
	}
	if Control(Options{Mark: 1}) == nil {
		t.Fatal("Options 非零时 Control 不应返回 nil")
	}
}

func TestOptionsString(t *testing.T) {
	cases := []struct {
		o    Options
		want string
	}{
		{Options{}, "默认线路"},
		{Options{Mark: 0x41000000}, "mark=0x41000000"},
		{Options{IfName: "eth0"}, "dev=eth0"},
		{Options{IfIndex: 5}, "ifindex=5"},
		{Options{Mark: 0x41000000, IfName: "eth0"}, "mark=0x41000000 dev=eth0"},
	}
	for _, c := range cases {
		if got := c.o.String(); got != c.want {
			t.Errorf("String() = %q, 期望 %q", got, c.want)
		}
	}
}

func TestIsIPv6(t *testing.T) {
	// 标准库传进 Control 的 network 来自 fd.ctrlNetwork()，对 tcp/udp
	// 一定带 4/6 后缀，这里覆盖实际会出现的取值
	cases := map[string]bool{
		"tcp4": false, "tcp6": true,
		"udp4": false, "udp6": true,
		"ip4": false, "ip6": true,
	}
	for network, want := range cases {
		if got := isIPv6(network); got != want {
			t.Errorf("isIPv6(%q) = %v, 期望 %v", network, got, want)
		}
	}
}
