package netutil

import "testing"

func TestIsValidDomain(t *testing.T) {
	valid := []string{"example.com", "a.b.c.example.com", "xn--fiqs8s.cn", "my-host.example.com"}
	invalid := []string{"example", "", "-bad.com", "bad-.com", "has space.com", "a..b", "with/slash.com", "semi;colon.com"}

	for _, d := range valid {
		if !IsValidDomain(d) {
			t.Errorf("IsValidDomain(%q) = false, 期望 true", d)
		}
	}
	for _, d := range invalid {
		if IsValidDomain(d) {
			t.Errorf("IsValidDomain(%q) = true, 期望 false", d)
		}
	}
}
