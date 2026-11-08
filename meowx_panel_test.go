package main

// 账户订阅导入地址的单元测试。跑法同 meowx_ggy_test.go（main.go 的 init 里就 flag.Parse）：
// go test -c -tags with_gvisor -o meowx.test . && ./meowx.test -test.run Panel

import "testing"

func TestPanelSubscriptionBase(t *testing.T) {
	const panel = "https://panel.example.com"
	cases := []struct{ raw, want string }{
		{"", panel},
		{"   ", panel},
		{"https://sub.example.com", "https://sub.example.com"},
		{"https://sub.example.com/", "https://sub.example.com"},
		{"https://sub.example.com:8443/some/path", "https://sub.example.com:8443"},
		{"http://10.0.0.2:12889", "http://10.0.0.2:12889"},
		{"sub.example.com", "https://sub.example.com"},
		{"ftp://sub.example.com", panel},
		{"https://", panel},
	}
	for _, c := range cases {
		if got := panelSubscriptionBase(c.raw, panel); got != c.want {
			t.Errorf("panelSubscriptionBase(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

func TestPanelSubscriptionLink(t *testing.T) {
	const sub = "https://sub.example.com"
	cases := []struct{ name, path, filename, token, want string }{
		// 短链自带凭证，挂在订阅域名上
		{"short", "/x/abcUSER", "a.yaml", "T", "https://sub.example.com/x/abcUSER"},
		{"short-no-token", "/x/abc", "", "", "https://sub.example.com/x/abc"},
		// 关了短链接：接口地址补订阅令牌
		{"file", "/api/clash/subscribe?filename=a.yaml", "a.yaml", "T", "https://sub.example.com/api/clash/subscribe?filename=a.yaml&token=T"},
		{"package", "/api/user/package-subscribe?assignment_id=7", "__package__:7", "T", "https://sub.example.com/api/user/package-subscribe?assignment_id=7&token=T"},
		{"has-token", "/api/clash/subscribe?filename=a.yaml&token=X", "a.yaml", "T", "https://sub.example.com/api/clash/subscribe?filename=a.yaml&token=X"},
		{"needs-token", "/api/user/package-subscribe?merged=1", "", "", ""},
		// 旧主控不给 subscription_path
		{"legacy", "", "a.yaml", "T", "https://sub.example.com/api/clash/subscribe?filename=a.yaml&t=clash&token=T"},
		{"legacy-no-token", "", "a.yaml", "", ""},
	}
	for _, c := range cases {
		if got := panelSubscriptionLink(sub, c.path, c.filename, c.token); got != c.want {
			t.Errorf("%s: panelSubscriptionLink = %q, want %q", c.name, got, c.want)
		}
	}
}
