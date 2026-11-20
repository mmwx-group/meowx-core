package main

// 账户订阅导入地址的单元测试。跑法同 meowx_ggy_test.go（main.go 的 init 里就 flag.Parse）：
// go test -c -tags with_gvisor -o meowx.test . && ./meowx.test（不带参数，跑全部）

import (
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

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

// 白名单上报写日志（#1779）：一台目标一行，任一族成功就算成功；错误里不能带出上报地址里的 token
func TestPanelReportLogLines(t *testing.T) {
	results := []map[string]any{
		{"kind": "panel", "host": "panel.example.com", "family": "tcp4", "ok": true},
		{"kind": "panel", "host": "panel.example.com", "family": "tcp6", "ok": false, "error": "connect: network is unreachable"},
		{"kind": "po0", "host": "203.0.113.9:8443", "family": "tcp4", "ok": false, "error": "token 无效（403），到主控里重新登记这台 po0"},
		{"kind": "ggy", "token": "ctecsfw_••••abcd", "ok": true}, // GGY 自己写，这里跳过
	}
	got := reportLogLines(results)
	want := []string{
		"主控白名单 panel.example.com：成功（IPv4）",
		"po0 加白 203.0.113.9:8443：失败（IPv4 token 无效（403），到主控里重新登记这台 po0）",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestPanelReportTargetHidesToken(t *testing.T) {
	const token = "pgnfw_secretTOKEN1234"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" || !strings.Contains(r.URL.Path, token) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// po0 的 200 应答带着名单（规格 po0-ggy-results.md §1）：名单里有本机才算加白成功
		_, _ = w.Write([]byte(`{"enabled":true,"whitelist":["127.0.0.1"],"limit":5,"currentIp":"127.0.0.1"}`))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	res := reportTarget("po0", "https://"+host+"/api/firewall/"+token+"/add", true)
	if len(res) != 1 || res[0]["ok"] != true {
		t.Fatalf("自签证书的 po0 应该报成功：%v", res)
	}

	// 找一个没人听的端口：连不上，错误文字里不能有 token
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := l.Addr().String()
	l.Close()
	res = reportTarget("po0", "https://"+dead+"/api/firewall/"+token+"/add", true)
	if len(res) != 1 || res[0]["ok"] != false {
		t.Fatalf("应该失败：%v", res)
	}
	if e, _ := res[0]["error"].(string); e == "" || strings.Contains(e, token) {
		t.Fatalf("错误文字为空或带出了 token：%q", e)
	}
	for _, line := range reportLogLines(res) {
		if strings.Contains(line, token) {
			t.Fatalf("日志带出了 token：%q", line)
		}
	}
}

// 测速榜上传凭证：payload_hash 不对、没登录都直接报错（外壳据此退回匿名上传），不去连主控
func TestPanelSpeedTestGrantRejects(t *testing.T) {
	saved := panelStatePath
	defer func() { panelStatePath = saved }()
	panelStatePath = filepath.Join(t.TempDir(), "panel.json")

	for _, hash := range []string{"", "abc", strings.Repeat("g", 64), strings.Repeat("a", 63), strings.Repeat("a", 65)} {
		if _, err := panelSpeedTestGrant(hash); err == nil || err.Error() != "payload_hash 无效" {
			t.Errorf("hash %q: err = %v", hash, err)
		}
	}
	// 大写与首尾空白规整之后合法，但没登录
	if _, err := panelSpeedTestGrant(" " + strings.Repeat("AB", 32) + "\n"); err == nil || err.Error() != "还没有登录主控账户" {
		t.Errorf("not logged in: err = %v", err)
	}
}

// 外壳接实时通道（规格 entry-realtime.md §7）：只打印 {"base","token"}，没登录时报错
func TestPanelRealtimeConfig(t *testing.T) {
	old := panelStatePath
	defer func() { panelStatePath = old }()
	panelStatePath = filepath.Join(t.TempDir(), "panel.json")
	if _, err := panelRealtimeConfig(); err == nil {
		t.Fatal("not logged in should be an error")
	}
	st := &panelState{Base: "https://panel.example.com", Token: "T0KEN", Username: "alice", ReportURL: "https://panel.example.com/api/fw/x/add"}
	if err := st.save(); err != nil {
		t.Fatal(err)
	}
	out, err := panelRealtimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	m, _ := out.(map[string]any)
	if len(m) != 2 || m["base"] != "https://panel.example.com" || m["token"] != "T0KEN" {
		t.Fatalf("realtime-config = %+v", out)
	}
}
