package main

// GGY 加白的单元测试（只用假 token，不连真实的 GGY）。main.go 的 init 里就 flag.Parse，go test 带的 -test.* 参数过不去：
// 先编出测试程序再不带参数跑——go test -c -tags with_gvisor -o meowx.test . && ./meowx.test

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const ggyTestToken = "ctecsfw_TESTtoken0000000000AAAA"

func TestGGYParseToken(t *testing.T) {
	cases := []struct {
		in   string
		want string // "" = 不合法
	}{
		{ggyTestToken, ggyTestToken},
		{"  " + ggyTestToken + "\n", ggyTestToken},
		{"https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=" + ggyTestToken, ggyTestToken},
		{" https://www.guguyun.com/cany_tencentecs/firewall/whitelist?a=1&token=" + ggyTestToken + "&b=2#x ", ggyTestToken},
		{"www.guguyun.com/cany_tencentecs/firewall/whitelist?token=" + ggyTestToken, ggyTestToken},
		{"https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=", ""},
		{"https://www.guguyun.com/cany_tencentecs/firewall/whitelist", ""},
		{"https://www.guguyun.com/x?id=" + ggyTestToken, ""},
		{"abc-DEF_1", "abc-DEF_1"}, // 不强制前缀
		{"abcdefgh", "abcdefgh"},   // 8 位
		{"abcdefg", ""},            // 太短
		{strings.Repeat("a", 200), strings.Repeat("a", 200)},
		{strings.Repeat("a", 201), ""}, // 太长
		{"ctecsfw_TEST token", ""},     // 中间有空白
		{"ctecsfw_TEST.token0", ""},    // 非法字符
		{"ctecsfw_TEST'token0", ""},
		{"ctecsfw_测试token0000", ""},
		{"", ""},
	}
	for _, c := range cases {
		got, ok := parseGGYToken(c.in)
		if c.want == "" {
			if ok {
				t.Errorf("parseGGYToken(%q) = %q, want invalid", c.in, got)
			}
			continue
		}
		if !ok || got != c.want {
			t.Errorf("parseGGYToken(%q) = %q, %v, want %q", c.in, got, ok, c.want)
		}
	}
}

func TestGGYAddDedupAndLimit(t *testing.T) {
	var cfg ggyConfig
	if _, err := cfg.add(ggyTestToken); err != nil {
		t.Fatal(err)
	}
	// 整条链接与裸 token 规范化后相同 = 重复
	if _, err := cfg.add("https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=" + ggyTestToken); err == nil {
		t.Error("duplicate token accepted")
	}
	if _, err := cfg.add(" " + ggyTestToken + " "); err == nil {
		t.Error("duplicate token with spaces accepted")
	}
	if _, err := cfg.add("short"); err == nil || err.Error() != "token 格式不对" {
		t.Errorf("invalid token error = %v", err)
	}
	if _, err := cfg.add("  "); err == nil || err.Error() != "请填写 token" {
		t.Errorf("empty token error = %v", err)
	}
	if _, err := cfg.add(ggyTestToken); err == nil || err.Error() != "这个 token 已经添加过" {
		t.Errorf("duplicate token error = %v", err)
	}
	for i := 1; len(cfg.Tokens) < ggyMaxTokens; i++ {
		if _, err := cfg.add("ctecsfw_TESTtoken" + strings.Repeat("0", 10) + string(rune('A'+i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := cfg.add("ctecsfw_TESTtoken0000000000ZZZZ"); err == nil || err.Error() != "最多添加 20 个 token" {
		t.Errorf("more than 20 tokens: %v", err)
	}
	if len(cfg.Tokens) != ggyMaxTokens {
		t.Errorf("len = %d", len(cfg.Tokens))
	}
}

func TestGGYMask(t *testing.T) {
	cases := map[string]string{
		ggyTestToken:          "ctecsfw_••••AAAA",
		"ctecsfw_abcdefgBBBB": "ctecsfw_••••BBBB",
		"abcdefgh1234":        "••••1234",
		"ab_cd_ef_gh":         "ab_••••f_gh",
		"abc-DEF-ghi-JKL":     "••••-JKL",
		"_leading12345":       "_••••2345",
	}
	for in, want := range cases {
		if got := maskGGYToken(in); got != want {
			t.Errorf("maskGGYToken(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGGYReportURL(t *testing.T) {
	want := "https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=" + ggyTestToken
	if got := ggyReportURL(ggyTestToken); got != want {
		t.Errorf("ggyReportURL = %q, want %q", got, want)
	}
}

func TestGGYJudge(t *testing.T) {
	invalidBody := `{"status":400,"msg":"白名单分享链接无效或已失效","data":[]}`
	cases := []struct {
		name    string
		code    int
		body    string
		ok      bool
		invalid bool
		reason  string
		head    string
	}{
		{"status 200 number", 200, `{"status":200,"msg":"加白成功","data":[]}`, true, false, "加白成功", ""},
		{"status 200.0", 200, `{"status":200.0}`, true, false, "", ""},
		{"status 200 string", 200, `{"status":"200","msg":""}`, true, false, "", ""},
		{"status 200 string spaces", 200, `{"status":" 200 ","msg":" ok "}`, true, false, "ok", ""},
		{"status 400 invalid", 200, invalidBody, false, true, "白名单分享链接无效或已失效", ""},
		{"status 400 string expired", 200, `{"status":"400","msg":"链接已失效"}`, false, true, "链接已失效", ""},
		{"status 400 other msg", 200, `{"status":400,"msg":"操作太频繁"}`, false, false, "操作太频繁", ""},
		{"status 500 invalid msg", 200, `{"status":500,"msg":"链接无效"}`, false, false, "链接无效", ""},
		{"status 500 no msg", 200, `{"status":500}`, false, false, "status 500", ""},
		{"status string no msg", 200, `{"status":" fail ","msg":""}`, false, false, "status fail", ""},
		{"status null", 200, `{"status":null}`, false, false, "status null", ""},
		{"no status", 200, `{"code":0,"message":"ok"}`, true, false, "", `{"code":0,"message":"ok"}`},
		{"no status with msg", 200, `{"msg":"已加白"}`, true, false, "已加白", `{"msg":"已加白"}`},
		{"not json", 200, "<html>\n<body>hello</body></html>", false, false, "应答无法解析", "<html> <body>hello</body></html>"},
		{"json array", 200, `[1,2]`, false, false, "应答无法解析", "[1,2]"},
		{"empty body", 200, "", false, false, "应答无法解析", ""},
		{"http 404", 404, invalidBody, false, false, "HTTP 404", ""},
		{"http 502", 502, "", false, false, "HTTP 502", ""},
	}
	for _, c := range cases {
		got := judgeGGYResponse(c.code, []byte(c.body))
		if got.OK != c.ok || got.Invalid != c.invalid || got.Reason != c.reason || got.Head != c.head {
			t.Errorf("%s: got %+v, want ok=%v invalid=%v reason=%q head=%q", c.name, got, c.ok, c.invalid, c.reason, c.head)
		}
	}
}

func TestGGYLogLine(t *testing.T) {
	m := maskGGYToken(ggyTestToken)
	cases := []struct {
		o    ggyOutcome
		want string
	}{
		{ggyOutcome{OK: true}, "GGY 加白 ctecsfw_••••AAAA：成功"},
		{ggyOutcome{OK: true, Reason: "加白成功"}, "GGY 加白 ctecsfw_••••AAAA：成功（加白成功）"},
		{ggyOutcome{OK: true, Head: `{"code":0}`}, `GGY 加白 ctecsfw_••••AAAA：成功（应答没有 status：{"code":0}）`},
		{ggyOutcome{OK: true, Reason: "ok", Head: `{"msg":"ok"}`}, `GGY 加白 ctecsfw_••••AAAA：成功（ok；应答没有 status：{"msg":"ok"}）`},
		{ggyOutcome{Invalid: true, Reason: "白名单分享链接无效或已失效"}, "GGY 加白 ctecsfw_••••AAAA：失败（白名单分享链接无效或已失效）"},
		{ggyOutcome{Reason: "应答无法解析", Head: "<html>"}, "GGY 加白 ctecsfw_••••AAAA：失败（应答无法解析：<html>）"},
		{ggyOutcome{Reason: "HTTP 502"}, "GGY 加白 ctecsfw_••••AAAA：失败（HTTP 502）"},
	}
	for _, c := range cases {
		if got := ggyLogLine(m, c.o); got != c.want {
			t.Errorf("ggyLogLine(%+v) = %q, want %q", c.o, got, c.want)
		}
	}
}

func TestGGYSnippet(t *testing.T) {
	long := `{"data":"` + strings.Repeat("咕", 100) + `"}`
	got := ggySnippet([]byte(long))
	if len(got) > 160 || !strings.HasPrefix(got, `{"data":"咕`) || strings.ContainsRune(got, '�') {
		t.Errorf("snippet = %q (%d bytes)", got, len(got))
	}
}

// 对本机 TLS 测试服务器跑一遍完整的上报：请求的形状、证书照常校验、错误文字里不带完整 token
func TestGGYReportRequest(t *testing.T) {
	var gotMethod, gotQuery, gotAccept, gotUA, gotEncoding string
	var gotClose bool
	var gotUAPresent bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotQuery = r.Method, r.URL.Query().Get("token")
		gotAccept, gotEncoding = r.Header.Get("Accept"), r.Header.Get("Accept-Encoding")
		_, gotUAPresent = r.Header["User-Agent"]
		gotUA = r.UserAgent()
		gotClose = r.Close
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":400,"msg":"白名单分享链接无效或已失效","data":[]}`))
	}))
	defer server.Close()

	oldBase, oldTLS := ggyReportBase, ggyTLSConfig
	defer func() { ggyReportBase, ggyTLSConfig = oldBase, oldTLS }()
	ggyReportBase = server.URL + "/cany_tencentecs/firewall/whitelist?token="

	// 自签证书：照常校验时必须失败
	ggyTLSConfig = nil
	out := reportGGY(ggyTestToken)
	if out.OK || !strings.HasPrefix(out.Reason, "连不上：") || strings.Contains(out.Reason, ggyTestToken) {
		t.Fatalf("self-signed server: %+v", out)
	}

	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	ggyTLSConfig = &tls.Config{RootCAs: pool}
	out = reportGGY(ggyTestToken)
	if out.OK || !out.Invalid || out.Reason != "白名单分享链接无效或已失效" {
		t.Errorf("outcome = %+v", out)
	}
	if gotMethod != http.MethodGet || gotQuery != ggyTestToken || gotAccept != "application/json" {
		t.Errorf("request: method=%q token=%q accept=%q", gotMethod, gotQuery, gotAccept)
	}
	if gotUAPresent || gotUA != "" || gotEncoding != "" || !gotClose {
		t.Errorf("headers: ua=%v %q accept-encoding=%q close=%v", gotUAPresent, gotUA, gotEncoding, gotClose)
	}
}

func TestGGYRedact(t *testing.T) {
	got := ggyRedact(`Get "https://x/?token=`+ggyTestToken+`": timeout`, ggyTestToken)
	if strings.Contains(got, ggyTestToken) || !strings.Contains(got, "ctecsfw_••••AAAA") {
		t.Errorf("redact = %q", got)
	}
}
