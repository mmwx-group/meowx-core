package main

// po0 加白结果 / 备注的单元测试（规格 miaomiaowuC/Design/po0-ggy-results.md §5）。只用假 token、本机假服务器。
// 跑法同 meowx_ggy_test.go：go test -c -tags with_gvisor -o meowx.test . && ./meowx.test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const po0TestToken = "pgnfw_FAKEtoken0000TEST"

func TestPo0SameC24(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.2.3.4", "1.2.3.4", true},
		{"1.2.3.4", "1.2.3.5", false},    // 两边都是精确 IP：必须全等
		{"1.2.3.0/24", "1.2.3.77", true}, // 一边是 /24
		{"1.2.3.77", "1.2.3.0/24", true},
		{"1.2.3.0/24", "1.2.3.0/24", true},
		{"1.2.3.0/24", "1.2.4.9", false},
		{"1.2.3.0/24", "1.2.4.0/24", false},
		{"10.0.0.0/24", "10.0.0.255", true},
		{"1.2.3.0/16", "1.2.3.4", false},     // 只认 /24
		{"2001:db8::1", "2001:db8::1", true}, // IPv6 只按全等
		{"2001:db8::1", "2001:db8::2", false},
		{"2001:db8::/24", "2001:db8::2", false},
		{"", "", false},
		{"1.2.3.4", "", false},
	}
	for _, c := range cases {
		if got := po0SameC24(c.a, c.b); got != c.want {
			t.Errorf("po0SameC24(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func intp(n int) *int { return &n }

func TestPo0Judge(t *testing.T) {
	type want struct {
		kind    string
		entries int
		limit   *int
		current string
		message string
	}
	cases := []struct {
		name   string
		status int
		body   string
		slot   *int
		want   want
	}{
		{"对象名单 + 精确 IP", 200, `{"enabled":true,"whitelist":[{"ip":"5.6.7.8","slot":1},{"ip":"1.2.3.4","slot":null}],"limit":5,"currentIp":"1.2.3.4"}`, nil,
			want{po0KindSuccess, 2, intp(5), "1.2.3.4", ""}},
		{"字符串名单（旧版服务端）", 200, `{"enabled":true,"whitelist":["9.9.9.9","1.2.3.4"],"limit":5,"currentIp":"1.2.3.4"}`, nil,
			want{po0KindSuccess, 2, intp(5), "1.2.3.4", ""}},
		{"/24 与精确 IP 混杂", 200, `{"enabled":true,"whitelist":["9.9.9.9",{"ip":"1.2.3.0/24","slot":2}],"limit":3,"currentIp":"1.2.3.99"}`, intp(2),
			want{po0KindSuccess, 2, intp(3), "1.2.3.99", ""}},
		{"currentIp 是 /24", 200, `{"enabled":true,"whitelist":[{"ip":"1.2.3.4"}],"limit":3,"currentIp":"1.2.3.0/24"}`, nil,
			want{po0KindSuccess, 1, intp(3), "1.2.3.0/24", ""}},
		{"防火墙没开", 200, `{"enabled":false,"whitelist":[],"limit":5,"currentIp":"1.2.3.4"}`, nil,
			want{po0KindDisabled, 0, intp(5), "1.2.3.4", ""}},
		{"名单里没有本机", 200, `{"enabled":true,"whitelist":["1.2.4.4",{"ip":"8.8.8.0/24","slot":1}],"limit":5,"currentIp":"1.2.3.4"}`, nil,
			want{po0KindNotApplied, 2, intp(5), "1.2.3.4", ""}},
		{"同段但都是精确 IP 不算", 200, `{"enabled":true,"whitelist":["1.2.3.5"],"limit":5,"currentIp":"1.2.3.4"}`, nil,
			want{po0KindNotApplied, 1, intp(5), "1.2.3.4", ""}},
		{"403 带槽位 = 槽位冲突", 403, `{"error":"slot conflict","currentIp":"1.2.3.4"}`, intp(1),
			want{po0KindSlotConflict, 0, nil, "1.2.3.4", "本机 IP 已在这台 po0 的其它槽位，先到 po0 面板删除旧槽位"}},
		{"403 不带槽位 = token 无效", 403, `forbidden`, nil,
			want{po0KindInvalidToken, 0, nil, "", ""}},
		{"500", 500, `oops`, nil, want{po0KindFailed, 0, nil, "", "HTTP 500"}},
		{"200 但不是 JSON", 200, `<html>ok</html>`, nil, want{po0KindFailed, 0, nil, "", "应答无法解析"}},
		{"200 是数组", 200, `[1,2]`, nil, want{po0KindFailed, 0, nil, "", "应答无法解析"}},
		{"200 空正文", 200, ``, nil, want{po0KindFailed, 0, nil, "", "应答无法解析"}},
		{"200 只回确认的老 po0", 200, `{"success":true}`, nil, want{po0KindSuccess, 0, nil, "", ""}},
		// 缺字段时信 200（规格 §1.1）
		{"空对象", 200, `{}`, nil, want{po0KindSuccess, 0, nil, "", ""}},
		{"只有 limit", 200, `{"limit":5}`, nil, want{po0KindSuccess, 0, intp(5), "", ""}},
		{"只有名单没有 currentIp", 200, `{"enabled":true,"whitelist":["1.2.3.4"],"limit":5}`, nil, want{po0KindSuccess, 1, intp(5), "", ""}},
		{"只有 currentIp 没有名单", 200, `{"currentIp":"1.2.3.4","limit":5}`, nil, want{po0KindSuccess, 0, intp(5), "1.2.3.4", ""}},
		{"enabled 缺省按开启、名单比不上", 200, `{"whitelist":["9.9.9.9"],"currentIp":"1.2.3.4"}`, nil, want{po0KindNotApplied, 1, nil, "1.2.3.4", ""}},
		{"名单是 null", 200, `{"whitelist":null,"currentIp":"1.2.3.4"}`, nil, want{po0KindSuccess, 0, nil, "1.2.3.4", ""}},
		{"缺名单但 enabled:false", 200, `{"enabled":false}`, nil, want{po0KindDisabled, 0, nil, "", ""}},
	}
	for _, c := range cases {
		r := judgePo0Response(c.status, []byte(c.body), c.slot)
		if r.Kind != c.want.kind || len(r.Entries) != c.want.entries || r.CurrentIP != c.want.current || r.Message != c.want.message {
			t.Errorf("%s: got %+v", c.name, r)
		}
		if (r.Limit == nil) != (c.want.limit == nil) || (r.Limit != nil && *r.Limit != *c.want.limit) {
			t.Errorf("%s: limit = %v", c.name, r.Limit)
		}
		if (r.Slot == nil) != (c.slot == nil) {
			t.Errorf("%s: slot = %v", c.name, r.Slot)
		}
	}
	// 200 一律带 enabled（缺省 true）；没有名单时 entries 是 null、空名单是 []（界面据此决定画不画名单）
	for body, want := range map[string]string{`{}`: `null`, `{"limit":5}`: `null`, `{"whitelist":[],"currentIp":"1.2.3.4"}`: `[]`} {
		r := judgePo0Response(200, []byte(body), nil)
		got, _ := json.Marshal(r.Entries)
		if r.Enabled == nil || !*r.Enabled || string(got) != want {
			t.Errorf("%s: enabled=%v entries=%s", body, r.Enabled, got)
		}
	}
	if r := judgePo0Response(200, []byte(`{"whitelist":[],"currentIp":"1.2.3.4"}`), nil); r.Kind != po0KindNotApplied {
		t.Errorf("空名单 + currentIp 应该是 notApplied：%s", r.Kind)
	}
	// 名单按应答顺序、槽位照抄（数字字符串也认）
	r := judgePo0Response(200, []byte(`{"enabled":true,"whitelist":[{"ip":"a","slot":3},{"ip":"b","slot":null},"c",{"ip":"d","slot":"4"},{"ip":""},7],"limit":5,"currentIp":"x"}`), nil)
	got, _ := json.Marshal(r.Entries)
	if string(got) != `[{"ip":"a","slot":3},{"ip":"b","slot":null},{"ip":"c","slot":null},{"ip":"d","slot":4}]` {
		t.Errorf("entries = %s", got)
	}
}

func TestPo0ResultText(t *testing.T) {
	on, off := true, false
	cases := []struct {
		r    po0Result
		want string
	}{
		{po0Result{Kind: po0KindSuccess, Enabled: &on, Limit: intp(5), Entries: make([]po0Entry, 3)}, "已加白 · 3/5"},
		{po0Result{Kind: po0KindSuccess}, "已加白"},
		{po0Result{Kind: po0KindSuccess, Enabled: &on, Limit: intp(5)}, "已加白"},                              // 只有 limit、没有名单
		{po0Result{Kind: po0KindSuccess, Enabled: &on, Entries: make([]po0Entry, 2)}, "已加白"},                // 有名单没有 limit
		{po0Result{Kind: po0KindSuccess, Enabled: &on, Limit: intp(5), Entries: []po0Entry{}}, "已加白 · 0/5"}, // 缺 currentIp、空名单
		{po0Result{Kind: po0KindDisabled, Enabled: &off}, "po0 没有开启防火墙"},
		{po0Result{Kind: po0KindNotApplied, Enabled: &on, Limit: intp(5), Entries: make([]po0Entry, 5)}, "加白未生效 · 5/5"},
		{po0Result{Kind: po0KindSlotConflict}, "槽位冲突：本机 IP 已在这台 po0 的其它槽位，先到 po0 面板删除旧槽位"},
		{po0Result{Kind: po0KindInvalidToken}, "token 无效"},
		{po0Result{Kind: po0KindFailed, Message: "HTTP 502"}, "失败：HTTP 502"},
	}
	for _, c := range cases {
		if got := po0ResultText(c.r); got != c.want {
			t.Errorf("po0ResultText(%+v) = %q, want %q", c.r, got, c.want)
		}
	}
}

func TestPo0PickResult(t *testing.T) {
	r, _ := po0PickResult([]po0Result{{Kind: po0KindFailed}, {Kind: po0KindNotApplied}})
	if r.Kind != po0KindNotApplied {
		t.Errorf("picked %s", r.Kind)
	}
	r, _ = po0PickResult([]po0Result{{Kind: po0KindSuccess, CurrentIP: "v4"}, {Kind: po0KindSuccess, CurrentIP: "v6"}})
	if r.CurrentIP != "v4" {
		t.Errorf("tie should keep the first (IPv4): %+v", r)
	}
	if _, ok := po0PickResult(nil); ok {
		t.Error("empty should be false")
	}
}

func TestPo0RedactTokens(t *testing.T) {
	in := `Post "https://1.2.3.4/api/firewall/` + po0TestToken + `/add?slot=2": dial tcp: refused; again pgnfw_abcd1234`
	out := redactPo0Tokens(in)
	if strings.Contains(out, po0TestToken) || strings.Contains(out, "pgnfw_abcd1234") {
		t.Fatalf("token 没脱敏：%q", out)
	}
	if !strings.Contains(out, "pgnfw_••••TEST") || !strings.Contains(out, "pgnfw_••••1234") {
		t.Fatalf("脱敏写法不对：%q", out)
	}
}

func TestPo0SlotFromURL(t *testing.T) {
	if s := po0SlotFromURL("https://1.2.3.4/api/firewall/x/add?slot=3"); s == nil || *s != 3 {
		t.Errorf("slot = %v", s)
	}
	for _, u := range []string{"https://1.2.3.4/api/firewall/x/add", "https://1.2.3.4/api/firewall/x/add?slot=", "https://1.2.3.4/a?slot=x", "%%"} {
		if s := po0SlotFromURL(u); s != nil {
			t.Errorf("%q: slot = %v", u, *s)
		}
	}
}

func TestNormalizeNote(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"  家里的 po0 \n", "家里的 po0", true},
		{"a\tb\nc", "a b c", true},
		{"", "", true},
		{"   ", "", true},
		{strings.Repeat("喵", 40), strings.Repeat("喵", 40), true},
		{strings.Repeat("喵", 41), "", false},
		{" " + strings.Repeat("a", 40) + " ", strings.Repeat("a", 40), true},
		{"\xff", "", false},
	}
	for _, c := range cases {
		got, err := normalizeNote(c.in)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("normalizeNote(%q) = %q, %v", c.in, got, err)
		}
	}
}

// 端到端（本机假 po0，自签证书）：panel report 记下结果，po0 status 带回结果与备注、改备注、删条目后结果一起删
func TestPo0ReportAndStatus(t *testing.T) {
	dir := t.TempDir()
	savedState, savedResult, savedGGY, savedLog := po0StatePath, po0ResultPath, ggyResultPath, ggyAppLogPath
	defer func() {
		po0StatePath, po0ResultPath, ggyResultPath, ggyAppLogPath = savedState, savedResult, savedGGY, savedLog
	}()
	po0StatePath = filepath.Join(dir, "po0.json")
	po0ResultPath = ""
	ggyResultPath = filepath.Join(dir, "run", "ggy.json")
	ggyAppLogPath = filepath.Join(dir, "app.log")
	t.Setenv("MEOWX_GGY_STATE", filepath.Join(dir, "ggy.json"))
	savedPanel := panelStatePath
	defer func() { panelStatePath = savedPanel }()
	panelStatePath = filepath.Join(dir, "panel.json")

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/add") && r.URL.Query().Get("slot") == "2":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"currentIp":"127.0.0.1"}`))
		case strings.Contains(r.URL.Path, po0TestToken):
			_, _ = w.Write([]byte(`{"enabled":true,"whitelist":[{"ip":"9.9.9.9","slot":1},"127.0.0.0/24"],"limit":5,"currentIp":"127.0.0.1"}`))
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	mustPo0 := func(args ...string) map[string]any {
		t.Helper()
		out, err := po0Main(args)
		if err != nil {
			t.Fatalf("po0 %v: %v", args, err)
		}
		// 经过一次 JSON，和 CLI 输出一样
		data, _ := json.Marshal(out)
		var m map[string]any
		_ = json.Unmarshal(data, &m)
		if strings.Contains(string(data), po0TestToken) {
			t.Fatalf("status 输出带出了完整 token：%s", data)
		}
		return m
	}
	mustPo0("enable")
	mustPo0("add", addr, po0TestToken, "  家里  ")
	mustPo0("add", addr, po0TestToken+"@2")
	mustPo0("add", addr, "pgnfw_WRONGtoken9999")

	if _, err := po0Main([]string{"note", "0", strings.Repeat("长", 41)}); err == nil {
		t.Fatal("41 字的备注应该被拒")
	}

	st := mustPo0("status")
	custom := st["custom"].([]any)
	if len(custom) != 3 {
		t.Fatalf("custom = %v", custom)
	}
	first := custom[0].(map[string]any)
	if first["note"] != "家里" || first["result"] != nil || first["slot"] != nil {
		t.Fatalf("还没报过时：%v", first)
	}
	if s := custom[1].(map[string]any)["slot"]; s != float64(2) {
		t.Fatalf("slot = %v", s)
	}

	if _, err := panelReport(); err != nil {
		t.Fatal(err)
	}
	st = mustPo0("status")
	custom = st["custom"].([]any)
	kinds := []string{}
	for _, c := range custom {
		r, _ := c.(map[string]any)["result"].(map[string]any)
		if r == nil {
			t.Fatalf("报过之后没有结果：%v", c)
		}
		if at, _ := r["at"].(float64); at <= 0 {
			t.Fatalf("没有时间：%v", r)
		}
		kinds = append(kinds, r["kind"].(string))
	}
	if strings.Join(kinds, ",") != "success,slotConflict,invalidToken" {
		t.Fatalf("kinds = %v", kinds)
	}
	r0 := custom[0].(map[string]any)["result"].(map[string]any)
	if r0["current_ip"] != "127.0.0.1" || r0["limit"] != float64(5) || len(r0["entries"].([]any)) != 2 {
		t.Fatalf("success result = %v", r0)
	}

	// 改备注不动结果；清除备注
	st = mustPo0("note", "0", "")
	first = st["custom"].([]any)[0].(map[string]any)
	if first["note"] != "" || first["result"] == nil {
		t.Fatalf("清备注后：%v", first)
	}
	// 删掉一台：它的结果一起删
	mustPo0("remove", "1")
	if len(loadPo0Results()) != 2 {
		t.Fatalf("results = %v", loadPo0Results())
	}
	// 关掉总开关：结果全删
	mustPo0("disable")
	if len(loadPo0Results()) != 0 {
		t.Fatalf("关掉后 results = %v", loadPo0Results())
	}
	// 结果文件缺省放在 GGY 结果同目录
	if po0ResultFile() != filepath.Join(dir, "run", "po0-results.json") {
		t.Fatalf("po0ResultFile = %s", po0ResultFile())
	}
}

// 老的 po0.json 没有 note 照常读
func TestPo0LegacyStateWithoutNote(t *testing.T) {
	var po po0State
	if err := json.Unmarshal([]byte(`{"enabled":true,"custom":[{"address":"1.2.3.4","token":"`+po0TestToken+`"}]}`), &po); err != nil {
		t.Fatal(err)
	}
	if len(po.Custom) != 1 || po.Custom[0].Note != "" {
		t.Fatalf("%+v", po)
	}
	data, _ := json.Marshal(po.Custom[0])
	if strings.Contains(string(data), "note") {
		t.Fatalf("没有备注时不写 note：%s", data)
	}
}

// GGY 备注（无 uci 的外壳：存 MEOWX_GGY_STATE 文件）：add 带备注、note 改 / 清、remove 一起删；老文件没有 notes 照常读
func TestGGYNotes(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "ggy.json")
	t.Setenv("MEOWX_GGY_STATE", state)
	savedResult := ggyResultPath
	defer func() { ggyResultPath = savedResult }()
	ggyResultPath = filepath.Join(dir, "ggy-results.json")

	// 老文件
	if err := os.WriteFile(state, []byte(`{"enabled":false,"tokens":["`+ggyTestToken+`"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := ggyMain([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	tokens := out.(map[string]any)["tokens"].([]map[string]any)
	if len(tokens) != 1 || tokens[0]["note"] != "" {
		t.Fatalf("tokens = %v", tokens)
	}
	// 关着时添加不上报
	second := "ctecsfw_SECONDtoken0000BBBB"
	if _, err := ggyMain([]string{"add", second, " 办公室 "}); err != nil {
		t.Fatal(err)
	}
	if _, err := ggyMain([]string{"note", "0", "家里"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ggyMain([]string{"note", "5", "x"}); err == nil {
		t.Fatal("没有这一项应该报错")
	}
	if _, err := ggyMain([]string{"note", "0", strings.Repeat("x", 41)}); err == nil {
		t.Fatal("41 字的备注应该被拒")
	}
	out, _ = ggyMain([]string{"status"})
	tokens = out.(map[string]any)["tokens"].([]map[string]any)
	if tokens[0]["note"] != "家里" || tokens[1]["note"] != "办公室" {
		t.Fatalf("tokens = %v", tokens)
	}
	data, _ := json.Marshal(out)
	if strings.Contains(string(data), ggyTestToken) || strings.Contains(string(data), second) {
		t.Fatalf("status 带出了完整 token：%s", data)
	}
	// 删掉第一个：它的备注一起删
	if _, err := ggyMain([]string{"remove", "0"}); err != nil {
		t.Fatal(err)
	}
	cfg := loadGGYConfig()
	if len(cfg.Notes) != 1 || cfg.note(second) != "办公室" {
		t.Fatalf("notes = %v", cfg.Notes)
	}
	// 清除备注
	if _, err := ggyMain([]string{"note", "0", ""}); err != nil {
		t.Fatal(err)
	}
	if n := loadGGYConfig().note(second); n != "" {
		t.Fatalf("note = %q", n)
	}
}

func TestGGYResultOf(t *testing.T) {
	cases := []struct {
		o    ggyOutcome
		kind string
	}{
		{ggyOutcome{OK: true, Reason: "添加成功"}, "success"},
		{ggyOutcome{Invalid: true, Reason: "白名单分享链接无效或已失效"}, "invalidToken"},
		{ggyOutcome{Reason: "HTTP 502"}, "failed"},
	}
	for _, c := range cases {
		r := ggyResultOf(c.o, 100)
		if r.Kind != c.kind || r.At != 100 {
			t.Errorf("%+v → %+v", c.o, r)
		}
	}
	if r := ggyResultOf(ggyOutcome{OK: true, Reason: "添加成功"}, 1); r.Msg != "添加成功" || !r.OK || r.Error != "" {
		t.Errorf("success msg: %+v", r)
	}
}

// GGY 成功时记下 msg（里面的 token 换成脱敏写法）与 kind，status 带回来；本机假服务器
func TestGGYResultMsgInStatus(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":200,"msg":"已加入白名单 ` + r.URL.Query().Get("token") + `"}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	t.Setenv("MEOWX_GGY_STATE", filepath.Join(dir, "ggy.json"))
	oldBase, oldTLS, oldResult, oldLog := ggyReportBase, ggyTLSConfig, ggyResultPath, ggyAppLogPath
	defer func() { ggyReportBase, ggyTLSConfig, ggyResultPath, ggyAppLogPath = oldBase, oldTLS, oldResult, oldLog }()
	ggyReportBase = server.URL + "/cany_tencentecs/firewall/whitelist?token="
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	ggyTLSConfig = &tls.Config{RootCAs: pool}
	ggyResultPath = filepath.Join(dir, "ggy-results.json")
	ggyAppLogPath = filepath.Join(dir, "app.log")

	if _, err := ggyMain([]string{"enable"}); err != nil {
		t.Fatal(err)
	}
	out, err := ggyMain([]string{"add", ggyTestToken, "测试"})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(out)
	if strings.Contains(string(data), ggyTestToken) {
		t.Fatalf("带出了完整 token：%s", data)
	}
	tokens := out.(map[string]any)["tokens"].([]map[string]any)
	r, _ := tokens[0]["result"].(ggyResult)
	if tokens[0]["note"] != "测试" || r.Kind != "success" || !r.OK || r.Msg != "已加入白名单 ctecsfw_••••AAAA" || r.At <= 0 {
		t.Fatalf("token = %+v", tokens[0])
	}
}
