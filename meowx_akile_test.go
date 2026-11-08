package main

// AkileCDN 白名单的单元测试（只用假 Key、回环上的假服务器，不连 cdnapi.akile.ai）。跑法同 meowx_ggy_test.go：
// go test -c -tags with_gvisor -o meowx.test . && ./meowx.test -test.run Akile

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const akileTestKey = "ak_TESTkey0000000000AAAA"

func TestAkileParseKey(t *testing.T) {
	cases := []struct{ in, want string }{
		{akileTestKey, akileTestKey},
		{"  " + akileTestKey + "\n", akileTestKey},
		{"X-API-Key: " + akileTestKey, akileTestKey},
		{"x-api-key:" + akileTestKey, akileTestKey},
		{"Bearer " + akileTestKey, akileTestKey},
		{"bearer   " + akileTestKey, akileTestKey},
		{"ak_abcdefgh", "ak_abcdefgh"}, // 8 位
		{"ak_abcdefg", ""},             // 太短
		{"ak_" + strings.Repeat("a", 200), "ak_" + strings.Repeat("a", 200)},
		{"ak_" + strings.Repeat("a", 201), ""},
		{"AK_TESTkey0000000000AAAA", ""}, // 前缀分大小写
		{"sk_TESTkey0000000000AAAA", ""},
		{"ak_TEST key000000000", ""},
		{"ak_TEST.key000000000", ""},
		{"Authorization: Bearer " + akileTestKey, ""},
		{"", ""},
	}
	for _, c := range cases {
		got, ok := parseAkileKey(c.in)
		if c.want == "" {
			if ok {
				t.Errorf("parseAkileKey(%q) = %q, want invalid", c.in, got)
			}
			continue
		}
		if !ok || got != c.want {
			t.Errorf("parseAkileKey(%q) = %q, %v, want %q", c.in, got, ok, c.want)
		}
	}
}

func TestAkileMask(t *testing.T) {
	if got := maskAkileKey(akileTestKey); got != "ak_••••AAAA" {
		t.Errorf("mask = %q", got)
	}
	if got := maskAkileKey(""); got != "" {
		t.Errorf("mask empty = %q", got)
	}
	if got := akileRedact("bad key "+akileTestKey+" !", akileTestKey); got != "bad key ak_••••AAAA !" {
		t.Errorf("redact = %q", got)
	}
}

func TestAkileExtractIPv4(t *testing.T) {
	cases := []struct {
		body, want string
		ok         bool
	}{
		{"203.0.113.10\n", "203.0.113.10", true},
		{"当前 IP：203.0.113.10  来自于：中国 上海 上海  电信\n", "203.0.113.10", true},
		{"当前 IP：198.51.100.7 来自于：x 203.0.113.10", "198.51.100.7", true},
		{"10.1.2.3", "", false},
		{"100.64.0.1", "", false},
		{"127.0.0.1", "", false},
		{"169.254.1.1", "", false},
		{"172.16.0.1", "", false},
		{"172.31.255.255", "", false},
		{"172.32.0.1", "172.32.0.1", true},
		{"192.168.1.1", "", false},
		{"198.18.0.1", "", false},
		{"198.19.255.255", "", false},
		{"198.20.0.1", "198.20.0.1", true},
		{"0.1.2.3", "", false},
		{"224.0.0.1", "", false},
		{"255.255.255.255", "", false},
		{"300.1.1.1", "", false},
		{"1.2.3.4.5", "", false},
		{"2001:db8::1", "", false},
		{"<html>blocked</html>", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, err := akileExtractIPv4(c.body)
		if c.ok != (err == nil) || got != c.want {
			t.Errorf("akileExtractIPv4(%q) = %q, %v, want %q ok=%v", c.body, got, err, c.want, c.ok)
		}
	}
}

func TestAkileParseRules(t *testing.T) {
	ids := func(rules []akileRule) string {
		var s []string
		for _, r := range rules {
			s = append(s, fmt.Sprint(r.ID))
		}
		return strings.Join(s, ",")
	}
	cases := []struct {
		name, body string
		port       int
		ok         bool
		want       string
	}{
		{"data array", `{"data":[{"id":1},{"id":2}]}`, 443, true, "1,2"},
		{"data.items", `{"data":{"items":[{"id":3}],"total":1}}`, 443, true, "3"},
		{"data.list", `{"data":{"list":[{"id":4}]}}`, 443, true, "4"},
		{"data.rules", `{"data":{"rules":[{"id":5}]}}`, 443, true, "5"},
		{"data obj without list -> top rules", `{"data":{"total":0},"rules":[{"id":6}]}`, 443, true, "6"},
		{"top rules", `{"rules":[{"id":7}]}`, 443, true, "7"},
		{"top items", `{"items":[{"id":8}]}`, 443, true, "8"},
		{"top array", `[{"id":9},{"id":10}]`, 443, true, "9,10"},
		{"empty", `{"data":[]}`, 443, true, ""},
		{"string ids", `{"data":[{"id":"11"},{"id":" 12 "},{"id":"x13"},{"id":"1.5"}]}`, 443, true, "11,12"},
		{"bad ids", `{"data":[{"id":1.5},{"id":null},{"name":"no id"},{"id":true},"str",{"id":14}]}`, 443, true, "14"},
		{"port filter", `{"data":[{"id":1,"listen_port":443},{"id":2,"listen_port":8443},{"id":3},{"id":4,"listen_port":"443"},{"id":5,"listen_port":"8443"}]}`, 443, true, "1,3,4"},
		{"no list", `{"data":null}`, 443, false, ""},
		{"no list obj", `{"message":"ok"}`, 443, false, ""},
		{"not json", `<html></html>`, 443, false, ""},
		{"scalar", `42`, 443, false, ""},
	}
	for _, c := range cases {
		rules, ok := parseAkileRules([]byte(c.body), c.port)
		if ok != c.ok || ids(rules) != c.want {
			t.Errorf("%s: got %v %q, want %v %q", c.name, ok, ids(rules), c.ok, c.want)
		}
	}

	// 说明文字按顺序取第一个非空字符串字段；node_id 数字或字符串；listen_port 单独取出
	body := `{"data":[
		{"id":1,"name":"","remark":"  香港 01 ","note":"n","entry_whitelist":"198.51.100.1/32","node_id":12,"listen_port":443},
		{"id":2,"note":"备注","node_id":"hk-2"},
		{"id":3,"node_name":"nn","target":"t"},
		{"id":4,"target":"1.2.3.4:443"},
		{"id":5,"name":7,"description":"d"},
		{"id":6}
	]}`
	rules, ok := parseAkileRules([]byte(body), 443)
	if !ok || len(rules) != 6 {
		t.Fatalf("rules = %v %+v", ok, rules)
	}
	want := []akileRule{
		{ID: 1, Summary: "香港 01", EntryWhitelist: "198.51.100.1/32", NodeID: "12", ListenPort: 443},
		{ID: 2, Summary: "备注", NodeID: "hk-2"},
		{ID: 3, Summary: "nn"},
		{ID: 4, Summary: "1.2.3.4:443"},
		{ID: 5, Summary: "d"},
		{ID: 6},
	}
	for i := range want {
		if rules[i] != want[i] {
			t.Errorf("rule %d = %+v, want %+v", i, rules[i], want[i])
		}
	}
}

func TestAkileServerTextAndClassify(t *testing.T) {
	cases := []struct {
		status     int
		body       string
		kind, text string
	}{
		{401, `{"error":"unauthorized"}`, akileKindInvalidKey, akileTextInvalidKey},
		{403, ``, akileKindInvalidKey, akileTextInvalidKey},
		{404, `{"error":"rule not found"}`, akileKindNotFound, akileTextNotFound},
		{429, `{"error":"slow down"}`, akileKindRateLimited, akileTextRateLimited},
		{400, `{"error":"节点开着白名单时不能清空"}`, akileKindFailed, "节点开着白名单时不能清空"},
		{400, `{"error":{"message":" invalid ip ","code":1}}`, akileKindFailed, "invalid ip"},
		{400, `{"error":{"code":1},"message":"m"}`, akileKindFailed, "m"},
		{422, `{"msg":"格式不对"}`, akileKindFailed, "格式不对"},
		{422, `{"detail":"bad"}`, akileKindFailed, "bad"},
		{422, `{"detail":[{"loc":"x"}]}`, akileKindFailed, "HTTP 422"},
		{500, `<html>oops</html>`, akileKindFailed, "HTTP 500"},
		{502, ``, akileKindFailed, "HTTP 502"},
		{204, ``, akileKindFailed, "HTTP 204"},
	}
	for _, c := range cases {
		kind, text := akileClassify(c.status, []byte(c.body))
		if kind != c.kind || text != c.text {
			t.Errorf("classify(%d, %s) = %s %q, want %s %q", c.status, c.body, kind, text, c.kind, c.text)
		}
	}
}

func TestAkileJudgePut(t *testing.T) {
	cases := []struct {
		body     string
		ok       bool
		kind     string
		previous string
	}{
		{`{"data":{"id":1,"entry_whitelist":"203.0.113.10/32","previous":"198.51.100.1/32","changed":true}}`, true, akileKindUpdated, "198.51.100.1"},
		{`{"data":{"id":1,"entry_whitelist":"203.0.113.10/32","previous":"203.0.113.10/32","changed":false}}`, true, akileKindUnchanged, "203.0.113.10"},
		{`{"data":{"id":"1"}}`, true, akileKindUnchanged, ""},
		{`{"data":{"changed":true}}`, false, akileKindFailed, ""},
		{`{"data":{"id":null}}`, false, akileKindFailed, ""},
		{`{"success":true}`, false, akileKindFailed, ""},
		{`{"data":[1]}`, false, akileKindFailed, ""},
		{`ok`, false, akileKindFailed, ""},
		{``, false, akileKindFailed, ""},
	}
	for _, c := range cases {
		o := judgeAkilePut([]byte(c.body))
		if o.OK != c.ok || o.Kind != c.kind || o.Previous != c.previous || (!c.ok && o.Error != akileTextBadReply) {
			t.Errorf("judge(%s) = %+v", c.body, o)
		}
	}
}

func TestAkileUCIValues(t *testing.T) {
	got := splitUCIValues(`'12|443|香港 01|HK 01 | 专线' '13|8443||it'\''s' '14|1||a'`)
	want := []string{"12|443|香港 01|HK 01 | 专线", "13|8443||it's", "14|1||a"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("split = %q", got)
	}
	if got := splitUCIValues(`plain 'two words'`); len(got) != 2 || got[0] != "plain" || got[1] != "two words" {
		t.Errorf("split mixed = %q", got)
	}
	n, ok := decodeAkileNode(want[0])
	if !ok || n.RuleID != 12 || n.Port != 443 || n.Label != "香港 01" || n.Name != "HK 01 | 专线" {
		t.Errorf("decode = %+v %v", n, ok)
	}
	if enc := encodeAkileNode(n); enc != want[0] {
		t.Errorf("encode = %q", enc)
	}
	for _, bad := range []string{"x|443||a", "0|443||a", "1|0||a", "1|70000||a", "1|443|a", ""} {
		if _, ok := decodeAkileNode(bad); ok {
			t.Errorf("decode(%q) accepted", bad)
		}
	}
}

func TestAkileAddNode(t *testing.T) {
	var cfg akileConfig
	if err := cfg.addNode(akileNode{RuleID: 1, Port: 443, Name: " HK\n01 ", Label: "a|b"}); err != nil {
		t.Fatal(err)
	}
	if n := cfg.Nodes[0]; n.Name != "HK 01" || n.Label != "a/b" {
		t.Errorf("cleaned = %+v", n)
	}
	if err := cfg.addNode(akileNode{RuleID: 1, Port: 8443, Name: "x"}); err == nil || err.Error() != "这条规则已经添加过" {
		t.Errorf("dup = %v", err)
	}
	if err := cfg.addNode(akileNode{RuleID: 2, Port: 0, Name: "x"}); err == nil {
		t.Error("port 0 accepted")
	}
	if err := cfg.addNode(akileNode{RuleID: 2, Port: 1, Name: "  "}); err == nil {
		t.Error("empty name accepted")
	}
	for i := int64(2); len(cfg.Nodes) < akileMaxNodes; i++ {
		if err := cfg.addNode(akileNode{RuleID: i, Port: 443, Name: "n"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := cfg.addNode(akileNode{RuleID: 99, Port: 443, Name: "n"}); err == nil || err.Error() != "最多 20 个节点" {
		t.Errorf("limit = %v", err)
	}
}

func TestAkileConfigNodes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yamlText := `
proxies:
  - {name: "🇭🇰 香港 01", type: vless, server: hk.example.com, port: 443}
  - {name: str-port, type: trojan, server: 1.2.3.4, port: "8443"}
  - {name: direct, type: direct}
  - {name: ts, type: tailscale}
  - {name: hy2-hop, type: hysteria2, server: h.example.com, ports: "20000-20010"}
  - {name: bad-port, type: ss, server: x, port: 0}
  - {name: "", type: ss, server: x, port: 1}
proxy-groups:
  - {name: PROXY, type: select, proxies: [direct]}
`
	if err := os.WriteFile(path, []byte(yamlText), 0o600); err != nil {
		t.Fatal(err)
	}
	nodes, err := akileConfigNodes(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 || nodes[0]["name"] != "🇭🇰 香港 01" || nodes[0]["port"] != 443 || nodes[0]["server"] != "hk.example.com" ||
		nodes[1]["name"] != "str-port" || nodes[1]["port"] != 8443 || nodes[1]["type"] != "trojan" {
		t.Errorf("nodes = %v", nodes)
	}
	if _, err := akileConfigNodes(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("missing file accepted")
	}
}

// ---------- 上报流程（回环上的假接口 + 假出口 IP 端点）----------

type akileFake struct {
	mu       sync.Mutex
	ip       string
	ipStatus int
	// 按规则 ID 给的应答：状态码与正文；没写的回 200 + changed=true
	replies map[string]akileFakeReply
	puts    []string // 收到的 PUT：「<id> <body>」
	keys    []string
	gets    []string
	rules   string
}

type akileFakeReply struct {
	status int
	body   string
}

func (f *akileFake) setIP(ip string) { f.mu.Lock(); f.ip = ip; f.mu.Unlock() }

func (f *akileFake) reset() {
	f.mu.Lock()
	f.puts, f.keys, f.gets = nil, nil, nil
	f.mu.Unlock()
}

func setupAkileFake(t *testing.T) *akileFake {
	t.Helper()
	f := &akileFake{ip: "203.0.113.10", ipStatus: 200, replies: map[string]akileFakeReply{}}
	ipServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		ip, status := f.ip, f.ipStatus
		f.mu.Unlock()
		w.WriteHeader(status)
		_, _ = io.WriteString(w, "当前 IP："+ip+"  来自于：测试\n")
	}))
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.keys = append(f.keys, r.Header.Get("X-API-Key"))
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && r.URL.Path == "/api/open/rules" {
			f.gets = append(f.gets, r.URL.RawQuery)
			_, _ = io.WriteString(w, f.rules)
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/open/rules/"), "/")
		if r.Method != http.MethodPut || len(parts) != 2 || parts[1] != "entry-whitelist" || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(400)
			_, _ = io.WriteString(w, `{"error":"bad request"}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		f.puts = append(f.puts, parts[0]+" "+string(body))
		if rep, ok := f.replies[parts[0]]; ok {
			w.WriteHeader(rep.status)
			_, _ = io.WriteString(w, rep.body)
			return
		}
		var req struct {
			EntryWhitelist string `json:"entry_whitelist"`
		}
		_ = json.Unmarshal(body, &req)
		fmt.Fprintf(w, `{"data":{"id":%s,"entry_whitelist":"%s/32","previous":"198.51.100.1/32","changed":true}}`, parts[0], req.EntryWhitelist)
	}))
	t.Cleanup(func() { ipServer.Close(); api.Close() })

	dir := t.TempDir()
	oldBase, oldTLS, oldEPs, oldResult, oldLog := akileAPIBase, akileTLSConfig, akileIPEndpoints, akileResultPath, ggyAppLogPath
	t.Cleanup(func() {
		akileAPIBase, akileTLSConfig, akileIPEndpoints, akileResultPath, ggyAppLogPath = oldBase, oldTLS, oldEPs, oldResult, oldLog
	})
	pool := x509.NewCertPool()
	pool.AddCert(api.Certificate())
	akileAPIBase = api.URL + "/api/open"
	akileTLSConfig = &tls.Config{RootCAs: pool}
	akileIPEndpoints = []string{ipServer.URL + "/"}
	akileResultPath = filepath.Join(dir, "akile.json")
	ggyAppLogPath = filepath.Join(dir, "app.log")
	t.Setenv("MEOWX_AKILE_STATE", filepath.Join(dir, "akile-state.json"))
	return f
}

func akileTestNodes(n int) []akileNode {
	var nodes []akileNode
	for i := 1; i <= n; i++ {
		nodes = append(nodes, akileNode{RuleID: int64(100 + i), Port: 443, Name: fmt.Sprintf("节点 %d", i), Label: "l"})
	}
	return nodes
}

func akileSaveTestConfig(t *testing.T, cfg akileConfig) {
	t.Helper()
	if err := cfg.save(); err != nil {
		t.Fatal(err)
	}
}

func akileResultOf(entry map[string]any) akileResult {
	r, _ := entry["result"].(akileResult)
	return r
}

func TestAkileReportRounds(t *testing.T) {
	f := setupAkileFake(t)
	nodes := akileTestNodes(3)
	akileSaveTestConfig(t, akileConfig{Enabled: true, Key: akileTestKey, Nodes: nodes})

	// 事件轮：全部 PUT，写的是查到的出口 IP
	results, ip := akileReport(akileTestKey, nodes, false)
	if ip != "203.0.113.10" || len(results) != 3 || len(f.puts) != 3 {
		t.Fatalf("first round: ip=%q results=%v puts=%v", ip, results, f.puts)
	}
	if f.puts[0] != `101 {"entry_whitelist":"203.0.113.10"}` {
		t.Errorf("put = %q", f.puts[0])
	}
	for _, k := range f.keys {
		if k != akileTestKey {
			t.Errorf("X-API-Key = %q", k)
		}
	}
	r := akileResultOf(results[0])
	if !r.OK || r.Kind != akileKindUpdated || r.IP != "203.0.113.10" || r.Previous != "198.51.100.1" || r.At == 0 {
		t.Errorf("result = %+v", r)
	}

	// 定时轮、IP 没变：全部跳过，不发 PUT，结果不变
	f.reset()
	before := loadAkileResults()
	results, _ = akileReport(akileTestKey, nodes, true)
	if len(results) != 0 || len(f.puts) != 0 {
		t.Fatalf("timer same ip: results=%v puts=%v", results, f.puts)
	}
	if after := loadAkileResults(); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Errorf("results changed on skip: %v -> %v", before, after)
	}

	// 事件轮、IP 没变：照样 PUT
	results, _ = akileReport(akileTestKey, nodes, false)
	if len(results) != 3 || len(f.puts) != 3 {
		t.Fatalf("event same ip: puts=%v", f.puts)
	}

	// 定时轮、IP 变了：全部 PUT
	f.reset()
	f.setIP("203.0.113.20")
	results, ip = akileReport(akileTestKey, nodes, true)
	if ip != "203.0.113.20" || len(f.puts) != 3 || !strings.Contains(f.puts[2], "203.0.113.20") {
		t.Fatalf("timer new ip: puts=%v", f.puts)
	}

	// 上一次失败（404）的节点：定时轮也要 PUT；成功的跳过；404 不截断后面的
	f.reset()
	f.replies["102"] = akileFakeReply{404, `{"error":"rule not found"}`}
	results, _ = akileReport(akileTestKey, nodes, false)
	if len(f.puts) != 3 {
		t.Fatalf("404 round: puts=%v", f.puts)
	}
	if r := akileResultOf(results[1]); r.OK || r.Kind != akileKindNotFound || r.Error != akileTextNotFound {
		t.Errorf("404 result = %+v", r)
	}
	f.reset()
	delete(f.replies, "102")
	results, _ = akileReport(akileTestKey, nodes, true)
	if len(f.puts) != 1 || !strings.HasPrefix(f.puts[0], "102 ") || len(results) != 1 {
		t.Fatalf("timer after failure: puts=%v results=%v", f.puts, results)
	}

	// changed=false → 已是
	f.reset()
	f.replies["101"] = akileFakeReply{200, `{"data":{"id":101,"entry_whitelist":"203.0.113.20/32","previous":"203.0.113.20/32","changed":false}}`}
	results, _ = akileReport(akileTestKey, nodes[:1], false)
	if r := akileResultOf(results[0]); !r.OK || r.Kind != akileKindUnchanged || r.IP != "203.0.113.20" {
		t.Errorf("unchanged result = %+v", r)
	}
	log, _ := os.ReadFile(ggyAppLogPath)
	for _, want := range []string{
		"AkileCDN 白名单 节点 1（规则 #101）：已更新 198.51.100.1 → 203.0.113.10",
		"AkileCDN 白名单 节点 2（规则 #102）：失败（规则不存在（已删除，或不属于这个 API Key 的账号））",
		"AkileCDN 白名单 节点 1（规则 #101）：已是 203.0.113.20",
		"[Whitelist] ",
	} {
		if !strings.Contains(string(log), want) {
			t.Errorf("log missing %q:\n%s", want, log)
		}
	}
}

func TestAkileReportStops(t *testing.T) {
	f := setupAkileFake(t)
	nodes := akileTestNodes(4)
	akileSaveTestConfig(t, akileConfig{Enabled: true, Key: akileTestKey, Nodes: nodes})

	// 429：本轮剩下的不再发
	f.replies["102"] = akileFakeReply{429, `{"error":"too many requests"}`}
	results, _ := akileReport(akileTestKey, nodes, false)
	if len(f.puts) != 2 || len(results) != 4 {
		t.Fatalf("429: puts=%v results=%d", f.puts, len(results))
	}
	for i, want := range []string{akileKindUpdated, akileKindRateLimited, akileKindRateLimited, akileKindRateLimited} {
		r := akileResultOf(results[i])
		if r.Kind != want || (want == akileKindRateLimited && r.Error != akileTextRateLimited) {
			t.Errorf("429 result %d = %+v", i, r)
		}
	}

	// 401：同一个 Key 后面的也不发；服务端在出错文字里回显完整 Key 也不能漏出去
	f.reset()
	delete(f.replies, "102")
	f.replies["101"] = akileFakeReply{401, `{"error":"invalid key ` + akileTestKey + `"}`}
	results, _ = akileReport(akileTestKey, nodes, false)
	if len(f.puts) != 1 {
		t.Fatalf("401: puts=%v", f.puts)
	}
	for i, entry := range results {
		if r := akileResultOf(entry); r.Kind != akileKindInvalidKey || r.Error != akileTextInvalidKey {
			t.Errorf("401 result %d = %+v", i, r)
		}
	}

	// 定时轮里截断只作用于本来要发的：上一次成功、IP 没变的照旧跳过
	f.reset()
	delete(f.replies, "101")
	akileReport(akileTestKey, nodes, false) // 全部成功
	f.reset()
	f.setIP("203.0.113.30")
	f.replies["101"] = akileFakeReply{403, `{}`}
	results, _ = akileReport(akileTestKey, nodes, true)
	if len(f.puts) != 1 || len(results) != 4 {
		t.Fatalf("403 timer: puts=%v results=%d", f.puts, len(results))
	}

	// 其它错误：服务端的文字（含回显的 Key 也脱敏）
	f.reset()
	f.replies["101"] = akileFakeReply{400, `{"message":"key ` + akileTestKey + ` cannot clear"}`}
	results, _ = akileReport(akileTestKey, nodes[:1], false)
	if r := akileResultOf(results[0]); r.Kind != akileKindFailed || r.Error != "key ak_••••AAAA cannot clear" {
		t.Errorf("400 result = %+v", r)
	}

	assertNoAkileKey(t)
}

func TestAkileReportNoIP(t *testing.T) {
	f := setupAkileFake(t)
	nodes := akileTestNodes(2)
	akileSaveTestConfig(t, akileConfig{Enabled: true, Key: akileTestKey, Nodes: nodes})
	akileReport(akileTestKey, nodes, false)

	f.reset()
	f.setIP("192.168.1.2") // 端点给的不是公网地址
	results, ip := akileReport(akileTestKey, nodes, true)
	if ip != "" || len(f.puts) != 0 || len(results) != 2 {
		t.Fatalf("no ip: ip=%q puts=%v results=%v", ip, f.puts, results)
	}
	for _, entry := range results {
		if r := akileResultOf(entry); r.OK || r.Kind != akileKindFailed || r.Error != akileTextNoIP {
			t.Errorf("no ip result = %+v", r)
		}
	}
	log, _ := os.ReadFile(ggyAppLogPath)
	if !strings.Contains(string(log), "AkileCDN 白名单：查不到本机直连出口 IPv4（") {
		t.Errorf("log = %s", log)
	}

	// 端点连不上
	f.reset()
	akileIPEndpoints = []string{"http://127.0.0.1:1/"}
	results, _ = akileReport(akileTestKey, nodes, false)
	if len(f.puts) != 0 || akileResultOf(results[0]).Error != akileTextNoIP {
		t.Errorf("unreachable: puts=%v results=%v", f.puts, results)
	}
}

// 子命令走一遍（MEOWX_AKILE_STATE 指到临时 JSON）：输出的形状、开关 / 换 Key / 添加立刻报、删除不报、定时轮
func TestAkileMainFlow(t *testing.T) {
	f := setupAkileFake(t)
	run := func(args ...string) map[string]any {
		t.Helper()
		out, err := akileMain(args)
		if err != nil {
			t.Fatalf("akile %v: %v", args, err)
		}
		data, _ := json.Marshal(out)
		var m map[string]any
		_ = json.Unmarshal(data, &m)
		if strings.Contains(string(data), akileTestKey) {
			t.Fatalf("akile %v leaked the key: %s", args, data)
		}
		return m
	}
	fail := func(want string, args ...string) {
		t.Helper()
		if _, err := akileMain(args); err == nil || err.Error() != want {
			t.Errorf("akile %v: err = %v, want %q", args, err, want)
		}
	}

	st := run("status")
	if st["enabled"] != false || st["has_key"] != false || st["key"] != "" || st["max"] != float64(20) || len(st["nodes"].([]any)) != 0 {
		t.Fatalf("status = %v", st)
	}
	fail(akileTextNeedKey, "add", "101", "443", "HK")
	fail(akileTextNeedKey, "rules", "443")
	fail(akileTextBadKey, "setkey", "sk_bad")

	st = run("setkey", "X-API-Key: "+akileTestKey)
	if st["has_key"] != true || st["key"] != "ak_••••AAAA" || len(f.puts) != 0 {
		t.Fatalf("setkey = %v puts=%v", st, f.puts)
	}

	// 查规则：带端口、按端口过滤
	f.rules = `{"data":[{"id":101,"remark":"香港","node_id":5,"listen_port":443,"entry_whitelist":"198.51.100.1/32"},{"id":102,"listen_port":8443}]}`
	st = run("rules", "443")
	rules := st["rules"].([]any)
	if len(rules) != 1 || f.gets[0] != "listen_port=443" {
		t.Fatalf("rules = %v gets=%v", st, f.gets)
	}
	if r := rules[0].(map[string]any); r["id"] != float64(101) || r["summary"] != "香港" || r["node_id"] != "5" ||
		r["listen_port"] != float64(443) || r["entry_whitelist"] != "198.51.100.1/32" {
		t.Errorf("rule = %v", r)
	}
	f.rules = `{"data":{"total":0}}`
	fail(akileTextBadReply, "rules", "443")
	fail("端口不对", "rules", "0")

	// 开关关着：添加不报
	st = run("add", "101", "443", "HK 01", "香港")
	if len(f.puts) != 0 || len(st["nodes"].([]any)) != 1 {
		t.Fatalf("add while off: %v puts=%v", st, f.puts)
	}
	if n := st["nodes"].([]any)[0].(map[string]any); n["name"] != "HK 01" || n["rule_id"] != float64(101) || n["port"] != float64(443) ||
		n["label"] != "香港" || n["result"] != nil {
		t.Errorf("node = %v", n)
	}
	fail("这条规则已经添加过", "add", "101", "8443", "dup")
	run("add", "102", "8443", "JP")

	// 打开：两个都报
	st = run("enable")
	if len(f.puts) != 2 || st["ip"] != "203.0.113.10" || len(st["results"].([]any)) != 2 {
		t.Fatalf("enable: %v puts=%v", st, f.puts)
	}
	res := st["nodes"].([]any)[0].(map[string]any)["result"].(map[string]any)
	if res["ok"] != true || res["kind"] != "updated" || res["ip"] != "203.0.113.10" || res["previous"] != "198.51.100.1" || res["at"].(float64) <= 0 {
		t.Errorf("result = %v", res)
	}

	// 开着时添加：只报新加的
	f.reset()
	run("add", "103", "443", "SG")
	if len(f.puts) != 1 || !strings.HasPrefix(f.puts[0], "103 ") {
		t.Fatalf("add while on: puts=%v", f.puts)
	}

	// 定时轮：IP 没变全部跳过；事件轮全部报
	f.reset()
	st = run("report", "--timer")
	if len(f.puts) != 0 || len(st["results"].([]any)) != 0 || st["ip"] != "203.0.113.10" {
		t.Fatalf("timer report: %v puts=%v", st, f.puts)
	}
	run("report")
	if len(f.puts) != 3 {
		t.Fatalf("event report: puts=%v", f.puts)
	}

	// 换 Key：立刻报全部
	f.reset()
	run("setkey", "ak_TESTkey0000000000BBBB")
	if len(f.puts) != 3 || f.keys[0] != "ak_TESTkey0000000000BBBB" {
		t.Fatalf("setkey report: puts=%v keys=%v", f.puts, f.keys)
	}

	// 删除不报，结果文件里只留还在的
	f.reset()
	st = run("remove", "0")
	if len(f.puts) != 0 || len(st["nodes"].([]any)) != 2 {
		t.Fatalf("remove: %v puts=%v", st, f.puts)
	}
	if _, ok := loadAkileResults()["101"]; ok {
		t.Error("removed node result kept")
	}
	fail("没有这一项", "remove", "5")

	// 关掉不报；关着时 report 也不报
	f.reset()
	run("disable")
	run("report")
	if len(f.puts) != 0 {
		t.Fatalf("disabled: puts=%v", f.puts)
	}

	// 清 Key：开关打开也不报
	run("clearkey")
	st = run("enable")
	if len(f.puts) != 0 || st["has_key"] != false {
		t.Fatalf("enable without key: %v puts=%v", st, f.puts)
	}

	// 状态文件的形状（飞牛读它）
	var state map[string]any
	data, _ := os.ReadFile(os.Getenv("MEOWX_AKILE_STATE"))
	_ = json.Unmarshal(data, &state)
	if state["enabled"] != true || state["key"] != "" || len(state["nodes"].([]any)) != 2 {
		t.Errorf("state file = %s", data)
	}
	assertNoAkileKey(t)
}

// 结果文件与日志里都不能出现完整 Key
func assertNoAkileKey(t *testing.T) {
	t.Helper()
	for _, path := range []string{akileResultPath, ggyAppLogPath} {
		data, _ := os.ReadFile(path)
		if strings.Contains(string(data), akileTestKey) || strings.Contains(string(data), "ak_TESTkey0000000000BBBB") {
			t.Errorf("%s contains the full key:\n%s", path, data)
		}
	}
}
