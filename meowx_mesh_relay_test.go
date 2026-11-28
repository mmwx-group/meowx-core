package main

// 喵窝设备中继（meowx_mesh_relay.go）的单元测试与一次完整的 tick：
//   - 纯函数：路径判定、活动过滤、与上次比较、desired 对比、endpoints 拼接、版本比较；
//   - tick：假主控（httptest，加密 RPC 用测试里现生成的许可证 / 主控密钥，走真的 panelsecure 加解密）
//     + 假 tailscaled（unix socket 上的 LocalAPI）+ 假 tailscale 命令行（shell 脚本，set 的参数写进文件、LocalAPI 照它回）。
// 跑法：go test -tags with_gvisor -run 'Relay|MeshTick|PeerPath' .

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/panelsecure"
	"golang.org/x/crypto/chacha20poly1305"
)

var relayT0 = time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

func TestPeerPathOf(t *testing.T) {
	hs := relayT0.Add(-time.Minute)
	cases := []struct {
		p    tsPeerStatus
		ok   bool
		path string
		via  string
	}{
		// 设备中继优先于直连与中继服务器
		{tsPeerStatus{TailscaleIPs: []string{"fd7a:115c:a1e0::5", "100.64.0.21"}, PeerRelay: "203.0.113.7:40000:vni:12345", CurAddr: "1.2.3.4:41641", Relay: "meowx-7"}, true, "peer_relay", "203.0.113.7:40000:vni:12345"},
		{tsPeerStatus{TailscaleIPs: []string{"100.64.0.30"}, CurAddr: "198.51.100.9:41641", Relay: "meowx-7"}, true, "direct", "198.51.100.9:41641"},
		{tsPeerStatus{TailscaleIPs: []string{"100.64.0.31"}, Relay: "meowx-7-alt"}, true, "derp", "meowx-7-alt"},
		{tsPeerStatus{TailscaleIPs: []string{"100.64.0.32"}}, false, "", ""},
		// 没有喵窝 IPv4 不报
		{tsPeerStatus{TailscaleIPs: []string{"fd7a:115c:a1e0::9"}, CurAddr: "1.2.3.4:1"}, false, "", ""},
	}
	for i, c := range cases {
		c.p.LastHandshake = hs
		got, ok := peerPathOf(&c.p)
		if ok != c.ok {
			t.Fatalf("#%d ok=%v", i, ok)
		}
		if !ok {
			continue
		}
		via := got.PeerRelay + got.Endpoint + got.DERPRegion
		if got.Path != c.path || via != c.via || got.LastHandshake != "2026-11-28T09:59:00Z" {
			t.Fatalf("#%d %+v", i, got)
		}
	}
	// 没握过手：不带 last_handshake
	p, _ := peerPathOf(&tsPeerStatus{TailscaleIPs: []string{"100.64.0.31"}, Relay: "meowx-1"})
	if raw, _ := json.Marshal(p); strings.Contains(string(raw), "last_handshake") {
		t.Fatalf("%s", raw)
	}
}

func TestActivePeerPaths(t *testing.T) {
	st := &tsStatusJSON{Peer: map[string]*tsPeerStatus{
		"a": {TailscaleIPs: []string{"100.64.0.2"}, Relay: "meowx-1", LastHandshake: relayT0.Add(-4 * time.Minute)},                // 握手在 5 分钟内
		"b": {TailscaleIPs: []string{"100.64.0.3"}, Relay: "meowx-1", LastHandshake: relayT0.Add(-10 * time.Minute), RxBytes: 100}, // 字节比上次多
		"c": {TailscaleIPs: []string{"100.64.0.4"}, Relay: "meowx-1", LastHandshake: relayT0.Add(-10 * time.Minute), RxBytes: 50},  // 字节没变
		"d": {TailscaleIPs: []string{"100.64.0.5"}, Relay: "meowx-1"},                                                              // 从没往来
		"e": {TailscaleIPs: []string{"100.64.0.6"}, Relay: "meowx-1", LastHandshake: relayT0.Add(-10 * time.Minute), TxBytes: 9},   // 新出现、有字节
		"f": {TailscaleIPs: []string{"100.64.0.7"}, LastHandshake: relayT0},                                                        // 有活动但没有路径
	}}
	prev := map[string][2]int64{"100.64.0.3": {10, 0}, "100.64.0.4": {50, 0}}
	got := activePeerPaths(st, prev, relayT0)
	var ips []string
	for _, p := range got {
		ips = append(ips, p.IP)
	}
	if strings.Join(ips, ",") != "100.64.0.2,100.64.0.3,100.64.0.6" {
		t.Fatalf("%v", ips)
	}
}

func TestPathsDue(t *testing.T) {
	one := []meshPeerPath{{IP: "100.64.0.2", Path: "derp", DERPRegion: "meowx-1"}}
	cases := []struct {
		name  string
		paths []meshPeerPath
		ts    meshTickState
		at    time.Duration // now - PathsAt
		want  bool
	}{
		{"第一次", one, meshTickState{}, 0, true},
		{"一分钟内没变", one, meshTickState{PathsAt: 1, PathsSig: pathsSignature(one)}, 30 * time.Second, false},
		{"到点", one, meshTickState{PathsAt: 1, PathsSig: pathsSignature(one)}, 60 * time.Second, true},
		{"变了", one, meshTickState{PathsAt: 1, PathsSig: "x"}, 6 * time.Second, true},
		{"变了但不到 5 秒", one, meshTickState{PathsAt: 1, PathsSig: "x"}, 3 * time.Second, false},
		{"从有到无", nil, meshTickState{PathsAt: 1, PathsNonEmpty: true}, 60 * time.Second, true},
		{"一直没有", nil, meshTickState{PathsAt: 1}, 600 * time.Second, false},
		{"接口没有", one, meshTickState{PathsOffUntil: relayT0.Add(time.Hour).Unix()}, 0, false},
	}
	for _, c := range cases {
		ts := c.ts
		if ts.PathsAt == 1 {
			ts.PathsAt = relayT0.Add(-c.at).Unix()
		}
		if got, why := pathsDue(c.paths, &ts, relayT0); got != c.want {
			t.Errorf("%s: %v（%s）", c.name, got, why)
		}
	}
}

func TestRelayReconcile(t *testing.T) {
	d := relayDesired{Enabled: true, Port: 40000, StaticEndpoints: []string{"203.0.113.7:40000", "[2001:db8::7]:40000", "bad"}, DDNSHost: "home.example.com"}
	eps := relayEndpoints(d, []string{"198.51.100.9", "2001:db8::9", "203.0.113.7"})
	want := "203.0.113.7:40000,[2001:db8::7]:40000,198.51.100.9:40000,[2001:db8::9]:40000"
	if strings.Join(eps, ",") != want {
		t.Fatalf("%v", eps)
	}
	if args := relaySetArgs(d, eps); strings.Join(args, " ") != "set --relay-server-port=40000 --relay-server-static-endpoints="+want {
		t.Fatalf("%v", args)
	}
	if args := relaySetArgs(relayDesired{}, nil); strings.Join(args, " ") != "set --relay-server-port= --relay-server-static-endpoints=" {
		t.Fatalf("%v", args)
	}
	// 顺序不同、写法不同（IPv4 映射）的地址算一样
	same := relayLocal{Enabled: true, Port: 40000, Endpoints: []string{"[2001:db8::9]:40000", "198.51.100.9:40000", "[::ffff:203.0.113.7]:40000", "[2001:db8::7]:40000"}}
	if relayNeedsSet(d, eps, same) {
		t.Fatal("一致的不该 set")
	}
	for name, l := range map[string]relayLocal{
		"没开":    {Endpoints: []string{}},
		"端口不同":  {Enabled: true, Port: 40001, Endpoints: same.Endpoints},
		"地址少一个": {Enabled: true, Port: 40000, Endpoints: same.Endpoints[:3]},
	} {
		if !relayNeedsSet(d, eps, l) {
			t.Errorf("%s：该 set", name)
		}
	}
	off := relayDesired{Port: 40000}
	if relayNeedsSet(off, nil, relayLocal{}) || !relayNeedsSet(off, nil, relayLocal{Enabled: true, Port: 40000}) || !relayNeedsSet(off, nil, relayLocal{Endpoints: []string{"1.2.3.4:5"}}) {
		t.Fatal("关闭的对比不对")
	}
}

func TestRelayVersionAndAddrs(t *testing.T) {
	for v, ok := range map[string]bool{"1.86.0": true, "1.104.5": true, "1.104.5-t1234abcd-gdeadbeef": true, "1.84.3": false, "1.9": false, "": false, "v1.90.1": true, "abc": false} {
		if versionAtLeast(v, relayMinVersion) != ok {
			t.Errorf("%q", v)
		}
	}
	for a, ok := range map[string]bool{"203.0.113.7": true, "2001:db8::1": true, "192.168.1.2": false, "10.0.0.1": false, "100.64.0.1": false, "198.18.0.9": false, "fd7a:115c:a1e0::1": false, "::1": false, "fe80::1": false} {
		if ddnsUsable(mustAddr(t, a)) != ok {
			t.Errorf("%s", a)
		}
	}
	srv := &relayServerStatus{Sessions: []relaySessionJSON{{VNI: 7, Client1: relayClientInfo{Endpoint: "198.51.100.2:50123", ShortDisco: "d:1a2b", PacketsTx: 3, BytesTx: 900}}}}
	raw, _ := json.Marshal(relaySessionsForReport(srv))
	if string(raw) != `[{"clients":[{"bytes_tx":900,"endpoint":"198.51.100.2:50123","packets_tx":3,"short_disco":"d:1a2b"},{"bytes_tx":0,"endpoint":"","packets_tx":0,"short_disco":""}],"vni":7}]` {
		t.Fatalf("%s", raw)
	}
	if relayErrorText(400, "invalid_port", "端口要在 1024–65535") != "端口要在 1024–65535" || relayErrorText(409, "device_relay_disabled", "") != "管理员关闭了设备中继" {
		t.Fatal("错误文字")
	}
	if !(&relayError{status: 404, code: "not_found"}).routeMissing() || (&relayError{status: 404, code: "device_not_found"}).routeMissing() {
		t.Fatal("404 区分")
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// ---------- 一次完整的 tick ----------

type fakeMaster struct {
	t      *testing.T
	srv    *httptest.Server
	priv   *ecdh.PrivateKey
	mu     sync.Mutex
	calls  []map[string]any // 每次 RPC 的内层（不含 token / nonce）
	relay  relayDesired     // 主控存的期望配置
	paths  int              // 路径接口回的状态码（0 = 正常）
	report int
}

func newFakeMaster(t *testing.T) *fakeMaster {
	lpub, lpriv, _ := ed25519.GenerateKey(rand.Reader)
	saved := panelsecure.LicenseKey
	panelsecure.LicenseKey = base64.StdEncoding.EncodeToString(lpub)
	t.Cleanup(func() { panelsecure.LicenseKey = saved })
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	m := &fakeMaster{t: t, priv: priv}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/secure/cert":
			pub := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
			exp := time.Now().Add(time.Hour).Unix()
			sig := ed25519.Sign(lpriv, panelsecure.CertMessage(pub, "127.0.0.1", exp))
			_ = json.NewEncoder(w).Encode(panelsecure.Cert{MasterPub: pub, Domain: "127.0.0.1", ExpireUnix: exp, Sig: base64.StdEncoding.EncodeToString(sig)})
		case "/api/secure/rpc":
			m.rpc(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *fakeMaster) rpc(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	ePub, err := ecdh.X25519().NewPublicKey(body[:32])
	if err != nil {
		w.WriteHeader(400)
		return
	}
	shared, _ := m.priv.ECDH(ePub)
	salt := append(append([]byte{}, body[:32]...), m.priv.PublicKey().Bytes()...)
	c2s, _ := chacha20poly1305.New(panelsecure.HKDF(shared, salt, panelsecure.InfoRPCClientToServer))
	plain, err := c2s.Open(nil, body[32:44], body[44:], nil)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	var inner map[string]any
	_ = json.Unmarshal(plain, &inner)
	delete(inner, "token")
	delete(inner, "nonce")
	delete(inner, "ts")
	status, resp := m.route(inner)
	out, _ := json.Marshal(resp)
	s2c, _ := chacha20poly1305.New(panelsecure.HKDF(shared, salt, panelsecure.InfoRPCServerToClient))
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(status)
	_, _ = w.Write(append(nonce, s2c.Seal(nil, nonce, out, nil)...))
}

func (m *fakeMaster) route(inner map[string]any) (int, any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, inner)
	switch fmt.Sprint(inner["method"], " ", inner["path"]) {
	case "POST /user/mesh/paths":
		if m.paths != 0 {
			return m.paths, map[string]any{"error": "not_found", "message": ""}
		}
		return 200, map[string]any{"success": true}
	case "POST /user/mesh/relay/report":
		if m.report != 0 {
			return m.report, map[string]any{"error": "rate_limited", "message": "上报太频繁"}
		}
		state := "disabled"
		if m.relay.Enabled {
			state = "pending"
			if inner["enabled"] == true && int(inner["port"].(float64)) == m.relay.Port {
				state = "active"
			}
		}
		return 200, map[string]any{"desired": m.relay, "state": state, "message": ""}
	case "GET /user/mesh/relay?device_id=15":
		return 200, map[string]any{"device_id": 15, "enabled": m.relay.Enabled, "state": "active", "capable": true}
	case "PUT /user/mesh/devices/15/relay":
		if p, _ := inner["port"].(float64); p != 0 && p < 1024 {
			return 400, map[string]any{"error": "invalid_port", "message": "端口要在 1024–65535 之间"}
		}
		return 200, map[string]any{"device_id": 15, "state": "pending"}
	}
	return 404, map[string]any{"error": "not_found"}
}

func (m *fakeMaster) take(path string) []map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out, rest []map[string]any
	for _, c := range m.calls {
		if c["path"] == path {
			out = append(out, c)
		} else {
			rest = append(rest, c)
		}
	}
	m.calls = rest
	return out
}

// fakeTailscaled：LocalAPI（status / prefs / debug-peer-relay-sessions），中继端口与静态地址照假命令行最后一次 set 的参数
type fakeTailscaled struct {
	mu        sync.Mutex
	status    tsStatusJSON
	setLog    string
	noRelay   bool
	sessions  []relaySessionJSON
	sock, cli string
}

func newFakeTailscaled(t *testing.T) *fakeTailscaled {
	if runtime.GOOS == "windows" {
		t.Skip("要 unix socket 与 sh")
	}
	dir, err := os.MkdirTemp("", "mxts")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &fakeTailscaled{sock: filepath.Join(dir, "ts.sock"), cli: filepath.Join(dir, "tailscale"), setLog: filepath.Join(dir, "set.log")}
	script := `#!/bin/sh
case "$1" in --socket=*) shift ;; esac
case "$1" in
version) echo 1.104.5; echo "  tailscale commit: test" ;;
set) shift; echo "$*" >> '` + f.setLog + `' ;;
*) echo "unknown $1" >&2; exit 1 ;;
esac
`
	if err := os.WriteFile(f.cli, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", f.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(f.serve)}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return f
}

// lastSet：最后一次 set 的端口（nil = 关）与静态地址
func (f *fakeTailscaled) lastSet() (*uint16, []string) {
	data, _ := os.ReadFile(f.setLog)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	last := lines[len(lines)-1]
	var port *uint16
	var eps []string
	for _, a := range strings.Fields(last) {
		if v, ok := strings.CutPrefix(a, "--relay-server-port="); ok && v != "" {
			var p uint16
			fmt.Sscan(v, &p)
			port = &p
		}
		if v, ok := strings.CutPrefix(a, "--relay-server-static-endpoints="); ok && v != "" {
			eps = strings.Split(v, ",")
		}
	}
	return port, eps
}

func (f *fakeTailscaled) setCount() int {
	data, _ := os.ReadFile(f.setLog)
	if len(strings.TrimSpace(string(data))) == 0 {
		return 0
	}
	return len(strings.Split(strings.TrimSpace(string(data)), "\n"))
}

func (f *fakeTailscaled) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Host != "local-tailscaled.sock" {
		http.Error(w, "bad host", 403)
		return
	}
	port, eps := f.lastSet()
	switch r.URL.Path {
	case "/localapi/v0/status":
		_ = json.NewEncoder(w).Encode(f.status)
	case "/localapi/v0/prefs":
		_ = json.NewEncoder(w).Encode(map[string]any{"RelayServerPort": port, "RelayServerStaticEndpoints": eps})
	case "/localapi/v0/debug-peer-relay-sessions":
		if f.noRelay {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(relayServerStatus{UDPPort: port, Sessions: f.sessions})
	default:
		http.NotFound(w, r)
	}
}

func TestMeshTick(t *testing.T) {
	master := newFakeMaster(t)
	ts := newFakeTailscaled(t)
	dir := t.TempDir()
	saved, savedLookup := panelStatePath, ddnsLookup
	t.Cleanup(func() { panelStatePath, ddnsLookup = saved, savedLookup })
	panelStatePath = filepath.Join(dir, "panel.json")
	_ = os.WriteFile(panelStatePath, []byte(fmt.Sprintf(`{"base":%q,"token":"tok"}`, master.srv.URL)), 0o600)
	lookups := 0
	ddnsLookup = func(host string) ([]string, error) {
		lookups++
		if host != "home.example.com" {
			return nil, fmt.Errorf("no such host")
		}
		return []string{"198.51.100.9", "2001:db8::9"}, nil
	}

	now := relayT0
	var slept time.Duration
	env := &tickEnv{cli: ts.cli, sock: ts.sock, now: func() time.Time { return now }, sleep: func(d time.Duration) { slept += d; now = now.Add(d) }}
	ts.status = tsStatusJSON{Version: "1.104.5-t1", BackendState: "Running", Self: &tsPeerStatus{ID: "15", TailscaleIPs: []string{"100.64.0.9"}},
		Peer: map[string]*tsPeerStatus{
			"a": {TailscaleIPs: []string{"100.64.0.21"}, PeerRelay: "203.0.113.7:40000:vni:12345", LastHandshake: now.Add(-time.Minute), RxBytes: 4200, TxBytes: 980},
			"b": {TailscaleIPs: []string{"100.64.0.31"}, Relay: "meowx-7-alt", LastHandshake: now.Add(-time.Hour)},
		}}
	master.relay = relayDesired{Enabled: true, Port: 40000, StaticEndpoints: []string{"203.0.113.7:40000"}, DDNSHost: "home.example.com"}

	// 第一轮：报路径（只有 a 有活动）→ 报中继（还没开）→ tailscale set → 补报（active）→ 放行 40000
	out := runMeshTick(env, dir, false, "")
	if fw := out["firewall"].(map[string]any); fw["relay_port"] != 40000 || out["state"] != "active" || out["error"] != "" {
		t.Fatalf("第一轮：%+v", out)
	}
	paths := master.take("/user/mesh/paths")
	if len(paths) != 1 {
		t.Fatalf("路径上报 %d 次", len(paths))
	}
	if raw, _ := json.Marshal(paths[0]["peers"]); string(raw) != `[{"ip":"100.64.0.21","last_handshake":"2026-11-28T09:59:00Z","path":"peer_relay","peer_relay":"203.0.113.7:40000:vni:12345","rx_bytes":4200,"tx_bytes":980}]` || paths[0]["device_id"] != float64(15) {
		t.Fatalf("路径：%s %v", raw, paths[0]["device_id"])
	}
	reports := master.take("/user/mesh/relay/report")
	if len(reports) != 2 || reports[0]["enabled"] != false || reports[1]["enabled"] != true || reports[1]["port"] != float64(40000) || reports[1]["tailscale_version"] != "1.104.5" {
		t.Fatalf("中继上报：%+v", reports)
	}
	if raw, _ := json.Marshal(reports[1]["endpoints"]); string(raw) != `["203.0.113.7:40000","198.51.100.9:40000","[2001:db8::9]:40000"]` {
		t.Fatalf("上报的 endpoints：%s", raw)
	}
	if port, eps := ts.lastSet(); port == nil || *port != 40000 || strings.Join(eps, ",") != "203.0.113.7:40000,198.51.100.9:40000,[2001:db8::9]:40000" {
		t.Fatalf("set：%v %v", port, eps)
	}
	if slept != relayPostSpacing {
		t.Fatalf("两次上报之间要隔 5 秒：%v", slept)
	}

	// 第二轮（一分钟后）：a 没新流量、握手也过了 5 分钟 → 报一次空列表；中继照常报、不用 set；DDNS 不到 5 分钟不重新解析
	now = now.Add(5 * time.Minute)
	out = runMeshTick(env, dir, false, "")
	if paths = master.take("/user/mesh/paths"); len(paths) != 1 || len(paths[0]["peers"].([]any)) != 0 {
		t.Fatalf("从有到无要报一次空列表：%+v", paths)
	}
	if reports = master.take("/user/mesh/relay/report"); len(reports) != 1 || ts.setCount() != 1 || out["firewall"].(map[string]any)["relay_port"] != 40000 {
		t.Fatalf("第二轮：%+v %d %+v", reports, ts.setCount(), out)
	}
	if lookups != 2 { // 第一轮解析一次；第二轮离上次 5 分 5 秒，又解析一次
		t.Fatalf("DDNS 解析 %d 次", lookups)
	}

	// 第三轮：还是没有活动对端 → 不发；主控接口 404 时停一小时
	now = now.Add(time.Minute)
	runMeshTick(env, dir, false, "")
	if paths = master.take("/user/mesh/paths"); len(paths) != 0 {
		t.Fatalf("一直没有活动对端不该再报：%+v", paths)
	}
	ts.status.Peer["b"].RxBytes = 10 // b 有了新流量
	master.paths = 404
	now = now.Add(time.Minute)
	if out = runMeshTick(env, dir, false, ""); out["paths"].(map[string]any)["error"] == nil {
		t.Fatalf("404：%+v", out["paths"])
	}
	master.take("/user/mesh/paths")
	now = now.Add(time.Minute)
	runMeshTick(env, dir, false, "")
	if paths = master.take("/user/mesh/paths"); len(paths) != 0 {
		t.Fatal("404 之后一小时内不该再调")
	}
	master.take("/user/mesh/relay/report")

	// 管理员关掉：desired.enabled=false → 两个参数都给空串、防火墙撤掉；上次防火墙的错误随上报带上
	master.relay = relayDesired{Port: 40000}
	now = now.Add(time.Minute)
	out = runMeshTick(env, dir, false, "fw4 reload 失败")
	if port, eps := ts.lastSet(); port != nil || eps != nil || out["firewall"].(map[string]any)["relay_port"] != nil {
		t.Fatalf("关闭：%v %v %+v", port, eps, out)
	}
	reports = master.take("/user/mesh/relay/report")
	if len(reports) != 2 || reports[0]["error"] != "fw4 reload 失败" || reports[1]["enabled"] != false {
		t.Fatalf("关闭的上报：%+v", reports)
	}

	// 一分钟内再跑（页面触发）：不重复上报中继；--force 才报
	now = now.Add(10 * time.Second)
	runMeshTick(env, dir, false, "")
	if n := len(master.take("/user/mesh/relay/report")); n != 0 {
		t.Fatalf("不到一分钟不该报：%d", n)
	}
	now = now.Add(10 * time.Second)
	runMeshTick(env, dir, true, "")
	if n := len(master.take("/user/mesh/relay/report")); n != 1 {
		t.Fatalf("--force 要报：%d", n)
	}

	// tailscaled 没编进中继服务器：不 set，error 写明，照常上报版本
	master.relay = relayDesired{Enabled: true, Port: 40000, StaticEndpoints: []string{}}
	ts.noRelay = true
	before := ts.setCount()
	now = now.Add(time.Minute)
	out = runMeshTick(env, dir, false, "")
	if ts.setCount() != before || !strings.Contains(fmt.Sprint(out["error"]), "没有中继服务器功能") || out["relay_supported"] != false {
		t.Fatalf("不支持中继：%+v", out)
	}
	if reports = master.take("/user/mesh/relay/report"); len(reports) != 1 || !strings.Contains(fmt.Sprint(reports[0]["error"]), "没有中继服务器功能") {
		t.Fatalf("不支持时的上报：%+v", reports)
	}
	ts.noRelay = false

	// tailscaled 不在运行：防火墙照上次的（不来回开撤），不调主控
	ts.status.BackendState = "Stopped"
	now = now.Add(time.Minute)
	out = runMeshTick(env, dir, false, "")
	if len(master.take("/user/mesh/relay/report")) != 0 || !strings.Contains(fmt.Sprint(out["error"]), "不在运行") {
		t.Fatalf("没在跑：%+v", out)
	}
}

// relay get / set / paths 子命令：错误码带回（error_code / http_status 由 panelMain 输出）
func TestMeshRelayCommands(t *testing.T) {
	master := newFakeMaster(t)
	dir := t.TempDir()
	saved := panelStatePath
	t.Cleanup(func() { panelStatePath = saved })
	panelStatePath = filepath.Join(dir, "panel.json")
	_ = os.WriteFile(panelStatePath, []byte(fmt.Sprintf(`{"base":%q,"token":"tok"}`, master.srv.URL)), 0o600)

	obj, err := meshMain([]string{"relay", "get", "15"})
	if err != nil || obj.(map[string]any)["capable"] != true {
		t.Fatalf("get：%v %v", obj, err)
	}
	if _, err := meshMain([]string{"relay", "set", "15", `{"enabled":true,"port":80,"bogus":1}`}); err == nil {
		t.Fatal("端口不对要报错")
	} else if re, ok := err.(*relayError); !ok || re.ErrorCode() != "invalid_port" || re.HTTPStatus() != 400 || re.Error() != "端口要在 1024–65535 之间" {
		t.Fatalf("%#v", err)
	}
	calls := master.take("/user/mesh/devices/15/relay")
	if len(calls) != 1 || calls[0]["bogus"] != nil {
		t.Fatalf("多余字段不该转给主控：%+v", calls)
	}
	if _, err := meshMain([]string{"relay", "set", "15", `{"port":40000}`}); err == nil {
		t.Fatal("缺 enabled 要报错")
	}
	if _, err := meshMain([]string{"paths", "--device", "15"}); err == nil {
		t.Fatal("假主控没有 GET paths，应 404")
	} else if re, ok := err.(*relayError); !ok || !re.routeMissing() {
		t.Fatalf("%#v", err)
	}
}
