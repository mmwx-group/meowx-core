package entryoverride

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// 跑法：go test -tags with_gvisor ./component/entryoverride/

func reset(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "entry-overrides.json")
	if err := Load(path); err != nil {
		t.Fatal(err)
	}
	now = time.Now
	SetServerSource(nil)
	SetTrackerCloser(nil)
	registry.mu.Lock()
	registry.items = map[*tracked]struct{}{}
	registry.mu.Unlock()
	t.Cleanup(func() { now = time.Now; SetServerSource(nil); SetTrackerCloser(nil) })
	return path
}

func ips(list ...string) []netip.Addr {
	out := make([]netip.Addr, len(list))
	for i, s := range list {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func sameSet(got []netip.Addr, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	m := map[string]bool{}
	for _, ip := range got {
		m[ip.String()] = true
	}
	for _, w := range want {
		if !m[w] {
			return false
		}
	}
	return true
}

const src = "https://panel.example.com"

func TestRevOrdering(t *testing.T) {
	reset(t)
	r := Apply(src, ScopeUser, OriginPush, Update{Server: "HK-Entry.Example.com.", IPs: ips("203.0.113.10"), Rev: 100, ChainID: 7})
	if !r.Applied || r.Server != "hk-entry.example.com" || r.Rev != 100 {
		t.Fatalf("first apply: %+v", r)
	}
	if r := Apply(src, ScopeUser, OriginPush, Update{Server: "hk-entry.example.com", IPs: ips("203.0.113.99"), Rev: 50}); r.Applied || r.Rev != 100 {
		t.Fatalf("older rev must be ignored: %+v", r)
	}
	if r := Apply(src, ScopeUser, OriginPush, Update{Server: "hk-entry.example.com", IPs: ips("203.0.113.10"), Rev: 100}); r.Applied {
		t.Fatalf("equal rev must not apply: %+v", r)
	}
	if got := Lookup("hk-entry.example.com", 0, 0); !sameSet(got, "203.0.113.10") {
		t.Fatalf("lookup = %v", got)
	}
	Apply(src, ScopeUser, OriginPush, Update{Server: "hk-entry.example.com", IPs: ips("203.0.113.11", "203.0.113.12"), Rev: 200})
	if got := Lookup("HK-ENTRY.example.com", 0, 0); !sameSet(got, "203.0.113.11", "203.0.113.12") {
		t.Fatalf("lookup after newer rev = %v", got)
	}
	// 撤销：空集合 = 回到 DNS；之后更旧的推送不能把它加回来
	Apply(src, ScopeUser, OriginPush, Update{Server: "hk-entry.example.com", Rev: 300})
	if got := Lookup("hk-entry.example.com", 0, 0); got != nil {
		t.Fatalf("revoked entry still used: %v", got)
	}
	if r := Apply(src, ScopeUser, OriginPush, Update{Server: "hk-entry.example.com", IPs: ips("203.0.113.10"), Rev: 250}); r.Applied {
		t.Fatal("stale push re-added a revoked entry")
	}
	if len(List()) != 0 {
		t.Fatalf("revoked entry listed: %+v", List())
	}
}

func TestLookupRotationAndFamily(t *testing.T) {
	reset(t)
	Apply(src, ScopeUser, OriginPush, Update{Server: "e.example.com", IPs: ips("192.0.2.1", "192.0.2.2", "2001:db8::1"), Rev: 1})
	firsts := map[string]int{}
	for i := 0; i < 6; i++ {
		got := Lookup("e.example.com", 0, 0)
		if len(got) != 3 {
			t.Fatalf("lookup = %v", got)
		}
		firsts[got[0].String()]++
	}
	if len(firsts) != 3 {
		t.Fatalf("rotation should start at each IP in turn: %v", firsts)
	}
	if got := Lookup("e.example.com", 0, 6); !sameSet(got, "2001:db8::1") {
		t.Fatalf("v6 only = %v", got)
	}
	if got := Lookup("e.example.com", 0, 4); !sameSet(got, "192.0.2.1", "192.0.2.2") {
		t.Fatalf("v4 only = %v", got)
	}
	// IP 作键（没设链域名时 server 是入口组第一台的地址）
	Apply(src, ScopeUser, OriginPush, Update{Server: "[2001:DB8::20]", IPs: ips("2001:db8::21"), Rev: 1})
	if got := Lookup("2001:db8::20", 0, 0); !sameSet(got, "2001:db8::21") {
		t.Fatalf("ip key lookup = %v", got)
	}
}

func TestKeyRestriction(t *testing.T) {
	reset(t)
	servers := []Server{{Host: "other.example.com"}}
	var mu sync.Mutex
	SetServerSource(func() []Server { mu.Lock(); defer mu.Unlock(); return servers })
	Apply(src, ScopeUser, OriginPush, Update{Server: "hk-entry.example.com", IPs: ips("203.0.113.10"), Rev: 1})
	if got := Lookup("hk-entry.example.com", 0, 0); got != nil {
		t.Fatalf("key not in config must be ignored, got %v", got)
	}
	if l := List(); len(l) != 1 || l[0].Active {
		t.Fatalf("list should show the entry as inactive: %+v", l)
	}
	mu.Lock()
	servers = []Server{{Host: "HK-Entry.Example.COM"}}
	mu.Unlock()
	InvalidateServers()
	if got := Lookup("hk-entry.example.com", 0, 0); !sameSet(got, "203.0.113.10") {
		t.Fatalf("lookup after config reload = %v", got)
	}
	if l := List(); !l[0].Active {
		t.Fatalf("entry should be active now: %+v", l)
	}
}

func TestSnapshotReady(t *testing.T) {
	reset(t)
	other := "https://other.example.com"
	Apply(src, ScopeUser, OriginPush, Update{Server: "a.example.com", IPs: ips("192.0.2.1"), Rev: 1})
	Apply(src, ScopeUser, OriginPush, Update{Server: "b.example.com", IPs: ips("192.0.2.2"), Rev: 1})
	Apply(other, ScopeUser, OriginPush, Update{Server: "c.example.com", IPs: ips("192.0.2.3"), Rev: 1})
	asOf := time.Now().Add(time.Millisecond)
	time.Sleep(2 * time.Millisecond)

	// ready:false：只合并，不清理
	ApplySnapshot(src, ScopeUser, OriginSnapshot, false, asOf, []Update{{Server: "a.example.com", IPs: ips("192.0.2.1"), Rev: 1}})
	if Lookup("b.example.com", 0, 0) == nil {
		t.Fatal("ready:false snapshot must not clear entries")
	}
	// ready:true：这个主控来的、快照里没有的清掉；别的主控的不动
	res := ApplySnapshot(src, ScopeUser, OriginSnapshot, true, time.Now(), []Update{{Server: "a.example.com", IPs: ips("192.0.2.9"), Rev: 2}})
	if len(res) != 1 || !res[0].Applied || res[0].Rev != 2 {
		t.Fatalf("snapshot results = %+v", res)
	}
	if Lookup("b.example.com", 0, 0) != nil {
		t.Fatal("ready:true snapshot must clear unlisted keys of this source")
	}
	if got := Lookup("a.example.com", 0, 0); !sameSet(got, "192.0.2.9") {
		t.Fatalf("a = %v", got)
	}
	if Lookup("c.example.com", 0, 0) == nil {
		t.Fatal("entries of another panel must survive")
	}
	// 拉取请求在路上时推送新加的键：asOf 之后确认过的不清
	reqStart := time.Now()
	time.Sleep(2 * time.Millisecond)
	Apply(src, ScopeUser, OriginPush, Update{Server: "d.example.com", IPs: ips("192.0.2.4"), Rev: 5})
	ApplySnapshot(src, ScopeUser, OriginPull, true, reqStart, []Update{{Server: "a.example.com", IPs: ips("192.0.2.9"), Rev: 2}})
	if Lookup("d.example.com", 0, 0) == nil {
		t.Fatal("entry pushed after the pull request started must not be cleared by its (older) snapshot")
	}
}

func TestSnapshotRTScopes(t *testing.T) {
	reset(t)
	both := Update{Server: "shared.example.com", IPs: ips("192.0.2.1"), Rev: 1}
	only1 := Update{Server: "one.example.com", IPs: ips("192.0.2.2"), Rev: 1}
	only2 := Update{Server: "two.example.com", IPs: ips("192.0.2.3"), Rev: 1}
	ApplySnapshot(src, "rt:1", OriginSnapshot, true, time.Now(), []Update{both, only1})
	ApplySnapshot(src, "rt:2", OriginSnapshot, true, time.Now(), []Update{both, only2})
	if Lookup("one.example.com", 0, 0) == nil || Lookup("two.example.com", 0, 0) == nil {
		t.Fatal("two rt channels of the same panel must not clear each other's entries")
	}
	time.Sleep(2 * time.Millisecond)
	// rt:1 那份订阅不再用 shared 与 one：one 只有它认领，清掉；shared 还有 rt:2 认领，留着
	ApplySnapshot(src, "rt:1", OriginSnapshot, true, time.Now(), nil)
	if Lookup("one.example.com", 0, 0) != nil {
		t.Fatal("entry claimed only by rt:1 should be cleared")
	}
	if Lookup("shared.example.com", 0, 0) == nil {
		t.Fatal("entry still claimed by rt:2 must survive")
	}
	// 登录态的快照是这个用户全部的链：清这个主控来源的全部
	time.Sleep(2 * time.Millisecond)
	ApplySnapshot(src, ScopeUser, OriginSnapshot, true, time.Now(), nil)
	if len(List()) != 0 {
		t.Fatalf("user snapshot should clear all entries of this source: %+v", List())
	}
}

func TestExpiry(t *testing.T) {
	path := reset(t)
	Apply(src, ScopeUser, OriginPush, Update{Server: "old.example.com", IPs: ips("192.0.2.1"), Rev: 1})
	Apply(src, ScopeUser, OriginPush, Update{Server: "fresh.example.com", IPs: ips("192.0.2.2"), Rev: 1})
	base := time.Now()
	now = func() time.Time { return base.Add(6 * 24 * time.Hour) }
	// 6 天后 fresh 被快照确认（rev 不变也算确认）
	ApplySnapshot(src, ScopeUser, OriginSnapshot, false, now(), []Update{{Server: "fresh.example.com", IPs: ips("192.0.2.2"), Rev: 1}})
	now = func() time.Time { return base.Add(7*24*time.Hour + time.Minute) }
	if Lookup("old.example.com", 0, 0) != nil {
		t.Fatal("entry not confirmed for 7 days must expire")
	}
	if Lookup("fresh.example.com", 0, 0) == nil {
		t.Fatal("recently confirmed entry must survive")
	}
	ClearSource("https://nobody.example.com") // 任意一次变更都会把过期的清出落盘文件
	Apply(src, ScopeUser, OriginPush, Update{Server: "x.example.com", IPs: ips("192.0.2.3"), Rev: 1})
	data, _ := os.ReadFile(path)
	var f fileFormat
	_ = json.Unmarshal(data, &f)
	for _, e := range f.Entries {
		if e.Server == "old.example.com" {
			t.Fatal("expired entry still persisted")
		}
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	path := reset(t)
	Apply(src, "rt:abc", OriginPush, Update{Server: "hk-entry.example.com", IPs: ips("203.0.113.11", "203.0.113.12"), Rev: 1794000123456, ChainID: 7})
	Apply(src, ScopeUser, OriginPush, Update{Server: "198.51.100.20", IPs: ips("198.51.100.21"), Rev: 1794000099000, ChainID: 9})
	before := List()

	// 换个路径再换回来 = 重新从文件读
	if err := Load(filepath.Join(t.TempDir(), "other.json")); err != nil {
		t.Fatal(err)
	}
	if len(List()) != 0 {
		t.Fatal("fresh path should start empty")
	}
	if err := Load(path); err != nil {
		t.Fatal(err)
	}
	after := List()
	if len(after) != len(before) {
		t.Fatalf("round trip: before %+v after %+v", before, after)
	}
	for i := range before {
		b, a := before[i], after[i]
		if b.Server != a.Server || b.Rev != a.Rev || b.ChainID != a.ChainID || b.Source != a.Source ||
			len(b.IPs) != len(a.IPs) || b.UpdatedAt != a.UpdatedAt || b.ConfirmedAt != a.ConfirmedAt {
			t.Fatalf("round trip mismatch: %+v vs %+v", b, a)
		}
	}
	if got := Lookup("hk-entry.example.com", 0, 0); !sameSet(got, "203.0.113.11", "203.0.113.12") {
		t.Fatalf("lookup after reload = %v", got)
	}
	// 读回来的 rev 仍然生效
	if r := Apply(src, ScopeUser, OriginPush, Update{Server: "hk-entry.example.com", IPs: ips("203.0.113.1"), Rev: 1794000000000}); r.Applied {
		t.Fatal("older rev accepted after reload")
	}
	// 文件里不带任何凭证，只有键、IP、rev、来源与范围的摘要
	data, _ := os.ReadFile(path)
	var f fileFormat
	if err := json.Unmarshal(data, &f); err != nil || f.Version != 1 || len(f.Entries) != 2 {
		t.Fatalf("file = %s", data)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %v", st.Mode())
	}
	ClearSource(src)
	if len(List()) != 0 {
		t.Fatal("ClearSource left entries")
	}
}

// fakeConn 记录有没有被关掉；Context 让 connAlive 认得出死活。
type fakeConn struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func newFakeConn() *fakeConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &fakeConn{ctx: ctx, cancel: cancel}
}

func (f *fakeConn) Close() error             { f.cancel(); return nil }
func (f *fakeConn) Context() context.Context { return f.ctx }
func (f *fakeConn) closed() bool             { return f.ctx.Err() != nil }

func TestCloseConnectionsOnRemoval(t *testing.T) {
	reset(t)
	var hookCalls []string
	SetTrackerCloser(func(server string, ports Ports, removed []netip.Addr) int {
		for _, ip := range removed {
			hookCalls = append(hookCalls, server+"|"+ip.String())
		}
		return 1
	})
	Apply(src, ScopeUser, OriginPush, Update{Server: "hk.example.com", IPs: ips("203.0.113.10", "203.0.113.11"), Rev: 1})
	Apply(src, ScopeUser, OriginPush, Update{Server: "jp.example.com", IPs: ips("203.0.113.10"), Rev: 1})
	a := newFakeConn() // hk 经 .10
	b := newFakeConn() // hk 经 .11
	c := newFakeConn() // jp 经 .10（同一个 IP，别的键）
	u := newFakeConn() // 只知道 IP 的 UDP socket，.10 当时在 hk 与 jp 两个集合里
	Track("hk.example.com", 443, netip.MustParseAddr("203.0.113.10"), a)
	Track("hk.example.com", 443, netip.MustParseAddr("203.0.113.11"), b)
	Track("jp.example.com", 443, netip.MustParseAddr("203.0.113.10"), c)
	if !TrackIP(netip.MustParseAddrPort("203.0.113.10:443"), u) {
		t.Fatal("TrackIP should register an IP that is in a set")
	}
	if TrackIP(netip.MustParseAddrPort("198.51.100.1:443"), newFakeConn()) {
		t.Fatal("TrackIP must ignore IPs that are in no set")
	}

	// 上线：只加 IP，不动现有连接
	Apply(src, ScopeUser, OriginPush, Update{Server: "hk.example.com", IPs: ips("203.0.113.10", "203.0.113.11", "203.0.113.12"), Rev: 2})
	if a.closed() || b.closed() || len(hookCalls) != 0 {
		t.Fatal("adding an IP must not close anything")
	}
	// 卸载 .10：经 hk 连着 .10 的关掉；.11 与 jp 的不动
	Apply(src, ScopeUser, OriginPush, Update{Server: "hk.example.com", IPs: ips("203.0.113.11", "203.0.113.12"), Rev: 3, Reason: "unload"})
	if !a.closed() || !u.closed() {
		t.Fatal("connections to the removed IP via hk must be closed")
	}
	if b.closed() || c.closed() {
		t.Fatal("connections to other IPs / other keys must stay")
	}
	if len(hookCalls) != 1 || hookCalls[0] != "hk.example.com|203.0.113.10" {
		t.Fatalf("tracker closer calls = %v", hookCalls)
	}
	// 撤销覆盖（空集合）回到 DNS，不关连接
	Apply(src, ScopeUser, OriginPush, Update{Server: "hk.example.com", Rev: 4})
	if b.closed() {
		t.Fatal("revoking the override must not close connections")
	}
	if registry.size() != 2 { // b、c 还在
		t.Fatalf("registry size = %d", registry.size())
	}
}

func TestRegistryPrunesClosed(t *testing.T) {
	reset(t)
	for i := 0; i < registryPruneEvery*2; i++ {
		c := newFakeConn()
		Track("x.example.com", 443, netip.MustParseAddr("192.0.2.1"), c)
		_ = c.Close()
	}
	if n := registry.size(); n >= registryPruneEvery {
		t.Fatalf("closed connections should be pruned, size = %d", n)
	}
}

func TestNormalizeKey(t *testing.T) {
	cases := map[string]string{
		" HK-Entry.Example.COM. ": "hk-entry.example.com",
		"[2001:DB8::1]":           "2001:db8::1",
		"::ffff:192.0.2.1":        "192.0.2.1",
		"198.51.100.20":           "198.51.100.20",
		"":                        "",
	}
	for in, want := range cases {
		if got := NormalizeKey(in); got != want {
			t.Errorf("NormalizeKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// 入口端口（规格 §1）：没有 ports 字段只比 server；有时节点端口要在里面；[] 不匹配任何节点；端口不知道（0）只认没给 ports 的。
func TestPortsMatching(t *testing.T) {
	reset(t)
	Apply(src, ScopeUser, OriginPush, Update{Server: "legacy.example.com", IPs: ips("192.0.2.1"), Rev: 1})
	Apply(src, ScopeUser, OriginPush, Update{Server: "fw.example.com", IPs: ips("192.0.2.2"), Ports: PortList(50523, 50520, 50523, 0), Rev: 1})
	Apply(src, ScopeUser, OriginPush, Update{Server: "empty.example.com", IPs: ips("192.0.2.3"), Ports: PortList(), Rev: 1})

	if Lookup("legacy.example.com", 443, 0) == nil || Lookup("legacy.example.com", 0, 0) == nil {
		t.Fatal("entry without ports must match by server only")
	}
	if got := Lookup("fw.example.com", 50520, 0); !sameSet(got, "192.0.2.2") {
		t.Fatalf("port in ports = %v", got)
	}
	if Lookup("fw.example.com", 50523, 4) == nil {
		t.Fatal("second port in ports should match")
	}
	if Lookup("fw.example.com", 22, 0) != nil {
		t.Fatal("port not in ports (direct node on the same server) must not match")
	}
	if Lookup("fw.example.com", 0, 0) != nil {
		t.Fatal("unknown port must not match an entry that has ports")
	}
	if Lookup("empty.example.com", 443, 0) != nil || Lookup("empty.example.com", 0, 0) != nil {
		t.Fatal("ports [] must match no node")
	}
	// KeysOfIP（只知道远端地址的 UDP socket）同样按端口认
	if k := KeysOfIP(netip.MustParseAddr("192.0.2.2"), 50520); len(k) != 1 || k[0] != "fw.example.com" {
		t.Fatalf("keys of ip with matching port = %v", k)
	}
	if k := KeysOfIP(netip.MustParseAddr("192.0.2.2"), 22); len(k) != 0 {
		t.Fatalf("keys of ip with other port = %v", k)
	}

	// Active：有节点 server 等于键、端口也对得上才算
	SetServerSource(func() []Server {
		return []Server{{Host: "legacy.example.com", Port: 1}, {Host: "fw.example.com", Port: 22}, {Host: "empty.example.com", Port: 443}}
	})
	act := map[string]bool{}
	for _, v := range List() {
		act[v.Server] = v.Active
	}
	if !act["legacy.example.com"] || act["fw.example.com"] || act["empty.example.com"] {
		t.Fatalf("active with only a direct node on fw = %v", act)
	}
	SetServerSource(func() []Server {
		return []Server{{Host: "fw.example.com", Port: 22}, {Host: "FW.example.com", Port: 50523}}
	})
	for _, v := range List() {
		if v.Server == "fw.example.com" && !v.Active {
			t.Fatalf("fw should be active once a node on port 50523 exists: %+v", v)
		}
	}
}

// 只有端口变了（链上加减节点）、IP 不变：rev 更大就换上；同 rev 照旧不换。
func TestPortsOnlyChange(t *testing.T) {
	reset(t)
	Apply(src, ScopeUser, OriginPush, Update{Server: "fw.example.com", IPs: ips("192.0.2.2"), Ports: PortList(50520), Rev: 1})
	if r := Apply(src, ScopeUser, OriginPush, Update{Server: "fw.example.com", IPs: ips("192.0.2.2"), Ports: PortList(50520, 50523), Rev: 1}); r.Applied {
		t.Fatal("equal rev must not apply even if ports differ")
	}
	if Lookup("fw.example.com", 50523, 0) != nil {
		t.Fatal("ports changed by an equal rev")
	}
	r := Apply(src, ScopeUser, OriginPush, Update{Server: "fw.example.com", IPs: ips("192.0.2.2"), Ports: PortList(50520, 50523), Rev: 2, Reason: "admin"})
	if !r.Applied || r.Rev != 2 {
		t.Fatalf("ports-only change = %+v", r)
	}
	if Lookup("fw.example.com", 50523, 0) == nil || Lookup("fw.example.com", 50520, 0) == nil {
		t.Fatal("new ports not used")
	}
	// 链上的节点全删了：[]
	Apply(src, ScopeUser, OriginPush, Update{Server: "fw.example.com", IPs: ips("192.0.2.2"), Ports: PortList(), Rev: 3})
	if Lookup("fw.example.com", 50520, 0) != nil {
		t.Fatal("ports [] must stop matching")
	}
	// 快照里的端口同样按 rev 换上
	ApplySnapshot(src, ScopeUser, OriginSnapshot, true, time.Now(), []Update{{Server: "fw.example.com", IPs: ips("192.0.2.2"), Ports: PortList(443), Rev: 4}})
	if Lookup("fw.example.com", 443, 0) == nil {
		t.Fatal("snapshot ports not applied")
	}
}

// 落盘：缺省（没有 ports 字段）、[]、有端口三种都原样读回；老文件没有 ports 字段 = 缺省。
func TestPortsPersistence(t *testing.T) {
	path := reset(t)
	Apply(src, ScopeUser, OriginPush, Update{Server: "legacy.example.com", IPs: ips("192.0.2.1"), Rev: 1})
	Apply(src, ScopeUser, OriginPush, Update{Server: "fw.example.com", IPs: ips("192.0.2.2"), Ports: PortList(50523, 50520), Rev: 1})
	Apply(src, ScopeUser, OriginPush, Update{Server: "empty.example.com", IPs: ips("192.0.2.3"), Ports: PortList(), Rev: 1})

	var raw struct {
		Entries []map[string]json.RawMessage `json:"entries"`
	}
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, e := range raw.Entries {
		var server string
		_ = json.Unmarshal(e["server"], &server)
		p, has := e["ports"]
		switch server {
		case "legacy.example.com":
			if has {
				t.Fatalf("entry without ports persisted ports: %s", p)
			}
		case "fw.example.com":
			if !has || compactJSON(t, p) != "[50520,50523]" {
				t.Fatalf("fw ports persisted as %s", p)
			}
		case "empty.example.com":
			if !has || compactJSON(t, p) != "[]" {
				t.Fatalf("empty ports persisted as %q (present %v)", p, has)
			}
		}
	}

	if err := Load(filepath.Join(t.TempDir(), "other.json")); err != nil {
		t.Fatal(err)
	}
	if err := Load(path); err != nil {
		t.Fatal(err)
	}
	if Lookup("legacy.example.com", 8443, 0) == nil {
		t.Fatal("legacy entry should still match any port after reload")
	}
	if Lookup("fw.example.com", 50523, 0) == nil || Lookup("fw.example.com", 22, 0) != nil {
		t.Fatal("ports not restored")
	}
	if Lookup("empty.example.com", 443, 0) != nil {
		t.Fatal("ports [] not restored as empty")
	}
	views := map[string]View{}
	for _, v := range List() {
		views[v.Server] = v
	}
	if views["legacy.example.com"].Ports != nil || views["empty.example.com"].Ports == nil || len(*views["empty.example.com"].Ports) != 0 ||
		views["fw.example.com"].Ports == nil || len(*views["fw.example.com"].Ports) != 2 {
		t.Fatalf("views after reload = %+v", views)
	}

	// 老版本写的文件：没有 ports 字段
	old := filepath.Join(t.TempDir(), "old.json")
	_ = os.WriteFile(old, []byte(`{"version":1,"entries":[{"server":"fw.example.com","ips":["192.0.2.2"],"rev":1,"source":"`+src+`","updatedAt":`+
		jsonInt(time.Now().UnixMilli())+`,"confirmedAt":`+jsonInt(time.Now().UnixMilli())+`}]}`), 0o600)
	if err := Load(old); err != nil {
		t.Fatal(err)
	}
	if Lookup("fw.example.com", 22, 0) == nil {
		t.Fatal("old file without ports must match by server only")
	}
}

func compactJSON(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(v)
	return string(out)
}

func jsonInt(n int64) string {
	out, _ := json.Marshal(n)
	return string(out)
}

// 下线关连接只关端口在入口端口里的节点：同一 server 上另开的直连节点（端口不在 ports 里）不碰，连接表的关闭函数也拿到端口。
func TestCloseConnectionsRespectsPorts(t *testing.T) {
	reset(t)
	const key = "198.51.100.20" // 没设链域名：键 = 入口组首台的地址，和同机直连节点的 server 一样
	var gotPorts []Ports
	SetTrackerCloser(func(server string, ports Ports, removed []netip.Addr) int {
		gotPorts = append(gotPorts, ports)
		return 0
	})
	Apply(src, ScopeUser, OriginPush, Update{Server: key, IPs: ips("198.51.100.20", "198.51.100.21"), Ports: PortList(50520), Rev: 1})
	fw := newFakeConn()     // 转发节点（端口 50520）拨到 .20
	direct := newFakeConn() // 直连节点（端口 22）连着 .20：照常 DNS / 字面量，不经覆盖
	fwUDP := newFakeConn()
	Track(key, 50520, netip.MustParseAddr("198.51.100.20"), fw)
	Track(key, 22, netip.MustParseAddr("198.51.100.20"), direct) // 万一登记过（比如以前没有端口时），也不能关
	if !TrackIP(netip.MustParseAddrPort("198.51.100.20:50520"), fwUDP) {
		t.Fatal("UDP socket to the entry port should be registered")
	}
	if TrackIP(netip.MustParseAddrPort("198.51.100.20:22"), newFakeConn()) {
		t.Fatal("UDP socket to a port not in ports must not be registered")
	}

	Apply(src, ScopeUser, OriginPush, Update{Server: key, IPs: ips("198.51.100.21"), Ports: PortList(50520), Rev: 2, Reason: "unload"})
	if !fw.closed() || !fwUDP.closed() {
		t.Fatal("forward node connections to the removed IP must be closed")
	}
	if direct.closed() {
		t.Fatal("direct node on the same server (port not in ports) must not be closed")
	}
	if len(gotPorts) != 1 || !gotPorts[0].Match(50520) || gotPorts[0].Match(22) {
		t.Fatalf("tracker closer ports = %+v", gotPorts)
	}

	// 端口与 IP 同时变：按新旧端口的并集关（旧端口上的连接是经覆盖拨的）
	old := newFakeConn()
	Track(key, 50520, netip.MustParseAddr("198.51.100.21"), old)
	Apply(src, ScopeUser, OriginPush, Update{Server: key, IPs: ips("198.51.100.22"), Ports: PortList(50523), Rev: 3})
	if !old.closed() || direct.closed() {
		t.Fatal("union of old and new ports should be used when closing")
	}
}

func viewOf(t *testing.T, server string) View {
	t.Helper()
	for _, v := range List() {
		if v.Server == server {
			return v
		}
	}
	t.Fatalf("no view for %s", server)
	return View{}
}

// 入口服务器名称（规格 §2.2）：只留集合里的 IP、去空白截 64 字；同 rev 带了也补上（不算变更、不关连接）、
// 同 rev 没带不动；新 rev 没带就清掉；随落盘读回；View 的 JSON 一个都没有时不出 names。
func TestEntryNames(t *testing.T) {
	path := reset(t)
	closed := 0
	SetTrackerCloser(func(string, Ports, []netip.Addr) int { closed++; return 0 })
	key := "hk-entry.example.com"
	long := ""
	for i := 0; i < 70; i++ {
		long += "名"
	}
	// 普通用户的连接：没有 names
	Apply(src, ScopeUser, OriginSnapshot, Update{Server: key, IPs: ips("203.0.113.11", "203.0.113.12"), Rev: 100})
	if v := viewOf(t, key); v.Names != nil {
		t.Fatalf("names without field = %v", v.Names)
	}
	if data, _ := json.Marshal(viewOf(t, key)); json.Valid(data) && containsKey(t, data, "names") {
		t.Fatalf("view JSON must omit names: %s", data)
	}
	// 主控升级后同一个 rev 的快照带上名称：补上，不算变更
	r := Apply(src, ScopeUser, OriginSnapshot, Update{Server: key, IPs: ips("203.0.113.11", "203.0.113.12"), Rev: 100,
		Names: map[string]string{" 203.0.113.11 ": "  香港入口 A  ", "203.0.113.99": "不在集合里", "203.0.113.12": "   ", "bad": "x"}})
	if r.Applied {
		t.Fatalf("same rev with names must not count as applied: %+v", r)
	}
	if v := viewOf(t, key); len(v.Names) != 1 || v.Names["203.0.113.11"] != "香港入口 A" {
		t.Fatalf("names after same-rev = %v", v.Names)
	}
	// 同 rev 没带名称（rt 凭证的通道）：不动
	Apply(src, "rt:x", OriginSnapshot, Update{Server: key, IPs: ips("203.0.113.11", "203.0.113.12"), Rev: 100})
	if v := viewOf(t, key); v.Names["203.0.113.11"] != "香港入口 A" {
		t.Fatalf("same rev without names must keep them: %v", v.Names)
	}
	// 新 rev：名称跟着新集合走，超长截到 64 字
	Apply(src, ScopeUser, OriginPush, Update{Server: key, IPs: ips("203.0.113.12"), Rev: 200,
		Names: map[string]string{"203.0.113.12": long, "203.0.113.11": "已下线"}})
	if v := viewOf(t, key); len(v.Names) != 1 || len([]rune(v.Names["203.0.113.12"])) != MaxNameLength {
		t.Fatalf("names after new rev = %v", v.Names)
	}
	// 落盘读回
	if err := Load(filepath.Join(t.TempDir(), "other.json")); err != nil {
		t.Fatal(err)
	}
	if err := Load(path); err != nil {
		t.Fatal(err)
	}
	if v := viewOf(t, key); len([]rune(v.Names["203.0.113.12"])) != MaxNameLength {
		t.Fatalf("names after reload = %v", v.Names)
	}
	// 新 rev 没带名称：清掉
	Apply(src, ScopeUser, OriginPush, Update{Server: key, IPs: ips("203.0.113.12"), Rev: 300})
	if v := viewOf(t, key); v.Names != nil {
		t.Fatalf("new rev without names must clear them: %v", v.Names)
	}
	if closed != 1 {
		t.Fatalf("only the rev-200 removal closes connections, closer called %d times", closed)
	}
	// 老落盘文件（没有 names）读进来 = 没有
	old := `{"version":1,"entries":[{"server":"old.test","ips":["192.0.2.1"],"rev":1,"source":"s","updatedAt":` +
		jsonInt(time.Now().UnixMilli()) + `,"confirmedAt":` + jsonInt(time.Now().UnixMilli()) + `}]}`
	oldPath := filepath.Join(t.TempDir(), "old.json")
	if err := os.WriteFile(oldPath, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Load(oldPath); err != nil {
		t.Fatal(err)
	}
	if v := viewOf(t, "old.test"); v.Names != nil {
		t.Fatalf("old file names = %v", v.Names)
	}
}

func containsKey(t *testing.T, data []byte, key string) bool {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	_, ok := m[key]
	return ok
}
