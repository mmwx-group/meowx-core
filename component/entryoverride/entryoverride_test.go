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
	if got := Lookup("hk-entry.example.com", 0); !sameSet(got, "203.0.113.10") {
		t.Fatalf("lookup = %v", got)
	}
	Apply(src, ScopeUser, OriginPush, Update{Server: "hk-entry.example.com", IPs: ips("203.0.113.11", "203.0.113.12"), Rev: 200})
	if got := Lookup("HK-ENTRY.example.com", 0); !sameSet(got, "203.0.113.11", "203.0.113.12") {
		t.Fatalf("lookup after newer rev = %v", got)
	}
	// 撤销：空集合 = 回到 DNS；之后更旧的推送不能把它加回来
	Apply(src, ScopeUser, OriginPush, Update{Server: "hk-entry.example.com", Rev: 300})
	if got := Lookup("hk-entry.example.com", 0); got != nil {
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
		got := Lookup("e.example.com", 0)
		if len(got) != 3 {
			t.Fatalf("lookup = %v", got)
		}
		firsts[got[0].String()]++
	}
	if len(firsts) != 3 {
		t.Fatalf("rotation should start at each IP in turn: %v", firsts)
	}
	if got := Lookup("e.example.com", 6); !sameSet(got, "2001:db8::1") {
		t.Fatalf("v6 only = %v", got)
	}
	if got := Lookup("e.example.com", 4); !sameSet(got, "192.0.2.1", "192.0.2.2") {
		t.Fatalf("v4 only = %v", got)
	}
	// IP 作键（没设链域名时 server 是入口组第一台的地址）
	Apply(src, ScopeUser, OriginPush, Update{Server: "[2001:DB8::20]", IPs: ips("2001:db8::21"), Rev: 1})
	if got := Lookup("2001:db8::20", 0); !sameSet(got, "2001:db8::21") {
		t.Fatalf("ip key lookup = %v", got)
	}
}

func TestKeyRestriction(t *testing.T) {
	reset(t)
	servers := []string{"other.example.com"}
	var mu sync.Mutex
	SetServerSource(func() []string { mu.Lock(); defer mu.Unlock(); return servers })
	Apply(src, ScopeUser, OriginPush, Update{Server: "hk-entry.example.com", IPs: ips("203.0.113.10"), Rev: 1})
	if got := Lookup("hk-entry.example.com", 0); got != nil {
		t.Fatalf("key not in config must be ignored, got %v", got)
	}
	if l := List(); len(l) != 1 || l[0].Active {
		t.Fatalf("list should show the entry as inactive: %+v", l)
	}
	mu.Lock()
	servers = []string{"HK-Entry.Example.COM"}
	mu.Unlock()
	InvalidateServers()
	if got := Lookup("hk-entry.example.com", 0); !sameSet(got, "203.0.113.10") {
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
	if Lookup("b.example.com", 0) == nil {
		t.Fatal("ready:false snapshot must not clear entries")
	}
	// ready:true：这个主控来的、快照里没有的清掉；别的主控的不动
	res := ApplySnapshot(src, ScopeUser, OriginSnapshot, true, time.Now(), []Update{{Server: "a.example.com", IPs: ips("192.0.2.9"), Rev: 2}})
	if len(res) != 1 || !res[0].Applied || res[0].Rev != 2 {
		t.Fatalf("snapshot results = %+v", res)
	}
	if Lookup("b.example.com", 0) != nil {
		t.Fatal("ready:true snapshot must clear unlisted keys of this source")
	}
	if got := Lookup("a.example.com", 0); !sameSet(got, "192.0.2.9") {
		t.Fatalf("a = %v", got)
	}
	if Lookup("c.example.com", 0) == nil {
		t.Fatal("entries of another panel must survive")
	}
	// 拉取请求在路上时推送新加的键：asOf 之后确认过的不清
	reqStart := time.Now()
	time.Sleep(2 * time.Millisecond)
	Apply(src, ScopeUser, OriginPush, Update{Server: "d.example.com", IPs: ips("192.0.2.4"), Rev: 5})
	ApplySnapshot(src, ScopeUser, OriginPull, true, reqStart, []Update{{Server: "a.example.com", IPs: ips("192.0.2.9"), Rev: 2}})
	if Lookup("d.example.com", 0) == nil {
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
	if Lookup("one.example.com", 0) == nil || Lookup("two.example.com", 0) == nil {
		t.Fatal("two rt channels of the same panel must not clear each other's entries")
	}
	time.Sleep(2 * time.Millisecond)
	// rt:1 那份订阅不再用 shared 与 one：one 只有它认领，清掉；shared 还有 rt:2 认领，留着
	ApplySnapshot(src, "rt:1", OriginSnapshot, true, time.Now(), nil)
	if Lookup("one.example.com", 0) != nil {
		t.Fatal("entry claimed only by rt:1 should be cleared")
	}
	if Lookup("shared.example.com", 0) == nil {
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
	if Lookup("old.example.com", 0) != nil {
		t.Fatal("entry not confirmed for 7 days must expire")
	}
	if Lookup("fresh.example.com", 0) == nil {
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
	if got := Lookup("hk-entry.example.com", 0); !sameSet(got, "203.0.113.11", "203.0.113.12") {
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
	SetTrackerCloser(func(server string, removed []netip.Addr) int {
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
	Track("hk.example.com", netip.MustParseAddr("203.0.113.10"), a)
	Track("hk.example.com", netip.MustParseAddr("203.0.113.11"), b)
	Track("jp.example.com", netip.MustParseAddr("203.0.113.10"), c)
	if !TrackIP(netip.MustParseAddr("203.0.113.10"), u) {
		t.Fatal("TrackIP should register an IP that is in a set")
	}
	if TrackIP(netip.MustParseAddr("198.51.100.1"), newFakeConn()) {
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
		Track("x.example.com", netip.MustParseAddr("192.0.2.1"), c)
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
