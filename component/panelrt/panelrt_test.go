package panelrt

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/entryoverride"
	C "github.com/metacubex/mihomo/constant"
)

// 跑法：go test -tags with_gvisor ./component/panelrt/

func TestMain(m *testing.M) {
	timing = timingConfig{
		initialBackoff:     30 * time.Millisecond,
		maxBackoff:         200 * time.Millisecond,
		stableAfter:        time.Second,
		authFailureWindow:  150 * time.Millisecond,
		authFailureStrikes: 3,
		authFailureBackoff: time.Hour,
		kickMinInterval:    50 * time.Millisecond,
		resumeJitterMin:    0,
		resumeJitterMax:    10 * time.Millisecond,
		pingInterval:       100 * time.Millisecond,
		readTimeout:        5 * time.Second,
		handshakeTimeout:   5 * time.Second,
		pullInterval:       200 * time.Millisecond,
		subJitterMax:       0,
		subMinInterval:     300 * time.Millisecond,
	}
	os.Exit(m.Run())
}

// setup 每个用例一个新的数据目录（入口覆盖表与订阅 rev 都从空开始），只认 servers 这几个节点 server。
func setup(t *testing.T, servers ...string) {
	t.Helper()
	C.SetHomeDir(t.TempDir())
	ensureState()
	entryoverride.SetServerSource(func() []string { return servers })
	t.Cleanup(func() {
		Stop()
		SetSubscriptionCallback(nil)
		entryoverride.SetServerSource(proxyServers)
	})
}

type subEvent struct {
	base, key, rev string
	at             time.Time
}

func collectSubs(t *testing.T) func() []subEvent {
	var mu sync.Mutex
	var events []subEvent
	SetSubscriptionCallback(func(base, key, rev string) {
		mu.Lock()
		events = append(events, subEvent{base, key, rev, time.Now()})
		mu.Unlock()
	})
	return func() []subEvent {
		mu.Lock()
		defer mu.Unlock()
		return append([]subEvent(nil), events...)
	}
}

func hasUplink(list []map[string]any, typ string, chainID, rev float64) bool {
	for _, m := range list {
		if m["type"] == typ && (chainID == 0 || m["chainId"] == chainID) && (rev == 0 || m["rev"] == rev) {
			return true
		}
	}
	return false
}

func TestRealtimeEntryFailoverAndAck(t *testing.T) {
	setup(t, "legacy.test", "hk.test")
	p := newFakePanel(t)
	p.tokens["good"] = true
	p.onConnect = func(c *fakeWS) {
		// 旧主控的写法：没有 rev / reason
		_ = c.send(map[string]any{"type": "entry_failover", "domain": "legacy.test", "healthyIPs": []string{"203.0.113.10"}, "chainId": 7})
		_ = c.send(map[string]any{"type": "entry_failover", "domain": "HK.test", "healthyIPs": []string{"203.0.113.11", "203.0.113.12"},
			"chainId": 8, "rev": int64(1794000123456), "reason": "online"})
		_ = c.send(map[string]any{"type": "dashboard_invalidate", "x": 1}) // 不认识的推送忽略
	}
	if err := Configure([]Channel{{Base: p.base + "/", Token: "good"}}, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, "hk.test override", func() bool { return len(entryoverride.Lookup("hk.test", 0)) == 2 })
	if got := entryoverride.Lookup("legacy.test", 0); len(got) != 1 || got[0].String() != "203.0.113.10" {
		t.Fatalf("legacy push = %v", got)
	}
	waitFor(t, 3*time.Second, "ack + ping", func() bool {
		_, up, _, _ := p.snapshot()
		return hasUplink(up, "entry_ack", 8, 1794000123456) && hasUplink(up, "ping", 0, 0)
	})
	auths, up, _, _ := p.snapshot()
	if len(auths) != 1 || auths[0]["token"] != "good" || auths[0]["rt"] != nil || str(auths[0]["nonce"]) == "" || auths[0]["ts"] == nil {
		t.Fatalf("auth frame = %+v", auths)
	}
	caps, _ := auths[0]["caps"].([]any)
	if len(caps) != 3 || caps[0] != "entry_v2" || caps[1] != "sub_v2" || caps[2] != "ack" {
		t.Fatalf("caps = %v", caps)
	}
	if hasUplink(up, "entry_ack", 7, 0) {
		t.Fatal("legacy push without rev must not be acked")
	}
	st := Status()
	if len(st.Channels) != 1 || st.Channels[0].State != stateConnected || st.Channels[0].Auth != "token" || st.Channels[0].LastEvent != "entry_failover" {
		t.Fatalf("status = %+v", st)
	}
	views := Entries()
	if len(views) != 2 || views[0].Source != NormalizeBaseMust(t, p.base) {
		t.Fatalf("entries = %+v", views)
	}
	// 同一份配置再 PUT 一次：不重连
	if err := Configure([]Channel{{Base: p.base, Token: "good"}}, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, _, _, n := p.snapshot(); n != 1 {
		t.Fatalf("re-configuring the same channel reconnected (%d connections)", n)
	}
}

func NormalizeBaseMust(t *testing.T, raw string) string {
	b, err := NormalizeBase(raw)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRealtimeSnapshotReady(t *testing.T) {
	setup(t, "a.test", "b.test", "stale.test", "other.test")
	p := newFakePanel(t)
	p.tokens["good"] = true
	source := NormalizeBaseMust(t, p.base)
	ip := ips("192.0.2.9")
	entryoverride.Apply(source, entryoverride.ScopeUser, entryoverride.OriginPush, entryoverride.Update{Server: "stale.test", IPs: ip, Rev: 1})
	entryoverride.Apply("https://elsewhere.test", entryoverride.ScopeUser, entryoverride.OriginPush, entryoverride.Update{Server: "other.test", IPs: ip, Rev: 1})
	step := make(chan struct{})
	p.onConnect = func(c *fakeWS) {
		// 主控刚重启：ready=false，不能按它清理
		_ = c.send(map[string]any{"type": "entry_snapshot", "ready": false, "entries": []any{
			map[string]any{"server": "a.test", "chainId": 1, "ips": []string{"192.0.2.1"}, "rev": 100}}})
		<-step
		_ = c.send(map[string]any{"type": "entry_snapshot", "ready": true, "entries": []any{
			map[string]any{"server": "a.test", "chainId": 1, "ips": []string{"192.0.2.1"}, "rev": 100},
			map[string]any{"server": "b.test", "chainId": 2, "ips": []string{"192.0.2.2"}, "rev": 200}}})
	}
	if err := Configure([]Channel{{Base: p.base, Token: "good"}}, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, "a.test", func() bool { return entryoverride.Lookup("a.test", 0) != nil })
	if entryoverride.Lookup("stale.test", 0) == nil {
		t.Fatal("ready:false snapshot cleared an entry")
	}
	close(step)
	waitFor(t, 3*time.Second, "b.test", func() bool { return entryoverride.Lookup("b.test", 0) != nil })
	waitFor(t, 3*time.Second, "stale cleared", func() bool { return entryoverride.Lookup("stale.test", 0) == nil })
	if entryoverride.Lookup("other.test", 0) == nil {
		t.Fatal("snapshot from one panel cleared another panel's entry")
	}
	waitFor(t, 3*time.Second, "acks", func() bool {
		_, up, _, _ := p.snapshot()
		return hasUplink(up, "entry_ack", 1, 100) && hasUplink(up, "entry_ack", 2, 200)
	})
}

func TestRealtimeSubscriptionChanged(t *testing.T) {
	setup(t)
	events := collectSubs(t)
	p := newFakePanel(t)
	p.tokens["good"] = true
	steps := make(chan map[string]any, 8)
	p.onConnect = func(c *fakeWS) {
		for m := range steps {
			_ = c.send(m)
		}
	}
	if err := Configure([]Channel{{Base: p.base, Token: "good"}}, nil); err != nil {
		t.Fatal(err)
	}
	base := NormalizeBaseMust(t, p.base)
	// 旧主控：不带 subs = 这个主控来的全部订阅
	steps <- map[string]any{"type": "subscription_changed", "rev": "3f2a9c01b7de"}
	waitFor(t, 3*time.Second, "all-subs event", func() bool { return len(events()) == 1 })
	if e := events()[0]; e.base != base || e.key != "" || e.rev != "3f2a9c01b7de" {
		t.Fatalf("event = %+v", e)
	}
	steps <- map[string]any{"type": "subscription_changed", "rev": "x", "subs": []any{map[string]any{"key": "pkg:12", "rev": "r1"}}}
	waitFor(t, 3*time.Second, "pkg:12 r1", func() bool { return len(events()) == 2 })
	if e := events()[1]; e.key != "pkg:12" || e.rev != "r1" {
		t.Fatalf("event = %+v", e)
	}
	// 同一个 rev 再来不通知；快照里只有变了的通知
	steps <- map[string]any{"type": "subscription_changed", "rev": "x", "subs": []any{map[string]any{"key": "pkg:12", "rev": "r1"}}}
	steps <- map[string]any{"type": "sub_snapshot", "subs": []any{
		map[string]any{"key": "pkg:12", "rev": "r1"}, map[string]any{"key": "file:alice.yaml", "rev": "77aa01f3c9e0"}}}
	waitFor(t, 3*time.Second, "file:alice.yaml", func() bool { return len(events()) == 3 })
	if e := events()[2]; e.key != "file:alice.yaml" || e.rev != "77aa01f3c9e0" {
		t.Fatalf("event = %+v", e)
	}
	// 30s（测试里 300ms）内同一份订阅又变了：等满了再通知最新的
	first := events()[1].at
	steps <- map[string]any{"type": "subscription_changed", "rev": "x", "subs": []any{map[string]any{"key": "pkg:12", "rev": "r2"}}}
	steps <- map[string]any{"type": "subscription_changed", "rev": "x", "subs": []any{map[string]any{"key": "pkg:12", "rev": "r3"}}}
	waitFor(t, 3*time.Second, "pkg:12 r3", func() bool { return len(events()) == 4 })
	e := events()[3]
	if e.key != "pkg:12" || e.rev != "r3" {
		t.Fatalf("throttled event = %+v", e)
	}
	if gap := e.at.Sub(first); gap < timing.subMinInterval-20*time.Millisecond {
		t.Fatalf("second delivery for the same key after %v (< %v)", gap, timing.subMinInterval)
	}
	time.Sleep(timing.subMinInterval + 100*time.Millisecond)
	if n := len(events()); n != 4 {
		t.Fatalf("expected the two changes to coalesce, got %d events", n)
	}
	close(steps)
}

func TestRealtimeAuthFailure(t *testing.T) {
	setup(t)
	p := newFakePanel(t) // 不认任何 token：鉴权帧到了就关
	if err := Configure([]Channel{{Base: p.base, Token: "expired"}}, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "auth failure", func() bool {
		st := Status()
		return len(st.Channels) == 1 && st.Channels[0].AuthFailed
	})
	st := Status().Channels[0]
	if st.Attempts != timing.authFailureStrikes || st.State != stateBackoff {
		t.Fatalf("status = %+v", st)
	}
	if wait := time.Until(time.UnixMilli(st.NextRetryAt)); wait < timing.authFailureBackoff-time.Minute {
		t.Fatalf("auth failure should back off ~%v, next retry in %v", timing.authFailureBackoff, wait)
	}
	time.Sleep(200 * time.Millisecond)
	if auths, _, _, _ := p.snapshot(); len(auths) != timing.authFailureStrikes {
		t.Fatalf("kept retrying after auth failure: %d attempts", len(auths))
	}
	// 外壳换上新凭证：新通道立刻连上
	p.mu.Lock()
	p.tokens["fresh"] = true
	p.mu.Unlock()
	if err := Configure([]Channel{{Base: p.base, Token: "fresh"}}, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, "connected with new token", func() bool {
		st := Status()
		return len(st.Channels) == 1 && st.Channels[0].State == stateConnected
	})
}

func TestRealtimeReconnect(t *testing.T) {
	setup(t, "r.test")
	p := newFakePanel(t)
	p.tokens["good"] = true
	var n int
	var mu sync.Mutex
	p.onConnect = func(c *fakeWS) {
		mu.Lock()
		n++
		rev := int64(n)
		mu.Unlock()
		_ = c.send(map[string]any{"type": "entry_snapshot", "ready": true, "entries": []any{
			map[string]any{"server": "r.test", "chainId": 1, "ips": []string{"192.0.2." + string(rune('0'+rev))}, "rev": rev}}})
		time.Sleep(timing.authFailureWindow * 2) // 活过鉴权判定窗口再断：普通断线，不算鉴权失败
		c.close()
	}
	if err := Configure([]Channel{{Base: p.base, Token: "good"}}, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "three connections", func() bool { _, _, _, c := p.snapshot(); return c >= 3 })
	if st := Status().Channels[0]; st.AuthFailed {
		t.Fatalf("normal disconnects counted as auth failure: %+v", st)
	}
	waitFor(t, 3*time.Second, "latest snapshot applied", func() bool {
		got := entryoverride.Lookup("r.test", 0)
		return len(got) == 1 && got[0].String() != "192.0.2.1"
	})
}

func TestRealtimePullWhenWSDown(t *testing.T) {
	setup(t, "pull.test")
	events := collectSubs(t)
	p := newFakePanel(t)
	p.tokens["ro-cred"] = true
	p.wsDisabled = true
	p.entryState = map[string]any{"ready": true, "entries": []any{
		map[string]any{"server": "pull.test", "chainId": 3, "ips": []string{"198.51.100.21"}, "rev": 5}}}
	p.subRevs = map[string]any{"subs": []any{map[string]any{"key": "pkg:1", "rev": "p1"}}}
	if err := Configure([]Channel{{Base: p.base, RT: "ro-cred"}}, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, "pulled entry", func() bool { return entryoverride.Lookup("pull.test", 0) != nil })
	waitFor(t, 3*time.Second, "pulled sub rev", func() bool { return len(events()) == 1 })
	if e := events()[0]; e.key != "pkg:1" || e.rev != "p1" {
		t.Fatalf("event = %+v", e)
	}
	_, _, rpc, _ := p.snapshot()
	if len(rpc) == 0 || rpc[0]["rt"] != "ro-cred" || rpc[0]["token"] != nil || rpc[0]["method"] != "GET" {
		t.Fatalf("rpc auth = %+v", rpc)
	}
	// 连不上期间每隔 pullInterval 再拉
	waitFor(t, 3*time.Second, "periodic pulls", func() bool { _, _, rpc, _ := p.snapshot(); return len(rpc) >= 6 })
	st := Status().Channels[0]
	if st.Auth != "rt" || st.State == stateConnected || st.LastError == "" || st.LastPullAt == 0 {
		t.Fatalf("status = %+v", st)
	}
	if len(events()) != 1 {
		t.Fatalf("same rev re-delivered: %+v", events())
	}
}

func TestRealtimeOldPanelPull404(t *testing.T) {
	setup(t, "x.test")
	p := newFakePanel(t)
	p.tokens["good"] = true
	p.wsDisabled = true // 拉取接口也是 404（entryState / subRevs 为 nil）
	if err := Configure([]Channel{{Base: p.base, Token: "good"}}, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, "a pull attempt", func() bool { _, _, rpc, _ := p.snapshot(); return len(rpc) >= 2 })
	if len(Entries()) != 0 {
		t.Fatalf("entries = %+v", Entries())
	}
}

func TestNormalizeChannels(t *testing.T) {
	got, err := normalizeChannels([]Channel{
		{Base: "https://Panel.Example.com/", RT: "r1"},
		{Base: "panel.example.com", Token: "t1"},
		{Base: "https://panel.example.com", Token: "t2"}, // 同一主控只要一条登录态
		{Base: "https://sub.example.com", RT: "r2"},
		{Base: "https://sub.example.com", RT: "r3"}, // 没登录：几份订阅各一条
		{Base: "https://sub.example.com", RT: "r3"}, // 重复的去掉
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Base != "https://panel.example.com" || got[0].Token != "t1" ||
		got[1].RT != "r2" || got[2].RT != "r3" {
		t.Fatalf("normalized = %+v", got)
	}
	if got[0].scope() != entryoverride.ScopeUser || got[1].scope() == got[2].scope() {
		t.Fatal("scopes: token channels share the user scope, each rt has its own")
	}
	if _, err := normalizeChannels([]Channel{{Base: "ftp://x"}}); err == nil {
		t.Fatal("bad base accepted")
	}
	if _, err := normalizeChannels([]Channel{{Base: "https://x"}}); err == nil {
		t.Fatal("channel without credentials accepted")
	}
}

func TestApplyJSONShorthandAndStop(t *testing.T) {
	setup(t)
	p := newFakePanel(t)
	p.tokens["good"] = true
	if err := ApplyJSON([]byte(`{"base":"` + p.base + `","token":"good","hook":{"url":"http://127.0.0.1:7899/api/internal/subscription-changed"}}`)); err != nil {
		t.Fatal(err)
	}
	st := Status()
	if len(st.Channels) != 1 || st.Hook == nil || st.Hook.URL == "" {
		t.Fatalf("status = %+v", st)
	}
	if err := ApplyJSON([]byte(`{"hook":{"url":"not a url"}}`)); err == nil {
		t.Fatal("bad hook accepted")
	}
	if err := ApplyJSON([]byte(``)); err != nil {
		t.Fatal(err)
	}
	if st := Status(); len(st.Channels) != 0 || st.Hook != nil {
		t.Fatalf("empty body should stop everything: %+v", st)
	}
}

func TestReconnectPolicy(t *testing.T) {
	p := newReconnectPolicy()
	if d := p.connectionEnded(false, 0); d != timing.initialBackoff {
		t.Fatalf("first failure = %v", d)
	}
	if d := p.connectionEnded(false, 0); d != 2*timing.initialBackoff {
		t.Fatalf("second failure = %v", d)
	}
	for i := 0; i < 10; i++ {
		p.connectionEnded(false, 0)
	}
	if p.backoff != timing.maxBackoff {
		t.Fatalf("backoff not capped: %v", p.backoff)
	}
	if d := p.connectionEnded(true, timing.stableAfter); d != timing.initialBackoff || p.backoff != timing.initialBackoff {
		t.Fatalf("stable connection should reset backoff: %v", d)
	}
	// 连续三次秒关 = 鉴权失败；中间夹一次连不上就打断「连续」
	p.connectionEnded(true, 0)
	p.connectionEnded(false, 0)
	p.connectionEnded(true, 0)
	if p.connectionEnded(true, 0); p.authFailed {
		t.Fatal("non-consecutive short-lived connections counted as auth failure")
	}
	if d := p.connectionEnded(true, 0); !p.authFailed || d != timing.authFailureBackoff {
		t.Fatalf("third consecutive short-lived connection = %v (authFailed %v)", d, p.authFailed)
	}
	if d := p.connectionEnded(true, 0); d != timing.authFailureBackoff {
		t.Fatalf("stays in auth-failure backoff: %v", d)
	}
	if p.connectionEnded(true, timing.stableAfter); p.authFailed {
		t.Fatal("a stable connection should clear auth failure")
	}
}

func TestResumeDelay(t *testing.T) {
	if d := resumeDelay(0, false); d > timing.resumeJitterMax {
		t.Fatalf("no previous attempt: %v", d)
	}
	if d := resumeDelay(10*time.Millisecond, true); d < timing.kickMinInterval-10*time.Millisecond {
		t.Fatalf("kick too soon after the last attempt: %v", d)
	}
}
