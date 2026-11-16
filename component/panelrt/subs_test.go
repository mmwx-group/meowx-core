package panelrt

import (
	"encoding/json"
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
)

func ips(list ...string) []netip.Addr {
	out := make([]netip.Addr, len(list))
	for i, s := range list {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

// 订阅变更 hook：exec 追加订阅键、环境变量带 rev；url 收到 {"key","rev","base"}；同一份订阅 30s 内的多次变更合成一次。
func TestSubscriptionHooksAndThrottle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("exec hook test uses /bin/sh")
	}
	setup(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "hook.log")

	var mu sync.Mutex
	var posted []map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		posted = append(posted, body)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	hook := &Hook{
		Exec: []string{"/bin/sh", "-c", `printf '%s|%s|%s\n' "$1" "$MEOWX_SUB_REV" "$MEOWX_SUB_BASE" >> "` + out + `"`, "meowx-hook"},
		URL:  srv.URL + "/api/internal/subscription-changed",
	}
	if err := Configure(nil, hook); err != nil {
		t.Fatal(err)
	}
	// Configure(nil) 停掉通道，但 hook 还要留着给这个用例：直接设
	subs.setHook(hook)
	events := collectSubs(t)

	base := "https://panel.example.com"
	subs.changed(base, "pkg:12", "r1")
	waitFor(t, 3*time.Second, "first delivery", func() bool { return len(events()) == 1 })
	// 30s（测试里 300ms）内又变两次：合成一次、通知最新的
	subs.changed(base, "pkg:12", "r2")
	subs.changed(base, "pkg:12", "r3")
	time.Sleep(timing.subMinInterval / 2)
	if len(events()) != 1 {
		t.Fatal("second delivery inside the throttle window")
	}
	waitFor(t, 3*time.Second, "throttled delivery", func() bool { return len(events()) == 2 })
	if e := events()[1]; e.rev != "r3" {
		t.Fatalf("throttled delivery rev = %q", e.rev)
	}
	// 外壳自己刚拉过（NoteSubscriptionRev）：主控再说同一个 rev 不通知
	NoteSubscriptionRev(base, "pkg:12", "r4")
	subs.changed(base, "pkg:12", "r4")
	time.Sleep(timing.subMinInterval + 100*time.Millisecond)
	if len(events()) != 2 {
		t.Fatalf("known rev re-delivered: %+v", events())
	}
	// 旧主控：全部订阅（键为空）
	subs.changed(base, "", "legacy")
	waitFor(t, 3*time.Second, "all-subs delivery", func() bool { return len(events()) == 3 })

	waitFor(t, 5*time.Second, "exec hook output", func() bool {
		data, _ := os.ReadFile(out)
		return strings.Count(string(data), "\n") == 3
	})
	data, _ := os.ReadFile(out)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	want := []string{"pkg:12|r1|" + base, "pkg:12|r3|" + base, "|legacy|" + base}
	for i, w := range want {
		if lines[i] != w {
			t.Fatalf("exec hook line %d = %q, want %q", i, lines[i], w)
		}
	}
	waitFor(t, 3*time.Second, "url hook", func() bool { mu.Lock(); defer mu.Unlock(); return len(posted) == 3 })
	mu.Lock()
	if posted[1]["key"] != "pkg:12" || posted[1]["rev"] != "r3" || posted[1]["base"] != base || posted[2]["key"] != "" {
		t.Fatalf("posted = %+v", posted)
	}
	mu.Unlock()

	// 已知 rev 落盘：换数据目录再换回来，同一个 rev 不再通知
	path := subs.path
	subs.load(filepath.Join(dir, "other.json"))
	subs.load(path)
	subs.changed(base, "pkg:12", "r4")
	time.Sleep(timing.subMinInterval + 100*time.Millisecond)
	if len(events()) != 3 {
		t.Fatalf("persisted rev not honoured: %+v", events())
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"rev": "r4"`) || strings.Contains(string(raw), "legacy") {
		t.Fatalf("realtime-subs.json = %s", raw)
	}
}
