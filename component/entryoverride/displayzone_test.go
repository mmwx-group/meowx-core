package entryoverride

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// POSIX TZ 串构造的时区：标准时偏移、夏令时规则、尖括号名字；不合法的回 nil。
func TestPosixTZLocation(t *testing.T) {
	offset := func(tz string, at time.Time) int {
		t.Helper()
		loc := posixTZLocation(tz)
		if loc == nil {
			t.Fatalf("%q: nil", tz)
		}
		_, off := at.In(loc).Zone()
		return off
	}
	winter := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	summer := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		tz     string
		at     time.Time
		offset int
	}{
		{"CST-8", winter, 8 * 3600},
		{"CST-8", summer, 8 * 3600},
		{"CET-1CEST,M3.5.0,M10.5.0/3", winter, 3600},
		{"CET-1CEST,M3.5.0,M10.5.0/3", summer, 2 * 3600},
		// 2026 年欧洲夏令时 3 月 29 日 01:00 UTC 开始
		{"CET-1CEST,M3.5.0,M10.5.0/3", time.Date(2026, 3, 29, 0, 59, 0, 0, time.UTC), 3600},
		{"CET-1CEST,M3.5.0,M10.5.0/3", time.Date(2026, 3, 29, 1, 0, 0, 0, time.UTC), 2 * 3600},
		{"<+0330>-3:30", summer, 3*3600 + 30*60},
		{"EST5EDT,M3.2.0,M11.1.0", winter, -5 * 3600},
		{"EST5EDT,M3.2.0,M11.1.0", summer, -4 * 3600},
		{"UTC0", summer, 0},
	}
	for _, c := range cases {
		if got := offset(c.tz, c.at); got != c.offset {
			t.Errorf("%q at %v: offset %d, want %d", c.tz, c.at, got, c.offset)
		}
	}
	for _, bad := range []string{"", "   ", "CST", "-8", "AB-8", "<+03>", "<+0330", "XYZ99", "XYZ-8:77", "乱写"} {
		if posixTZLocation(trimTZ(bad)) != nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	// 夏令时部分写坏了：至少标准时是对的
	if got := offset("CET-1CEST,garbage", winter); got != 3600 {
		t.Errorf("broken DST rule: offset %d, want 3600", got)
	}
}

// 读 /etc/TZ：TZ 环境变量为空、Go 找不到本地时区（time.Local 叫 "UTC"）时才用；读不到 / 乱写回落 time.Local；内容变了重建。
func TestDefaultDisplayZone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "TZ")
	oldPath, oldLocal := etcTZPath, time.Local
	t.Cleanup(func() {
		etcTZPath, time.Local = oldPath, oldLocal
		tzCache.checked, tzCache.content, tzCache.loc = time.Time{}, "", nil
	})
	etcTZPath = path
	t.Setenv("TZ", "")
	fresh := func() *time.Location {
		tzCache.checked = time.Time{}
		return defaultDisplayZone()
	}
	off := func(l *time.Location) int {
		_, o := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC).In(l).Zone()
		return o
	}

	time.Local = time.UTC // 等同 OpenWrt 上 Go 的回落
	if fresh() != time.Local {
		t.Fatal("no /etc/TZ: want time.Local")
	}
	if err := os.WriteFile(path, []byte("CST-8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if o := off(fresh()); o != 8*3600 {
		t.Fatalf("CST-8: offset %d", o)
	}
	_ = os.WriteFile(path, []byte("CET-1CEST,M3.5.0,M10.5.0/3\n"), 0o644)
	if o := off(defaultDisplayZone()); o != 8*3600 {
		t.Fatalf("within recheck window should keep cache, offset %d", o)
	}
	if o := off(fresh()); o != 3600 {
		t.Fatalf("changed to CET: offset %d", o)
	}
	_ = os.WriteFile(path, []byte("乱写\n"), 0o644)
	if fresh() != time.Local {
		t.Fatal("garbage: want time.Local")
	}
	_ = os.WriteFile(path, []byte("CST-8\n"), 0o644)
	t.Setenv("TZ", "Asia/Tokyo")
	if fresh() != time.Local {
		t.Fatal("TZ set: want time.Local")
	}
	t.Setenv("TZ", "")
	time.Local = time.FixedZone("Local", 9*3600) // /etc/localtime 读得到
	if fresh() != time.Local {
		t.Fatal("real local zone: want time.Local")
	}
}

// 提示里的时间按显示时区：「今天」也按显示时区判断（UTC 里已是昨天，上海已是今天）。
func TestIconTitleDisplayZone(t *testing.T) {
	old := displayZone
	t.Cleanup(func() { displayZone = old })
	shanghai := posixTZLocation("CST-8")
	displayZone = func() *time.Location { return shanghai }

	at := time.Date(2026, 11, 19, 15, 49, 0, 0, time.UTC) // 上海 23:49
	sw := func(d time.Time) string { return iconTitle(ips("192.0.2.1"), nil, d, at) }
	if s := sw(time.Date(2026, 11, 19, 15, 49, 0, 0, time.UTC)); s != "主控指定入口 192.0.2.1 · 切换于 23:49" {
		t.Fatalf("today = %q", s)
	}
	// UTC 11-18 16:30 = 上海 11-19 00:30：同一天
	if s := sw(time.Date(2026, 11, 18, 16, 30, 0, 0, time.UTC)); s != "主控指定入口 192.0.2.1 · 切换于 00:30" {
		t.Fatalf("today across UTC midnight = %q", s)
	}
	// UTC 11-18 15:00 = 上海 11-18 23:00：前一天
	if s := sw(time.Date(2026, 11, 18, 15, 0, 0, 0, time.UTC)); s != "主控指定入口 192.0.2.1 · 切换于 11-18 23:00" {
		t.Fatalf("other day = %q", s)
	}
	// UTC 2025-12-31 17:00 = 上海 2026-01-01 01:00：今年
	if s := sw(time.Date(2025, 12, 31, 17, 0, 0, 0, time.UTC)); s != "主控指定入口 192.0.2.1 · 切换于 01-01 01:00" {
		t.Fatalf("this year across UTC new year = %q", s)
	}
	if s := sw(time.Date(2025, 12, 31, 15, 0, 0, 0, time.UTC)); s != "主控指定入口 192.0.2.1 · 切换于 2025-12-31 23:00" {
		t.Fatalf("other year = %q", s)
	}
}
