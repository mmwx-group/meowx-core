package provider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	P "github.com/metacubex/mihomo/constant/provider"
)

func dumpKeys(t *testing.T, s ruleStrategy) []string {
	t.Helper()
	m, ok := s.(mrsRuleStrategy)
	if !ok {
		t.Fatalf("strategy %T is not mrs", s)
	}
	var keys []string
	m.DumpMrs(func(key string) bool { keys = append(keys, key); return true })
	return keys
}

func equalKeys(a, b []string) bool {
	return strings.Join(a, "\n") == strings.Join(b, "\n")
}

const domainText = "example.com\n+.google.com\n.only-sub.org\nfoo.bar.net\n# comment\n"
const domainYaml = "payload:\n  - 'example.com'\n  - '+.google.com'\n  - '.only-sub.org'\n"
const ipText = "1.1.1.0/24\n2001:db8::/32\n10.0.0.1/32\n"

func TestMrsCacheMissThenHit(t *testing.T) {
	for _, c := range []struct {
		name     string
		behavior P.RuleBehavior
		format   P.RuleFormat
		buf      string
	}{
		{"domain-text", P.Domain, P.TextRule, domainText},
		{"domain-yaml", P.Domain, P.YamlRule, domainYaml},
		{"ipcidr-text", P.IPCIDR, P.TextRule, ipText},
	} {
		t.Run(c.name, func(t *testing.T) {
			cache := filepath.Join(t.TempDir(), "rs.txt"+mrsCacheSuffix)
			want, err := rulesParse([]byte(c.buf), newStrategy(c.behavior, nil), c.format)
			if err != nil {
				t.Fatal(err)
			}

			first, err := cachedRulesParse(cache, []byte(c.buf), newStrategy(c.behavior, nil), c.format)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(cache); err != nil {
				t.Fatalf("cache not written: %v", err)
			}
			if !equalKeys(dumpKeys(t, first), dumpKeys(t, want)) || first.Count() != want.Count() {
				t.Fatalf("first parse differs")
			}

			// 第二次走缓存，结果与直接解析一致（命中时确实没解析原文见 TestMrsCacheHitSkipsParse）
			second, err := cachedRulesParse(cache, []byte(c.buf), newStrategy(c.behavior, nil), c.format)
			if err != nil {
				t.Fatal(err)
			}
			if !equalKeys(dumpKeys(t, second), dumpKeys(t, want)) || second.Count() != want.Count() {
				t.Fatalf("cached parse differs: %v vs %v", dumpKeys(t, second), dumpKeys(t, want))
			}
		})
	}
}

// 命中时真的不解析原文：缓存里放的是另一份列表的 mrs，哈希头写成当前原文的，结果应当是缓存那份。
func TestMrsCacheHitSkipsParse(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "rs.txt"+mrsCacheSuffix)
	other, err := rulesParse([]byte("from-cache.example\n"), newStrategy(P.Domain, nil), P.TextRule)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeMrsCache(cache, mrsCacheKey([]byte(domainText), P.TextRule), other.(mrsRuleStrategy)); err != nil {
		t.Fatal(err)
	}
	got, err := cachedRulesParse(cache, []byte(domainText), newStrategy(P.Domain, nil), P.TextRule)
	if err != nil {
		t.Fatal(err)
	}
	if keys := dumpKeys(t, got); len(keys) != 1 || keys[0] != "from-cache.example" {
		t.Fatalf("expected cache content, got %v", keys)
	}
}

func TestMrsCacheStaleAndCorrupt(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "rs.txt"+mrsCacheSuffix)
	if _, err := cachedRulesParse(cache, []byte("old.example\n"), newStrategy(P.Domain, nil), P.TextRule); err != nil {
		t.Fatal(err)
	}
	// 原文变了：哈希不符，按新原文解析并重写缓存
	got, err := cachedRulesParse(cache, []byte("new.example\n"), newStrategy(P.Domain, nil), P.TextRule)
	if err != nil {
		t.Fatal(err)
	}
	if keys := dumpKeys(t, got); len(keys) != 1 || keys[0] != "new.example" {
		t.Fatalf("stale cache used: %v", keys)
	}
	// 同样内容换了格式写法也不能共用：格式进了哈希
	if mrsCacheKey([]byte("x"), P.TextRule) == mrsCacheKey([]byte("x"), P.YamlRule) {
		t.Fatal("format not in key")
	}

	// 缓存被截断：哈希头对得上、mrs 读不出来 → 退回解析
	data, err := os.ReadFile(cache)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, data[:len(data)-8], 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = cachedRulesParse(cache, []byte("new.example\n"), newStrategy(P.Domain, nil), P.TextRule)
	if err != nil {
		t.Fatal(err)
	}
	if keys := dumpKeys(t, got); len(keys) != 1 || keys[0] != "new.example" {
		t.Fatalf("corrupt cache: %v", keys)
	}
	// 目录里不留临时文件
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("leftover tmp %s", e.Name())
		}
	}
}

func TestMrsCacheSkipped(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "rs.txt"+mrsCacheSuffix)
	// classical 没有 mrs 形式（cachedRulesParse 按这个判断跳过）
	if _, ok := newStrategy(P.Classical, nil).(mrsRuleStrategy); ok {
		t.Fatal("classical should not be mrs")
	}
	// 空列表不写
	if _, err := cachedRulesParse(cache, []byte("# nothing\n"), newStrategy(P.Domain, nil), P.TextRule); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Fatalf("cache should not exist: %v", err)
	}
	// 没有路径（非 http 规则集）照常解析
	if s, err := cachedRulesParse("", []byte(domainText), newStrategy(P.Domain, nil), P.TextRule); err != nil || s.Count() == 0 {
		t.Fatalf("no-path parse: %v", err)
	}
}
