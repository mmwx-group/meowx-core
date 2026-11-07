package executor

import (
	"testing"

	"github.com/metacubex/mihomo/config"
)

// MeowX：priority-rules 的解析（executor 包里测：config 的 linkname 实现在这里）
func TestParsePriorityRules(t *testing.T) {
	base := "proxies:\n  - {name: 喵窝, type: direct}\nrules:\n  - MATCH,DIRECT\n"

	cfg, err := config.Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PriorityRules != nil {
		t.Fatalf("不写 priority-rules 时应为空，得到 %d 条", len(cfg.PriorityRules))
	}

	cfg, err = config.Parse([]byte(base + "priority-rules:\n  - IP-CIDR,100.64.0.0/10,喵窝,no-resolve\n  - DOMAIN-SUFFIX,meowx.internal,喵窝\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.PriorityRules) != 2 || cfg.PriorityRules[0].Adapter() != "喵窝" || cfg.PriorityRules[1].Payload() != "meowx.internal" {
		t.Fatalf("priority-rules 解析不对：%v", cfg.PriorityRules)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("rules 不应受影响，得到 %d 条", len(cfg.Rules))
	}

	// 出站不存在：和 rules 一样整份报错
	if _, err = config.Parse([]byte(base + "priority-rules:\n  - IP-CIDR,100.64.0.0/10,不存在,no-resolve\n")); err == nil {
		t.Fatal("出站不存在时应报错")
	}
}
