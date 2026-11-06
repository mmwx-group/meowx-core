package tunnel

import (
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// MeowX：先于出站模式匹配的规则（配置顶层的 priority-rules，写法同 rules）。
// 规则 / 全局 / 直连三种模式下都先查它，命中就用它的出站；没命中照旧按模式走。
// 客户端把组网（喵窝）的地址段放在这里，全局 / 直连模式下也能访问组网里的设备（同 MeowX iOS / macOS）。
// 不配置时为空，resolveMetadata 的行为一个字节不变。
var priorityRules []C.Rule

// UpdatePriorityRules 换掉先于出站模式匹配的规则（随配置重载）。
func UpdatePriorityRules(newRules []C.Rule) {
	configMux.Lock()
	priorityRules = newRules
	configMux.Unlock()
}

// PriorityRules 当前先于出站模式匹配的规则。
func PriorityRules() []C.Rule {
	configMux.RLock()
	defer configMux.RUnlock()
	return priorityRules
}

// matchPriority 按顺序查 priority-rules，第一条命中且出站存在（UDP 时还要支持 UDP）的就用它；都没命中返回 nil。
// 不处理 PASS / REMATCH 这类特殊出站（这张表只放直接指向某个出站的规则）。
func matchPriority(metadata *C.Metadata, helper C.RuleMatchHelper) (C.Proxy, C.Rule) {
	configMux.RLock()
	defer configMux.RUnlock()
	for _, rule := range priorityRules {
		matched, ada := rule.Match(metadata, helper)
		if !matched {
			continue
		}
		adapter, ok := proxies[ada]
		if !ok {
			continue
		}
		if metadata.NetWork == C.UDP && !adapter.SupportUDP() {
			log.Debugln("[Rule] priority rule %s: %s UDP is not supported", rule.Payload(), adapter.Name())
			continue
		}
		return adapter, rule
	}
	return nil, nil
}
