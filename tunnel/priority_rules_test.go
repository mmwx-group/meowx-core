package tunnel_test

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	RC "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/tunnel"
)

func named(name string) C.Proxy {
	return adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: name}))
}

// 三个出站：DIRECT、GLOBAL（全局模式用的）、喵窝（组网）；订阅规则只有 MATCH,PROXY
func setup(t *testing.T, priority []C.Rule) {
	t.Helper()
	tunnel.UpdateProxies(map[string]C.Proxy{
		"DIRECT": named("DIRECT"),
		"GLOBAL": named("GLOBAL"),
		"PROXY":  named("PROXY"),
		"喵窝":     named("喵窝"),
	}, nil)
	tunnel.UpdateRules([]C.Rule{RC.NewMatch("PROXY")}, nil, nil)
	tunnel.UpdatePriorityRules(priority)
	t.Cleanup(func() {
		tunnel.UpdatePriorityRules(nil)
		tunnel.SetMode(tunnel.Rule)
	})
}

func meshRules(t *testing.T) []C.Rule {
	t.Helper()
	cgnat, err := RC.NewIPCIDR("100.64.0.0/10", "喵窝", RC.WithIPCIDRNoResolve(true))
	if err != nil {
		t.Fatal(err)
	}
	site, err := RC.NewIPCIDR("192.168.1.0/24", "喵窝", RC.WithIPCIDRNoResolve(true))
	if err != nil {
		t.Fatal(err)
	}
	return []C.Rule{cgnat, RC.NewDomainSuffix("meowx.internal", "喵窝"), site}
}

func resolve(t *testing.T, md *C.Metadata) string {
	t.Helper()
	proxy, _, err := tunnel.ResolveMetadataForTest(md)
	if err != nil {
		t.Fatal(err)
	}
	return proxy.Name()
}

func byIP(ip string) *C.Metadata {
	return &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr(ip), DstPort: 80}
}

func byHost(host string) *C.Metadata {
	return &C.Metadata{NetWork: C.TCP, Host: host, DstPort: 80}
}

func TestPriorityRulesAllModes(t *testing.T) {
	setup(t, meshRules(t))
	want := map[tunnel.TunnelMode]string{tunnel.Rule: "PROXY", tunnel.Global: "GLOBAL", tunnel.Direct: "DIRECT"}
	for mode, other := range want {
		tunnel.SetMode(mode)
		// 命中：三种模式下都交给喵窝
		for _, md := range []*C.Metadata{byIP("100.100.1.2"), byIP("192.168.1.2"), byHost("nas.meowx.internal")} {
			if got := resolve(t, md); got != "喵窝" {
				t.Errorf("mode %v %v: got %s, want 喵窝", mode, md.RemoteAddress(), got)
			}
		}
		// 没命中：照旧按模式走
		for _, md := range []*C.Metadata{byIP("8.8.8.8"), byIP("192.168.2.2"), byHost("example.com")} {
			if got := resolve(t, md); got != other {
				t.Errorf("mode %v %v: got %s, want %s", mode, md.RemoteAddress(), got, other)
			}
		}
	}
}

// 不配置时行为不变：组网地址也按模式 / 订阅规则走
func TestPriorityRulesEmptyUnchanged(t *testing.T) {
	setup(t, nil)
	want := map[tunnel.TunnelMode]string{tunnel.Rule: "PROXY", tunnel.Global: "GLOBAL", tunnel.Direct: "DIRECT"}
	for mode, other := range want {
		tunnel.SetMode(mode)
		for _, md := range []*C.Metadata{byIP("100.100.1.2"), byHost("nas.meowx.internal")} {
			if got := resolve(t, md); got != other {
				t.Errorf("mode %v %v: got %s, want %s", mode, md.RemoteAddress(), got, other)
			}
		}
	}
}

// 规则指向的出站不存在时跳过这条，不拦后面的
func TestPriorityRulesMissingAdapter(t *testing.T) {
	missing, _ := RC.NewIPCIDR("100.64.0.0/10", "不存在", RC.WithIPCIDRNoResolve(true))
	setup(t, append([]C.Rule{missing}, meshRules(t)...))
	tunnel.SetMode(tunnel.Direct)
	if got := resolve(t, byIP("100.100.1.2")); got != "喵窝" {
		t.Errorf("got %s, want 喵窝", got)
	}
}
