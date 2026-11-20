package panelrt

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/entryoverride"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/tunnel"
)

func httpNode(t *testing.T, name, server string, port int) C.Proxy {
	t.Helper()
	h, err := outbound.NewHttp(outbound.HttpOption{Name: name, Server: server, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	return adapter.NewProxy(h)
}

// 节点名（nodes）与节点小标（icon）：用真实的节点表（tunnel.Proxies）配。
func useProxies(t *testing.T, list ...C.Proxy) {
	t.Helper()
	oldProxies, oldProviders := tunnel.Proxies(), tunnel.Providers()
	m := map[string]C.Proxy{}
	for _, p := range list {
		m[p.Name()] = p
	}
	tunnel.UpdateProxies(m, map[string]P.ProxyProvider{})
	entryoverride.InvalidateServers()
	t.Cleanup(func() {
		tunnel.UpdateProxies(oldProxies, oldProviders)
		entryoverride.InvalidateServers()
		entryoverride.SetProxyIcon(false)
	})
}

// /meowx/entries 每条的 nodes：server 规范化后等于键、端口在 ports 里（没有 ports 只比 server，[] 谁都不匹配）；没有时 []。
func TestEntriesNodes(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	ensureState()
	entryoverride.SetServerSource(proxyServers)
	useProxies(t,
		httpNode(t, "香港 01", "HK-Entry.Example.com.", 50520),
		httpNode(t, "香港 02", "hk-entry.example.com", 50523),
		httpNode(t, "香港直连", "hk-entry.example.com", 22),
		httpNode(t, "旧主控", "old.example.com", 443),
		httpNode(t, "空端口", "empty.example.com", 443),
		httpNode(t, "别的", "other.example.com", 443),
	)
	src := "https://panel.example.com"
	entryoverride.Apply(src, entryoverride.ScopeUser, entryoverride.OriginPush, entryoverride.Update{Server: "hk-entry.example.com",
		IPs: []netip.Addr{netip.MustParseAddr("203.0.113.11")}, Ports: entryoverride.PortList(50520, 50523), Rev: 1})
	entryoverride.Apply(src, entryoverride.ScopeUser, entryoverride.OriginPush, entryoverride.Update{Server: "old.example.com",
		IPs: []netip.Addr{netip.MustParseAddr("203.0.113.12")}, Rev: 1})
	entryoverride.Apply(src, entryoverride.ScopeUser, entryoverride.OriginPush, entryoverride.Update{Server: "empty.example.com",
		IPs: []netip.Addr{netip.MustParseAddr("203.0.113.13")}, Ports: entryoverride.PortList(), Rev: 1})
	entryoverride.Apply(src, entryoverride.ScopeUser, entryoverride.OriginPush, entryoverride.Update{Server: "gone.example.com",
		IPs: []netip.Addr{netip.MustParseAddr("203.0.113.14")}, Rev: 1})
	t.Cleanup(func() { entryoverride.ClearSource("") })

	got := map[string][]string{}
	for _, v := range Entries() {
		got[v.Server] = v.Nodes
	}
	want := map[string]string{
		"hk-entry.example.com": "香港 01,香港 02",
		"old.example.com":      "旧主控",
		"empty.example.com":    "",
		"gone.example.com":     "",
	}
	for k, w := range want {
		if strings.Join(got[k], ",") != w || got[k] == nil {
			t.Fatalf("nodes[%s] = %#v, want %q", k, got[k], w)
		}
	}
	data, _ := json.Marshal(map[string]any{"entries": Entries()})
	if !strings.Contains(string(data), `"nodes":[]`) || !strings.Contains(string(data), `"nodes":["香港 01","香港 02"]`) {
		t.Fatalf("entries JSON = %s", data)
	}
}

// 节点小标：缺省关；PUT 的 entryIcon 打开后，生效中覆盖的节点在节点 JSON 里带 icon，同机直连节点（端口不在 ports 里）不带。
func TestProxyIconToggle(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	ensureState()
	entryoverride.SetServerSource(proxyServers)
	hk := httpNode(t, "香港 01", "hk-entry.example.com", 50520)
	direct := httpNode(t, "香港直连", "hk-entry.example.com", 22)
	useProxies(t, hk, direct)
	entryoverride.Apply("https://panel.example.com", entryoverride.ScopeUser, entryoverride.OriginPush, entryoverride.Update{
		Server: "hk-entry.example.com", IPs: []netip.Addr{netip.MustParseAddr("203.0.113.11"), netip.MustParseAddr("203.0.113.12")},
		Ports: entryoverride.PortList(50520), Names: map[string]string{"203.0.113.11": "香港入口 A"}, Rev: 1})
	t.Cleanup(func() { entryoverride.ClearSource("") })

	icon := func(p C.Proxy) string {
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		_ = json.Unmarshal(data, &m)
		s, _ := m["icon"].(string)
		return s
	}
	if icon(hk) != "" {
		t.Fatal("icon must be off by default")
	}
	if err := ApplyJSON([]byte(`{"entryIcon":true}`)); err != nil {
		t.Fatal(err)
	}
	if !Status().EntryIcon {
		t.Fatal("status must report entryIcon")
	}
	got := icon(hk)
	if !strings.HasPrefix(got, "data:image/svg+xml,<svg ") || !strings.Contains(got, "<title>主控指定入口 香港入口 A（203.0.113.11）, 203.0.113.12 · 切换于 ") {
		t.Fatalf("icon = %s", got)
	}
	if icon(direct) != "" {
		t.Fatal("direct node on the same server must not get the icon")
	}
	// 不写 entryIcon 不改设置；写 false 关掉
	if err := ApplyJSON([]byte(`{}`)); err != nil || icon(hk) == "" {
		t.Fatalf("absent entryIcon must keep the setting (%v)", err)
	}
	if err := ApplyJSON([]byte(`{"entryIcon":false}`)); err != nil || icon(hk) != "" {
		t.Fatalf("entryIcon:false must turn it off (%v)", err)
	}
}
