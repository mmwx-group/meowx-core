package outbound

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/component/entryoverride"
	C "github.com/metacubex/mihomo/constant"
)

// 不经拨号器解析节点 server 的地方（ss / ssr / socks5 的 UDP、hysteria、wireguard 的对端地址、mieru）同样认入口覆盖表。
func TestResolveUDPAddrUsesEntryOverride(t *testing.T) {
	if err := entryoverride.Load(filepath.Join(t.TempDir(), "entry-overrides.json")); err != nil {
		t.Fatal(err)
	}
	entryoverride.SetServerSource(func() []entryoverride.Server { return []entryoverride.Server{{Host: "udp-entry.test"}} })
	defer entryoverride.SetServerSource(nil)
	entryoverride.Apply("https://panel.test", entryoverride.ScopeUser, entryoverride.OriginPush, entryoverride.Update{
		Server: "udp-entry.test", Rev: 1,
		IPs: []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")},
	})

	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		addr, err := resolveUDPAddr(context.Background(), "udp", "udp-entry.test:443", C.DualStack)
		if err != nil {
			t.Fatal(err)
		}
		if addr.Port != 443 {
			t.Fatalf("port changed: %v", addr)
		}
		seen[addr.IP.String()] = true
	}
	if !seen["192.0.2.10"] {
		t.Fatalf("dual stack should prefer IPv4 from the override: %v", seen)
	}
	addr, err := resolveUDPAddr(context.Background(), "udp", "udp-entry.test:443", C.IPv6Only)
	if err != nil || addr.IP.String() != "2001:db8::10" {
		t.Fatalf("ipv6-only = %v, %v", addr, err)
	}

	ips, err := mieruDNSResolver{prefer: C.DualStack}.LookupIP(context.Background(), "udp", "udp-entry.test")
	if err != nil || len(ips) != 2 {
		t.Fatalf("mieru lookup = %v, %v", ips, err)
	}
}
