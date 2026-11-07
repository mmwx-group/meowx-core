//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/tailscale/ipn/ipnstate"
	"github.com/metacubex/tailscale/types/key"
)

func TestConvertTailscaleStatus(t *testing.T) {
	seen := time.Date(2026, 11, 6, 8, 0, 0, 0, time.UTC)
	st := &ipnstate.Status{
		BackendState:   "Running",
		MagicDNSSuffix: "meowx.internal",
		Self:           &ipnstate.PeerStatus{ID: "15", HostName: "pixel", TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.69.123.58")}, Online: true},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			key.NewNode().Public(): {ID: "3", HostName: "openwrt", OS: "linux", TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.124.214.252")}, Online: true, Active: true, CurAddr: "203.0.113.7:41641", Relay: "meowx-1"},
			key.NewNode().Public(): {ID: "5", HostName: "mac", Relay: "meowx-1", LastSeen: seen},
		},
	}
	out := convertTailscaleStatus(st)
	if out.State != "Running" || out.Self == nil || out.Self.ID != "15" || out.Self.Addresses[0] != "100.69.123.58" {
		t.Fatalf("self 不对：%+v", out)
	}
	if len(out.Peers) != 2 || out.Peers[0].Name != "mac" || out.Peers[1].Name != "openwrt" {
		t.Fatalf("对端应按名字排序：%+v", out.Peers)
	}
	if p := out.Peers[1]; p.CurAddr != "203.0.113.7:41641" || p.Relay != "meowx-1" || !p.Online || !p.Active {
		t.Fatalf("直连 / 中继不对：%+v", p)
	}
	if p := out.Peers[0]; p.CurAddr != "" || p.Online || p.LastSeen != "2026-11-06T08:00:00Z" {
		t.Fatalf("离线设备不对：%+v", p)
	}
	// 没登记（Self 没有 ID）时不带 self
	if out := convertTailscaleStatus(&ipnstate.Status{BackendState: "NeedsLogin", Self: &ipnstate.PeerStatus{}}); out.Self != nil || out.Peers == nil {
		t.Fatalf("没登记时不该有 self、peers 不为 nil：%+v", out)
	}
}

func TestTailscaleStatusRegistry(t *testing.T) {
	old, cur := &Tailscale{}, &Tailscale{}
	unregisterOld := registerTailscaleOutbound("喵窝", old)
	unregisterCur := registerTailscaleOutbound("喵窝", cur) // 配置重载：新的同名出站顶替
	unregisterOld()                                       // 旧的被回收时只删自己那一条
	tailscaleOutboundsMu.Lock()
	got := tailscaleOutbounds["喵窝"]
	tailscaleOutboundsMu.Unlock()
	if got != cur {
		t.Fatal("旧出站关掉后，登记的应仍是新的那个")
	}
	unregisterCur()
	if st, err := TailscaleStatusByName(context.Background(), "喵窝"); st != nil || err != nil {
		t.Fatalf("没有这个出站时应回 (nil, nil)，得到 %v %v", st, err)
	}
}
