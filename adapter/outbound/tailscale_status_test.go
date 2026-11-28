//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
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
			key.NewNode().Public(): {ID: "7", HostName: "nas", Online: true, Active: true, Relay: "meowx-1", PeerRelay: "203.0.113.9:40000:vni:12345", RxBytes: 4200000, TxBytes: 980000, LastHandshake: seen},
		},
	}
	out := convertTailscaleStatus(st, nil)
	if out.State != "Running" || out.Self == nil || out.Self.ID != "15" || out.Self.Addresses[0] != "100.69.123.58" {
		t.Fatalf("self 不对：%+v", out)
	}
	if len(out.Peers) != 3 || out.Peers[0].Name != "mac" || out.Peers[1].Name != "nas" || out.Peers[2].Name != "openwrt" {
		t.Fatalf("对端应按名字排序：%+v", out.Peers)
	}
	if p := out.Peers[2]; p.CurAddr != "203.0.113.7:41641" || p.Relay != "meowx-1" || !p.Online || !p.Active {
		t.Fatalf("直连 / 中继不对：%+v", p)
	}
	if p := out.Peers[0]; p.CurAddr != "" || p.Online || p.LastSeen != "2026-11-06T08:00:00Z" {
		t.Fatalf("离线设备不对：%+v", p)
	}
	if p := out.Peers[0]; p.PeerRelay != "" || p.RxBytes != 0 || p.LastHandshake != "" {
		t.Fatalf("没走设备中继、没握过手时这几项应为空：%+v", p)
	}
	if p := out.Peers[1]; p.PeerRelay != "203.0.113.9:40000:vni:12345" || p.RxBytes != 4200000 || p.TxBytes != 980000 || p.LastHandshake != "2026-11-06T08:00:00Z" {
		t.Fatalf("设备中继 / 计数 / 握手不对：%+v", p)
	}
	// 零值不输出
	if b, _ := json.Marshal(out.Peers[0]); strings.Contains(string(b), "peerRelay") || strings.Contains(string(b), "lastHandshake") || strings.Contains(string(b), "rxBytes") {
		t.Fatalf("零值不该输出：%s", b)
	}
	// 没登记（Self 没有 ID）时不带 self
	if out := convertTailscaleStatus(&ipnstate.Status{BackendState: "NeedsLogin", Self: &ipnstate.PeerStatus{}}, nil); out.Self != nil || out.Peers == nil {
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

func TestPeerRelayViaName(t *testing.T) {
	home := &ipnstate.PeerStatus{ID: "3", HostName: "home-openwrt", DNSName: "home-openwrt.meowx.internal.", Addrs: []string{"203.0.113.9:41641", "192.168.1.1:41641"}}
	sameNAT := &ipnstate.PeerStatus{ID: "4", HostName: "laptop", Addrs: []string{"203.0.113.9:52000"}}
	nas := &ipnstate.PeerStatus{ID: "8", DNSName: "nas-v6.meowx.internal.", Addrs: []string{"[2001:db8::7]:41641"}}
	solo := &ipnstate.PeerStatus{ID: "10", HostName: "office", Addrs: []string{"198.51.100.20:41641"}}
	peers := []*ipnstate.PeerStatus{home, sameNAT, nas, solo}
	onlyHome := func(q *ipnstate.PeerStatus) bool { return q == home }
	cases := []struct {
		name, relay string
		relayTarget func(*ipnstate.PeerStatus) bool
		want        string
	}{
		{"v4 + vni，唯一一台", "198.51.100.20:40000:vni:12345", nil, "office"},
		{"v4 不带 vni 字样", "198.51.100.20:40000:12345", nil, "office"},
		{"v6 带方括号", "[2001:db8::7]:40000:vni:9", nil, "nas-v6"},
		{"v6 不带 vni 字样", "[2001:db8::7]:40000:9", nil, "nas-v6"},
		{"同一公网 IP 两台、不知道谁是中继：不认", "203.0.113.9:40000:vni:1", nil, ""},
		{"同一公网 IP 两台、只有一台授权给本机", "203.0.113.9:40000:vni:1", onlyHome, "home-openwrt"},
		{"同一公网 IP 两台、都没授权：不认", "203.0.113.9:40000:vni:1", func(*ipnstate.PeerStatus) bool { return false }, ""},
		{"同一公网 IP 两台、都授权：不认", "203.0.113.9:40000:vni:1", func(*ipnstate.PeerStatus) bool { return true }, ""},
		{"同一公网 IP 两台、端口碰巧对上一台也不认（不看端口）", "203.0.113.9:52000:vni:7", nil, ""},
		{"对不上", "192.0.2.1:40000:vni:1", nil, ""},
		{"写法不对", "garbage", nil, ""},
	}
	for _, c := range cases {
		target := &ipnstate.PeerStatus{ID: "9", HostName: "po0", PeerRelay: c.relay}
		if got := peerRelayViaName(target, append(peers, target), c.relayTarget); got != c.want {
			t.Errorf("%s：%q 应认成 %q，得到 %q", c.name, c.relay, c.want, got)
		}
	}
	// 对端自己的端点不算（中继地址碰巧是它自己的公网 IP）
	self := &ipnstate.PeerStatus{ID: "9", HostName: "po0", PeerRelay: "192.0.2.1:40000:vni:1", Addrs: []string{"192.0.2.1:41641"}}
	if got := peerRelayViaName(self, []*ipnstate.PeerStatus{self}, nil); got != "" {
		t.Errorf("对端自己不该认成中继：%q", got)
	}

	// 经 convertTailscaleStatus 输出
	st := &ipnstate.Status{
		BackendState: "Running",
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			key.NewNode().Public(): home,
			key.NewNode().Public(): sameNAT,
			key.NewNode().Public(): {ID: "9", HostName: "po0", Online: true, Active: true, PeerRelay: "203.0.113.9:40000:vni:12345"},
		},
	}
	out := convertTailscaleStatus(st, onlyHome)
	if out.Peers[0].Name != "home-openwrt" || out.Peers[0].PeerRelayVia != "" || out.Peers[2].Name != "po0" || out.Peers[2].PeerRelayVia != "home-openwrt" {
		t.Fatalf("peerRelayVia 不对：%+v", out.Peers)
	}
	if out := convertTailscaleStatus(st, nil); out.Peers[2].PeerRelayVia != "" {
		t.Fatalf("认不出唯一一台时应为空：%+v", out.Peers[2])
	}
}
