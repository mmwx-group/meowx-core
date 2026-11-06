//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/metacubex/tailscale/ipn/ipnstate"
)

// MeowX：按出站名找到 tailscale 出站（配置重载后新旧两个同名出站会短暂并存，登记的是最新的那个；
// 旧的关掉时只删自己那一条）。
var (
	tailscaleOutboundsMu sync.Mutex
	tailscaleOutbounds   = map[string]*Tailscale{}
)

func registerTailscaleOutbound(name string, t *Tailscale) func() {
	tailscaleOutboundsMu.Lock()
	tailscaleOutbounds[name] = t
	tailscaleOutboundsMu.Unlock()
	return func() {
		tailscaleOutboundsMu.Lock()
		if tailscaleOutbounds[name] == t {
			delete(tailscaleOutbounds, name)
		}
		tailscaleOutboundsMu.Unlock()
	}
}

// TailscaleStatusByName 取名字是 name 的 tailscale 出站的状态；没有这个出站回 (nil, nil)。
// 出站是懒启动的（第一次有连接才连控制服务器），这里会先启动它：问状态的是客户端界面，那时就该让设备上线。
func TailscaleStatusByName(ctx context.Context, name string) (*TailscaleStatus, error) {
	tailscaleOutboundsMu.Lock()
	t := tailscaleOutbounds[name]
	tailscaleOutboundsMu.Unlock()
	if t == nil {
		return nil, nil
	}
	return t.Status(ctx)
}

// Status 本机状态与各对端（会先启动出站，见 TailscaleStatusByName）。
func (t *Tailscale) Status(ctx context.Context) (*TailscaleStatus, error) {
	if err := t.ensureStarted(ctx); err != nil {
		return nil, err
	}
	lc, err := t.server.LocalClient()
	if err != nil {
		return nil, err
	}
	st, err := lc.Status(ctx)
	if err != nil {
		return nil, err
	}
	return convertTailscaleStatus(st), nil
}

func convertTailscaleStatus(st *ipnstate.Status) *TailscaleStatus {
	out := &TailscaleStatus{
		State:          st.BackendState,
		AuthURL:        st.AuthURL,
		Peers:          []TailscalePeerStatus{},
		Health:         st.Health,
		MagicDNSSuffix: st.MagicDNSSuffix,
	}
	if st.Self != nil && st.Self.ID != "" {
		self := convertTailscalePeer(st.Self)
		out.Self = &self
	}
	for _, p := range st.Peer {
		if p == nil {
			continue
		}
		out.Peers = append(out.Peers, convertTailscalePeer(p))
	}
	sort.Slice(out.Peers, func(i, j int) bool { return out.Peers[i].Name < out.Peers[j].Name })
	return out
}

func convertTailscalePeer(p *ipnstate.PeerStatus) TailscalePeerStatus {
	addrs := make([]string, 0, len(p.TailscaleIPs))
	for _, ip := range p.TailscaleIPs {
		addrs = append(addrs, ip.String())
	}
	var lastSeen string
	if !p.LastSeen.IsZero() {
		lastSeen = p.LastSeen.UTC().Format(time.RFC3339)
	}
	return TailscalePeerStatus{
		ID:        string(p.ID),
		Name:      p.HostName,
		DNSName:   p.DNSName,
		OS:        p.OS,
		Addresses: addrs,
		Online:    p.Online,
		Active:    p.Active,
		CurAddr:   p.CurAddr,
		Relay:     p.Relay,
		LastSeen:  lastSeen,
	}
}
