//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/tailscale/ipn/ipnstate"
	"github.com/metacubex/tailscale/tailcfg"
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
	// 中继 IP 对上不止一台设备时，只认授权给本机的中继：对方对本机有 relay-target 能力（WhoIs 的 CapMap = 它对本机的能力）。
	// 只在走设备中继、且对不出唯一一台时才问，每台问一次
	asked := map[*ipnstate.PeerStatus]bool{}
	isRelayTarget := func(q *ipnstate.PeerStatus) bool {
		if v, ok := asked[q]; ok {
			return v
		}
		ok := false
		if len(q.TailscaleIPs) > 0 {
			if who, err := lc.WhoIs(ctx, q.TailscaleIPs[0].String()); err == nil && who != nil {
				ok = who.CapMap.HasCapability(tailcfg.PeerCapabilityRelayTarget)
			}
		}
		asked[q] = ok
		return ok
	}
	return convertTailscaleStatus(st, isRelayTarget), nil
}

// convertTailscaleStatus 转成给界面的状态。isRelayTarget：这台设备是不是授权给本机的中继（nil = 不知道）。
func convertTailscaleStatus(st *ipnstate.Status, isRelayTarget func(*ipnstate.PeerStatus) bool) *TailscaleStatus {
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
	peers := make([]*ipnstate.PeerStatus, 0, len(st.Peer))
	for _, p := range st.Peer {
		if p != nil {
			peers = append(peers, p)
		}
	}
	// 按名字排序：输出顺序固定，认中继设备时同一个 IP 对上几台也总是挑同一台
	sort.Slice(peers, func(i, j int) bool { return peers[i].HostName < peers[j].HostName })
	for _, p := range peers {
		peer := convertTailscalePeer(p)
		if p.PeerRelay != "" {
			peer.PeerRelayVia = peerRelayViaName(p, peers, isRelayTarget)
		}
		out.Peers = append(out.Peers, peer)
	}
	return out
}

// peerRelayAddr 从 PeerRelay（「ip:port:vni:N」，也认「ip:port:N」；IPv6 为「[ip]:port:…」）取出中继的地址与端口。
func peerRelayAddr(relay string) (netip.Addr, uint16, bool) {
	var host, rest string
	if strings.HasPrefix(relay, "[") {
		end := strings.Index(relay, "]")
		if end < 0 {
			return netip.Addr{}, 0, false
		}
		host, rest = relay[1:end], strings.TrimPrefix(relay[end+1:], ":")
	} else {
		i := strings.Index(relay, ":")
		if i < 0 {
			return netip.Addr{}, 0, false
		}
		host, rest = relay[:i], relay[i+1:]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	portText, _, _ := strings.Cut(rest, ":")
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		port = 0 // 端口认不出时只按 IP 对
	}
	return addr.Unmap(), uint16(port), true
}

// peerRelayViaName 中继设备的名字：中继地址的 IP 对上哪台设备上报的端点（Addrs）就是哪台，对端自己不算。
// 同一个公网 IP 后面常有好几台（家里的路由器、电脑、手机共用出口）：对上不止一台时先只留授权给本机的中继
// （[isRelayTarget]），还是不止一台再看端口也对上的；仍不止一台就不认（为空，界面写「经设备中继」，不猜）。
func peerRelayViaName(p *ipnstate.PeerStatus, peers []*ipnstate.PeerStatus, isRelayTarget func(*ipnstate.PeerStatus) bool) string {
	addr, port, ok := peerRelayAddr(p.PeerRelay)
	if !ok {
		return ""
	}
	var byIP, byPort []*ipnstate.PeerStatus
	for _, q := range peers {
		if q == p {
			continue
		}
		ipHit, portHit := false, false
		for _, a := range q.Addrs {
			ap, err := netip.ParseAddrPort(a)
			if err != nil || ap.Addr().Unmap() != addr {
				continue
			}
			ipHit = true
			if port != 0 && ap.Port() == port {
				portHit = true
			}
		}
		if ipHit {
			byIP = append(byIP, q)
		}
		if portHit {
			byPort = append(byPort, q)
		}
	}
	if len(byIP) == 1 {
		return peerShortName(byIP[0])
	}
	if len(byIP) == 0 {
		return ""
	}
	if isRelayTarget != nil {
		var targets []*ipnstate.PeerStatus
		for _, q := range byIP {
			if isRelayTarget(q) {
				targets = append(targets, q)
			}
		}
		if len(targets) == 1 {
			return peerShortName(targets[0])
		}
		if len(targets) > 1 {
			byIP = targets
		}
	}
	var hit *ipnstate.PeerStatus
	for _, q := range byPort {
		for _, c := range byIP {
			if q == c {
				if hit != nil {
					return ""
				}
				hit = q
			}
		}
	}
	if hit == nil {
		return ""
	}
	return peerShortName(hit)
}

// peerShortName 设备名：HostName，没有时取 DNSName 的第一段（去掉 MagicDNS 后缀）。
func peerShortName(p *ipnstate.PeerStatus) string {
	if p.HostName != "" {
		return p.HostName
	}
	name, _, _ := strings.Cut(strings.TrimSuffix(p.DNSName, "."), ".")
	return name
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
	var lastHandshake string
	if !p.LastHandshake.IsZero() {
		lastHandshake = p.LastHandshake.UTC().Format(time.RFC3339)
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

		PeerRelay:     p.PeerRelay,
		RxBytes:       p.RxBytes,
		TxBytes:       p.TxBytes,
		LastHandshake: lastHandshake,
	}
}
