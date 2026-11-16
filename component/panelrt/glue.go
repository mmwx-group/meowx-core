package panelrt

import (
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/component/entryoverride"
	"github.com/metacubex/mihomo/component/netreset"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// 把入口覆盖表接到内核上：服务器集合来自当前配置的节点（含代理集），下线 IP 时按连接表关连接；换网时叫醒实时通道。
func init() {
	entryoverride.SetServerSource(proxyServers)
	entryoverride.SetTrackerCloser(closeTrackers)
	netreset.Register(Kick)
}

// OnConfigApplied 配置（重新）应用之后由 hub/executor 调：按数据目录读入落盘的入口覆盖表（启动时先用它），
// 并让入口覆盖表重新取节点的 server 集合。
func OnConfigApplied() {
	ensureState()
	entryoverride.InvalidateServers()
}

func eachProxy(fn func(C.Proxy)) {
	for _, p := range tunnel.Proxies() {
		fn(p)
	}
	for _, pd := range tunnel.Providers() {
		for _, p := range pd.Proxies() {
			fn(p)
		}
	}
}

func proxyHost(p C.Proxy) string {
	if p == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(p.Addr())
	if err != nil {
		return ""
	}
	return entryoverride.NormalizeKey(host)
}

// proxyServers 当前配置里全部节点的 server。
func proxyServers() []string {
	var out []string
	eachProxy(func(p C.Proxy) {
		if h := proxyHost(p); h != "" {
			out = append(out, h)
		}
	})
	return out
}

// closeTrackers 关掉连接表里经 server 为这个键的节点、远端地址是下线 IP 的连接（用户在连接页看得到的那些）。
// 远端地址认不出是哪个 IP 的（UDP 会话、部分多路复用）不在这里关，由拨号器登记的底层连接负责。
func closeTrackers(server string, removed []netip.Addr) int {
	names := map[string]bool{}
	eachProxy(func(p C.Proxy) {
		if proxyHost(p) == server {
			names[p.Name()] = true
		}
	})
	if len(names) == 0 {
		return 0
	}
	gone := map[netip.Addr]bool{}
	for _, ip := range removed {
		gone[ip.Unmap()] = true
	}
	var victims []statistic.Tracker
	statistic.DefaultManager.Range(func(t statistic.Tracker) bool {
		info := t.Info()
		if info == nil || info.Metadata == nil {
			return true
		}
		ip, err := netip.ParseAddr(info.Metadata.RemoteDst)
		if err != nil || !gone[ip.Unmap()] {
			return true
		}
		for _, name := range info.Chain {
			if names[name] {
				victims = append(victims, t)
				break
			}
		}
		return true
	})
	for _, t := range victims {
		_ = t.Close()
	}
	return len(victims)
}
