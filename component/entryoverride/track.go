package entryoverride

import (
	"context"
	"io"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

// 到入口 IP 的底层连接登记：拨号器拨到覆盖表给的 IP 后登记（TCP、连上的 UDP、QUIC 会话），只知道远端 IP 的 UDP socket
// 按 IP 登记；这个 IP 从某个键的集合里下线时关掉经这个键登记的那些——多路复用的会话、QUIC、UDP 关掉之后，
// 上面的代理连接一起断，应用重连时拨号器给的就是新集合里的 IP。
//
// 登记不包装连接（包一层会挡住 splice / vision 直通、syscall.Conn 判断这些优化），所以收不到「已关闭」的通知：
// 每登记一批就扫一遍，把已经关掉的摘掉（*net.TCPConn / *net.UDPConn 关掉后 RawConn.Control 报错；
// QUIC 连接看 Context）。认不出死活的连接留到总数超过上限时按先来先摘。

const (
	registryPruneEvery = 64
	registryMax        = 8192
)

type tracked struct {
	c    io.Closer
	ip   netip.Addr
	keys []string
	at   time.Time
}

type connRegistry struct {
	mu    sync.Mutex
	items map[*tracked]struct{}
	adds  int
}

var registry = &connRegistry{items: map[*tracked]struct{}{}}

type entryDialKey struct{}

// WithinEntryDial 标记「这是一次拨入口 IP 的拨号」：拨号器在里面再建 UDP socket（QUIC 的拨号器）时别再按 IP 登记一遍，
// 外层拨通后整条连接会登记。
func WithinEntryDial(ctx context.Context) context.Context {
	return context.WithValue(ctx, entryDialKey{}, true)
}

// InEntryDial 见 WithinEntryDial。
func InEntryDial(ctx context.Context) bool {
	v, _ := ctx.Value(entryDialKey{}).(bool)
	return v
}

// Track 登记一条经键 server 拨到入口 IP 的连接。
func Track(server string, ip netip.Addr, c io.Closer) {
	if c == nil || !ip.IsValid() {
		return
	}
	registry.add(&tracked{c: c, ip: ip.Unmap(), keys: []string{NormalizeKey(server)}, at: now()})
}

// TrackIP 登记一个只知道远端 IP 的 socket（UDP）：这个 IP 当前在哪些键的集合里就记在哪些键下；不在任何集合里不登记，回 false。
func TrackIP(ip netip.Addr, c io.Closer) bool {
	if c == nil {
		return false
	}
	keys := KeysOfIP(ip)
	if len(keys) == 0 {
		return false
	}
	registry.add(&tracked{c: c, ip: ip.Unmap(), keys: keys, at: now()})
	return true
}

func (r *connRegistry) add(t *tracked) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items[t] = struct{}{}
	r.adds++
	if r.adds < registryPruneEvery && len(r.items) <= registryMax {
		return
	}
	r.adds = 0
	for it := range r.items {
		if !connAlive(it.c) {
			delete(r.items, it)
		}
	}
	for len(r.items) > registryMax {
		var oldest *tracked
		for it := range r.items {
			if oldest == nil || it.at.Before(oldest.at) {
				oldest = it
			}
		}
		delete(r.items, oldest)
	}
}

// closeFor 关掉经键 server 登记、远端是 removed 里某个 IP、还开着的连接，回关掉的条数。
func (r *connRegistry) closeFor(server string, removed []netip.Addr) int {
	gone := map[netip.Addr]bool{}
	for _, ip := range removed {
		gone[ip.Unmap()] = true
	}
	var victims []*tracked
	r.mu.Lock()
	for it := range r.items {
		if !gone[it.ip] || !hasKey(it.keys, server) {
			continue
		}
		delete(r.items, it)
		victims = append(victims, it)
	}
	r.mu.Unlock()
	n := 0
	for _, it := range victims {
		if connAlive(it.c) {
			n++
		}
		_ = it.c.Close()
	}
	return n
}

func (r *connRegistry) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.items)
}

func hasKey(keys []string, key string) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}
	return false
}

// connAlive 认得出死活的连接看一眼；认不出的当作还开着。
func connAlive(c io.Closer) bool {
	switch v := c.(type) {
	case syscall.Conn:
		rc, err := v.SyscallConn()
		if err != nil {
			return false
		}
		return rc.Control(func(uintptr) {}) == nil
	case interface{ Context() context.Context }:
		return v.Context().Err() == nil
	}
	return true
}
