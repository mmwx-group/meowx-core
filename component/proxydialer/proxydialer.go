package proxydialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/entryoverride"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

type proxyDialer struct {
	proxy     C.ProxyAdapter
	statistic bool
}

func New(proxy C.ProxyAdapter, statistic bool) C.Dialer {
	return proxyDialer{proxy: proxy, statistic: statistic}
}

func (p proxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// MeowX：经链式代理（dialer-proxy）拨节点时同样认主控指定的转发入口：把节点的 server 换成覆盖表给的 IP 再交给前置代理，
	// 一个不通换下一个；拨通的连接登记下来，这个入口下线时关掉（见 component/entryoverride）
	if host, port, err := net.SplitHostPort(address); err == nil {
		if ips := entryoverride.Lookup(host, entryFamily(network)); len(ips) > 0 {
			return p.dialEntry(ctx, network, host, port, ips)
		}
	}
	return p.dial(ctx, network, address)
}

func (p proxyDialer) dialEntry(ctx context.Context, network, host, port string, ips []netip.Addr) (net.Conn, error) {
	var errs []error
	for i, ip := range ips {
		attemptCtx, cancel := ctx, context.CancelFunc(func() {})
		if left := len(ips) - i; left > 1 {
			if deadline, ok := ctx.Deadline(); ok {
				attemptCtx, cancel = context.WithTimeout(ctx, time.Until(deadline)/time.Duration(left))
			}
		}
		conn, err := p.dial(attemptCtx, network, net.JoinHostPort(ip.String(), port))
		cancel()
		if err == nil {
			entryoverride.Track(host, ip, conn)
			return conn, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

func entryFamily(network string) int {
	switch network {
	case "tcp4", "udp4":
		return 4
	case "tcp6", "udp6":
		return 6
	}
	return 0
}

func (p proxyDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	currentMeta := &C.Metadata{Type: C.INNER}
	if err := currentMeta.SetRemoteAddress(address); err != nil {
		return nil, err
	}
	if strings.Contains(network, "udp") { // using in wireguard outbound
		pc, err := p.listenPacket(ctx, currentMeta)
		if err != nil {
			return nil, err
		}
		if !currentMeta.Resolved() { // should not happen, maybe by a wrongly implemented proxy, but we can handle this (:
			err = pc.ResolveUDP(ctx, currentMeta)
			if err != nil {
				_ = pc.Close()
				return nil, err
			}
		}
		return N.NewBindPacketConn(pc, currentMeta.UDPAddr()), nil
	}
	conn, err := p.proxy.DialContext(ctx, currentMeta)
	if err != nil {
		return nil, err
	}
	if p.statistic {
		conn = statistic.NewTCPTracker(conn, statistic.DefaultManager, currentMeta, nil, 0, 0, false)
	}
	return conn, err
}

func (p proxyDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	if !strings.HasPrefix(network, "udp") {
		return nil, fmt.Errorf("proxyDialer only support udp network, but got: %s", network)
	}
	currentMeta := &C.Metadata{Type: C.INNER, DstIP: rAddrPort.Addr(), DstPort: rAddrPort.Port()}
	pc, err := p.listenPacket(ctx, currentMeta)
	if err == nil && !entryoverride.InEntryDial(ctx) {
		entryoverride.TrackIP(rAddrPort.Addr(), pc) // 发往入口 IP 的 UDP（经前置代理），这个入口下线时关掉
	}
	return pc, err
}

func (p proxyDialer) listenPacket(ctx context.Context, currentMeta *C.Metadata) (C.PacketConn, error) {
	currentMeta.NetWork = C.UDP
	pc, err := p.proxy.ListenPacketContext(ctx, currentMeta)
	if err != nil {
		return nil, err
	}
	if p.statistic {
		pc = statistic.NewUDPTracker(pc, statistic.DefaultManager, currentMeta, nil, 0, 0, false)
	}
	return pc, nil
}
