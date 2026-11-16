package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/metacubex/mihomo/component/entryoverride"
)

// MeowX：拨主控指定的转发入口（规格 miaomiaowuC/Design/entry-realtime.md §6）。
// 没指定解析器的拨号就是拨代理节点的 server（见 parseAddr）：入口覆盖表里有这个 server 时直接用表里的 IP，
// 不查 hosts 与 DNS；TLS SNI、Host、端口都不变——这里换的只是 TCP / UDP 连到哪个 IP。

// networkFamily tcp4 / udp4 只要 IPv4，tcp6 / udp6 只要 IPv6，别的两种都要。
func networkFamily(network string) int {
	switch network {
	case "tcp4", "udp4":
		return 4
	case "tcp6", "udp6":
		return 6
	}
	return 0
}

// preferFamily 节点设了偏好的 IP 版本时把那一族排在前面（同族内保持轮转顺序）。
func preferFamily(ips []netip.Addr, prefer int) []netip.Addr {
	if prefer != 4 && prefer != 6 || len(ips) < 2 {
		return ips
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.Is4() == (prefer == 4) {
			out = append(out, ip)
		}
	}
	for _, ip := range ips {
		if ip.Is4() != (prefer == 4) {
			out = append(out, ip)
		}
	}
	return out
}

// dialEntry 按入口覆盖表给的顺序（已轮转）逐个拨，一个不通当场换下一个。每个只分到剩余时间的一份，
// 免得第一个不通（比如刚下线、被丢包）把整次拨号的时间耗光。拨通的连接登记下来，这个 IP 下线时关掉。
func dialEntry(ctx context.Context, network, host string, ips []netip.Addr, port string, opt option) (net.Conn, error) {
	ctx = entryoverride.WithinEntryDial(ctx)
	var errs []error
	for i, ip := range ips {
		attemptCtx, cancel := ctx, context.CancelFunc(func() {})
		if left := len(ips) - i; left > 1 {
			budget := DefaultTCPTimeout
			if deadline, ok := ctx.Deadline(); ok {
				budget = time.Until(deadline) / time.Duration(left)
			}
			attemptCtx, cancel = context.WithTimeout(ctx, budget)
		}
		conn, err := dialContext(attemptCtx, network, ip, port, opt)
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
	if len(errs) == 0 {
		return nil, ErrorNoIpAddress
	}
	return nil, errors.Join(errs...)
}

// trackEntryLiteral 拨的地址本身就是 IP、且是某个入口当前集合里的 IP：按 IP 登记。
func trackEntryLiteral(ctx context.Context, address string, conn net.Conn) {
	if !entryoverride.Active() || entryoverride.InEntryDial(ctx) {
		return
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		entryoverride.TrackIP(ip, conn)
	}
}
