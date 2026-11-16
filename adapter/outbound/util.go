package outbound

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"strconv"

	"github.com/metacubex/mihomo/component/entryoverride"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

func serializesSocksAddr(metadata *C.Metadata) []byte {
	var buf [][]byte
	addrType := metadata.AddrType()
	p := uint(metadata.DstPort)
	port := []byte{uint8(p >> 8), uint8(p & 0xff)}
	switch addrType {
	case C.AtypDomainName:
		lenM := uint8(len(metadata.Host))
		host := []byte(metadata.Host)
		buf = [][]byte{{socks5.AtypDomainName, lenM}, host, port}
	case C.AtypIPv4:
		host := metadata.DstIP.AsSlice()
		buf = [][]byte{{socks5.AtypIPv4}, host, port}
	case C.AtypIPv6:
		host := metadata.DstIP.AsSlice()
		buf = [][]byte{{socks5.AtypIPv6}, host, port}
	}
	return bytes.Join(buf, nil)
}

func resolveIPWithResolver(ctx context.Context, host string, prefer C.DNSPrefer, r resolver.Resolver) (netip.Addr, error) {
	switch prefer {
	case C.IPv4Only:
		return resolver.ResolveIPv4WithResolver(ctx, host, r)
	case C.IPv6Only:
		return resolver.ResolveIPv6WithResolver(ctx, host, r)
	case C.IPv6Prefer:
		return resolver.ResolveIPPrefer6WithResolver(ctx, host, r)
	default:
		return resolver.ResolveIPWithResolver(ctx, host, r)
	}
}

// entryOverrideIPs MeowX：节点 server 在入口覆盖表里（主控指定的转发入口）时的 IP，已轮转、按偏好排好；没有回 nil。
func entryOverrideIPs(host string, prefer C.DNSPrefer) []netip.Addr {
	family := 0
	switch prefer {
	case C.IPv4Only:
		family = 4
	case C.IPv6Only:
		family = 6
	}
	ips := entryoverride.Lookup(host, family)
	if len(ips) < 2 {
		return ips
	}
	want6 := prefer == C.IPv6Prefer
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.Is6() == want6 {
			out = append(out, ip)
		}
	}
	for _, ip := range ips {
		if ip.Is6() != want6 {
			out = append(out, ip)
		}
	}
	return out
}

// resolveProxyServerIP 解析节点 server（UDP / QUIC 地址等不经拨号器的地方）：先查入口覆盖表，再照常 hosts → DNS。
func resolveProxyServerIP(ctx context.Context, host string, prefer C.DNSPrefer) (netip.Addr, error) {
	if ips := entryOverrideIPs(host, prefer); len(ips) > 0 {
		return ips[0], nil
	}
	return resolveIPWithResolver(ctx, host, prefer, resolver.ProxyServerHostResolver)
}

func resolveUDPAddr(ctx context.Context, network, address string, prefer C.DNSPrefer) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	ip, err := resolveProxyServerIP(ctx, host, prefer)

	if err != nil {
		return nil, err
	}

	ip, port = resolver.LookupIP4P(ip, port)

	var uint16Port uint16
	if port, err := strconv.ParseUint(port, 10, 16); err == nil {
		uint16Port = uint16(port)
	} else {
		return nil, err
	}
	// our resolver always unmap before return, so unneeded unmap at here
	// which is different with net.ResolveUDPAddr maybe return 4in6 address
	// 4in6 addresses can cause some strange effects on sing-based code
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16Port)), nil
}

func safeConnClose(c net.Conn, err error) {
	if err != nil && c != nil {
		_ = c.Close()
	}
}
