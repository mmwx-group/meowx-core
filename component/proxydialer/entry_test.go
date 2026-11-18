package proxydialer_test

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/entryoverride"
	"github.com/metacubex/mihomo/component/proxydialer"
)

// 跑法：go test -tags with_gvisor ./component/proxydialer/
//
// 经链式代理（dialer-proxy）拨节点：节点的 server 换成覆盖表给的 IP 再交给前置代理（这里前置代理是 DIRECT），
// 第一个不通换下一个；拨通的连接在这个 IP 下线时被关掉。
func TestProxyDialerUsesEntryOverride(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	if err := entryoverride.Load(filepath.Join(t.TempDir(), "entry-overrides.json")); err != nil {
		t.Fatal(err)
	}
	entryoverride.SetServerSource(func() []entryoverride.Server { return []entryoverride.Server{{Host: "chained-entry.test"}} })
	defer entryoverride.SetServerSource(nil)
	apply := func(rev int64, list ...string) {
		var addrs []netip.Addr
		for _, s := range list {
			addrs = append(addrs, netip.MustParseAddr(s))
		}
		entryoverride.Apply("https://panel.test", entryoverride.ScopeUser, entryoverride.OriginPush,
			entryoverride.Update{Server: "chained-entry.test", IPs: addrs, Rev: rev})
	}
	apply(1, "::1", "127.0.0.1")

	d := proxydialer.New(outbound.NewDirect(), false)
	var conn net.Conn
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort("chained-entry.test", port))
		cancel()
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		if conn != nil {
			_ = conn.Close()
		}
		conn = c
	}
	defer conn.Close()

	apply(2, "::1") // 卸载 127.0.0.1
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	if ne, ok := err.(net.Error); err == nil || ok && ne.Timeout() {
		t.Fatalf("chained conn to the removed IP should be closed, err = %v", err)
	}
}
