package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/entryoverride"
	"github.com/metacubex/mihomo/component/resolver"

	"github.com/miekg/dns"
)

// 跑法：go test -tags with_gvisor ./component/dialer/

func setupEntry(t *testing.T, server string, list ...string) {
	t.Helper()
	if err := entryoverride.Load(filepath.Join(t.TempDir(), "entry-overrides.json")); err != nil {
		t.Fatal(err)
	}
	entryoverride.SetServerSource(func() []entryoverride.Server { return []entryoverride.Server{{Host: server}} })
	t.Cleanup(func() { entryoverride.SetServerSource(nil); entryoverride.ClearSource("") })
	applyEntry(t, server, 1, list...)
}

func applyEntry(t *testing.T, server string, rev int64, list ...string) {
	t.Helper()
	var addrs []netip.Addr
	for _, s := range list {
		addrs = append(addrs, netip.MustParseAddr(s))
	}
	entryoverride.Apply("https://panel.test", entryoverride.ScopeUser, entryoverride.OriginPush,
		entryoverride.Update{Server: server, IPs: addrs, Rev: rev})
}

// acceptAll 在 127.0.0.1 上收连接，回端口与收到的连接数。
func acceptAll(t *testing.T) (int, *atomic.Int32, chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var n atomic.Int32
	conns := make(chan net.Conn, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			conns <- c
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, &n, conns
}

// 拨节点 server 时用覆盖表的 IP；第一个不通（::1 上没人听这个端口）当场换下一个。
func TestDialUsesEntryOverrideAndFailsOver(t *testing.T) {
	port, accepted, _ := acceptAll(t)
	setupEntry(t, "entry.test", "::1", "127.0.0.1")
	addr := net.JoinHostPort("entry.test", strconv.Itoa(port))
	for i := 0; i < 4; i++ { // 轮转：起点在两个 IP 之间换，两种顺序都得拨通
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, err := DialContext(ctx, "tcp", addr)
		cancel()
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		if got := c.RemoteAddr().(*net.TCPAddr).IP.String(); got != "127.0.0.1" {
			t.Fatalf("connected to %s", got)
		}
		_ = c.Close()
	}
	for deadline := time.Now().Add(2 * time.Second); accepted.Load() != 4 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if accepted.Load() != 4 {
		t.Fatalf("accepted %d", accepted.Load())
	}
}

// 卸载一个 IP：经这个 server 拨到它的连接被关掉，应用读到错误后自己重连。
func TestEntryRemovalClosesDialedConn(t *testing.T) {
	port, _, conns := acceptAll(t)
	setupEntry(t, "entry.test", "127.0.0.1")
	c, err := DialContext(context.Background(), "tcp", net.JoinHostPort("entry.test", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	peer := <-conns
	defer peer.Close()

	applyEntry(t, "entry.test", 2, "127.0.0.1", "127.0.0.2") // 上线：不动
	_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); err == nil || !isTimeout(err) {
		t.Fatalf("adding an IP must not close the conn, read err = %v", err)
	}
	applyEntry(t, "entry.test", 3, "127.0.0.2") // 卸载 127.0.0.1
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("conn to the removed IP should be closed, read err = %v", err)
	}
}

// UDP：发往入口 IP 的 socket（出站先解析好 server 再 ListenPacket）同样登记、下线时关掉。
func TestEntryRemovalClosesPacketConn(t *testing.T) {
	setupEntry(t, "entry.test", "127.0.0.1")
	pc, err := ListenPacket(context.Background(), "udp", "", netip.MustParseAddrPort("127.0.0.1:9"))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	applyEntry(t, "entry.test", 2, "127.0.0.3")
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := pc.ReadFrom(make([]byte, 16)); err == nil || isTimeout(err) {
		t.Fatalf("packet conn to the removed IP should be closed, err = %v", err)
	}
}

// 指定了解析器的拨号（DIRECT 等普通流量）不认覆盖表；覆盖表也不改 resolver 包本身的解析。
func TestNonProxyLookupsUnaffected(t *testing.T) {
	port, _, _ := acceptAll(t)
	setupEntry(t, "entry.test", "127.0.0.1")
	r := &fixedResolver{err: errors.New("nxdomain")}
	_, err := DialContext(context.Background(), "tcp", net.JoinHostPort("entry.test", strconv.Itoa(port)), WithResolver(r))
	if err == nil || r.calls.Load() == 0 {
		t.Fatalf("explicit resolver must be used (calls=%d, err=%v)", r.calls.Load(), err)
	}
	if ips, _ := resolver.LookupIPWithResolver(context.Background(), "entry.test", r); len(ips) != 0 {
		t.Fatalf("resolver package must not see overrides: %v", ips)
	}
	// 不在当前配置里的键不用：照常走节点 server 的解析器
	entryoverride.SetServerSource(func() []entryoverride.Server { return []entryoverride.Server{{Host: "someone-else.test"}} })
	old := resolver.ProxyServerHostResolver
	proxyResolver := &fixedResolver{err: errors.New("nxdomain")}
	resolver.ProxyServerHostResolver = proxyResolver
	defer func() { resolver.ProxyServerHostResolver = old }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if c, err := DialContext(ctx, "tcp", net.JoinHostPort("entry.test", strconv.Itoa(port))); err == nil {
		_ = c.Close()
		t.Fatal("override used although no proxy has this server")
	}
	if proxyResolver.calls.Load() == 0 {
		t.Fatal("dial should fall back to the proxy-server resolver")
	}
}

// 入口端口：同一 server 上另开的直连节点（端口不在 ports 里）照常走节点 server 的解析器，不改连入口 IP。
func TestEntryPortsExcludeDirectNode(t *testing.T) {
	port, accepted, _ := acceptAll(t)
	if err := entryoverride.Load(filepath.Join(t.TempDir(), "entry-overrides.json")); err != nil {
		t.Fatal(err)
	}
	entryoverride.SetServerSource(func() []entryoverride.Server {
		return []entryoverride.Server{{Host: "entry.test", Port: uint16(port)}, {Host: "entry.test", Port: 9}}
	})
	t.Cleanup(func() { entryoverride.SetServerSource(nil); entryoverride.ClearSource("") })
	entryoverride.Apply("https://panel.test", entryoverride.ScopeUser, entryoverride.OriginPush, entryoverride.Update{
		Server: "entry.test", IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Ports: entryoverride.PortList(uint16(port)), Rev: 1})

	c, err := DialContext(context.Background(), "tcp", net.JoinHostPort("entry.test", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("forward node (port in ports) should use the override: %v", err)
	}
	_ = c.Close()

	old := resolver.ProxyServerHostResolver
	proxyResolver := &fixedResolver{err: errors.New("nxdomain")}
	resolver.ProxyServerHostResolver = proxyResolver
	defer func() { resolver.ProxyServerHostResolver = old }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if c, err := DialContext(ctx, "tcp", net.JoinHostPort("entry.test", "9")); err == nil {
		_ = c.Close()
		t.Fatal("direct node (port not in ports) must not use the override")
	}
	if proxyResolver.calls.Load() == 0 {
		t.Fatal("direct node should be resolved by the proxy-server resolver")
	}
	for deadline := time.Now().Add(2 * time.Second); accepted.Load() != 1 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if accepted.Load() != 1 {
		t.Fatalf("accepted %d", accepted.Load())
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

type fixedResolver struct {
	err   error
	calls atomic.Int32
}

func (r *fixedResolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	r.calls.Add(1)
	return nil, r.err
}
func (r *fixedResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.LookupIP(ctx, host)
}
func (r *fixedResolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.LookupIP(ctx, host)
}
func (r *fixedResolver) ResolveECH(ctx context.Context, host string) ([]byte, error) {
	return nil, r.err
}
func (r *fixedResolver) ExchangeContext(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	return nil, r.err
}
func (r *fixedResolver) Invalid() bool    { return true }
func (r *fixedResolver) ClearCache()      {}
func (r *fixedResolver) ResetConnection() {}
