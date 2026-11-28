package main

// 喵窝设备中继（规格 miaomiaowuC/Design/mesh-peer-relay.md §2 / §5，主控接口 mmwx-mesh/docs/MEOWX_MESH_PEER_RELAY_API.md）。
// OpenWrt 与飞牛 / Docker 版都用官方 tailscaled 当中继设备：上报、对账、DDNS 写在这里一份，平台只管防火墙与界面。
//
//	meowx-core panel mesh relay get [<设备编号>]            GET /user/mesh/relay（带编号 = 那一台；不带 = {"relays":[…]}）
//	meowx-core panel mesh relay set <设备编号> <JSON>        PUT /user/mesh/devices/<编号>/relay
//	meowx-core panel mesh relay local [--socket <sock>]     本机 tailscaled 的中继状态（LocalAPI，不经主控，主控不可达时页面用）
//	meowx-core panel mesh paths [--device <编号>]            GET /user/mesh/paths
//	meowx-core panel mesh tick --tailscale <cli> [--socket <sock>] --state <目录> [--force] [--fw-error <上次防火墙的错误>]
//	                                                        每分钟一次：报路径、报中继、按 desired 执行 tailscale set，
//	                                                        输出 {"firewall":{"relay_port":N|null},"state":…,"error":…}，平台按 firewall 开 / 撤端口
//
// 中继会话只能从 LocalAPI 读（CLI 的 debug peer-relay-sessions 只给人看）：经 tailscaled 的 unix socket 发 HTTP，
// Host 写 local-tailscaled.sock（同官方 client/local）。tick 的上次结果存在 --state 目录的 mesh-tick.json。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	tsDefaultSocket     = "/var/run/tailscale/tailscaled.sock"
	relayMinVersion     = "1.86.0" // 主控 device_relay.min_version 的缺省（tailscaled 从这个版本起有中继服务端）
	relayPostSpacing    = 5 * time.Second
	relayReportInterval = 55 * time.Second // cron 每分钟一次，留几秒余量
	relayOffRetry       = time.Hour        // 主控没有这个接口（404）时隔这么久再试
	pathActiveWindow    = 5 * time.Minute
	ddnsInterval        = 5 * time.Minute
	relayMaxEndpoints   = 8
)

// ---------- 主控接口（错误格式 {"error":"<码>","message":"<中文>"}） ----------

type relayError struct {
	status int
	code   string
	msg    string
}

func (e *relayError) Error() string      { return e.msg }
func (e *relayError) HTTPStatus() int    { return e.status }
func (e *relayError) ErrorCode() string  { return e.code }
func (e *relayError) routeMissing() bool { return e.status == 404 && e.code != "device_not_found" }

// relayErrorText：主控给了中文 message 就用它；没有按错误码 / 状态码说
func relayErrorText(status int, code, message string) string {
	if m := strings.TrimSpace(message); m != "" {
		return m
	}
	switch code {
	case "invalid_port":
		return "端口不对（1024–65535）"
	case "invalid_endpoint":
		return "静态地址不对（要写公网 IP:端口，IPv6 加方括号，最多 4 个）"
	case "invalid_ddns_host":
		return "DDNS 域名不对"
	case "share_not_allowed":
		return "只有管理员能把中继共享给所有人"
	case "device_not_found":
		return "设备不存在或不属于本账号"
	case "device_relay_disabled":
		return "管理员关闭了设备中继"
	case "rate_limited":
		return "上报太频繁，等下一轮"
	case "invalid_request":
		return "请求格式错误"
	}
	switch status {
	case 401:
		return "登录已失效，请重新登录主控账户"
	case 403:
		return "这个账号不能用喵窝了（可能已被移出喵窝名单）"
	case 404:
		return "主控还没有设备中继接口（请升级主控）"
	case 429:
		return "上报太频繁，等下一轮"
	case 502, 503:
		return "主控暂时不可用，请稍后再试"
	}
	if code != "" {
		return code
	}
	return fmt.Sprintf("主控回 HTTP %d", status)
}

func relayCall(st *panelState, path, method string, payload map[string]any) (map[string]any, error) {
	raw, status, err := panelRPCRawStatus(st.Base, path, method, st.Token, payload)
	if err != nil {
		if status >= 400 {
			return nil, &relayError{status: status, msg: relayErrorText(status, "", "")}
		}
		return nil, err
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		if status >= 400 {
			return nil, &relayError{status: status, msg: relayErrorText(status, "", "")}
		}
		return nil, fmt.Errorf("主控应答无法解析：%v", err)
	}
	code, _ := obj["error"].(string)
	msg, _ := obj["message"].(string)
	if status >= 400 || code != "" {
		return nil, &relayError{status: status, code: code, msg: relayErrorText(status, code, msg)}
	}
	return obj, nil
}

// ---------- tailscaled（LocalAPI 与命令行） ----------

type tsPeerStatus struct {
	ID            string
	HostName      string
	TailscaleIPs  []string
	Online        bool
	CurAddr       string
	Relay         string // DERP 区域代码
	PeerRelay     string // ip:port:vni:12345
	RxBytes       int64
	TxBytes       int64
	LastHandshake time.Time
}

type tsStatusJSON struct {
	Version      string
	BackendState string
	Self         *tsPeerStatus
	Peer         map[string]*tsPeerStatus
}

type relayClientInfo struct {
	Endpoint   string
	ShortDisco string
	PacketsTx  uint64
	BytesTx    uint64
}

type relaySessionJSON struct {
	VNI     uint32
	Client1 relayClientInfo
	Client2 relayClientInfo
}

// relayServerStatus：LocalAPI debug-peer-relay-sessions（UDPPort 为 nil = 没开中继）
type relayServerStatus struct {
	UDPPort  *uint16
	Sessions []relaySessionJSON
}

type tsPrefsJSON struct {
	ControlURL                 string
	RelayServerPort            *uint16
	RelayServerStaticEndpoints []string
}

// localAPIGet：经 tailscaled 的 unix socket 发一个 GET（照官方 client/local：主机名 local-tailscaled.sock）
func localAPIGet(sock, path string, v any) (int, error) {
	c := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", sock)
		},
	}}
	req, err := http.NewRequest("GET", "http://local-tailscaled.sock/localapi/v0/"+path, nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, fmt.Errorf("连不上 tailscaled（%s）：%v", sock, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return resp.StatusCode, fmt.Errorf("tailscaled %s 回 HTTP %d：%s", path, resp.StatusCode, msg)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return resp.StatusCode, fmt.Errorf("tailscaled %s 的应答无法解析：%v", path, err)
	}
	return resp.StatusCode, nil
}

// relaySessionsUnsupported：这个 tailscaled 没编进中继服务器（ts_omit_relayserver，或低于 1.86）：LocalAPI 没有这个接口
func relaySessionsUnsupported(code int, err error) bool {
	if err == nil {
		return false
	}
	if code == 404 {
		return true
	}
	return code == 500 && strings.Contains(err.Error(), "extension unavailable")
}

func tsCLI(cli, sock string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	full := args
	if sock != "" {
		full = append([]string{"--socket=" + sock}, args...)
	}
	out, err := exec.CommandContext(ctx, cli, full...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// ---------- 路径（§2.2 / §2.3，纯函数） ----------

type meshPeerPath struct {
	IP            string `json:"ip"`
	Path          string `json:"path"`
	PeerRelay     string `json:"peer_relay,omitempty"`
	Endpoint      string `json:"endpoint,omitempty"`
	DERPRegion    string `json:"derp_region,omitempty"`
	RxBytes       int64  `json:"rx_bytes"`
	TxBytes       int64  `json:"tx_bytes"`
	LastHandshake string `json:"last_handshake,omitempty"`
}

func peerIPv4(p *tsPeerStatus) string {
	for _, s := range p.TailscaleIPs {
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			return a.String()
		}
	}
	return ""
}

// peerPathOf：按顺序取第一个成立的——PeerRelay → peer_relay、CurAddr → direct、Relay → derp；都没有 / 没有喵窝 IPv4 不报
func peerPathOf(p *tsPeerStatus) (meshPeerPath, bool) {
	out := meshPeerPath{IP: peerIPv4(p), RxBytes: p.RxBytes, TxBytes: p.TxBytes}
	if out.IP == "" {
		return out, false
	}
	if !p.LastHandshake.IsZero() {
		out.LastHandshake = p.LastHandshake.UTC().Format(time.RFC3339)
	}
	switch {
	case p.PeerRelay != "":
		out.Path, out.PeerRelay = "peer_relay", p.PeerRelay
	case p.CurAddr != "":
		out.Path, out.Endpoint = "direct", p.CurAddr
	case p.Relay != "":
		out.Path, out.DERPRegion = "derp", p.Relay
	default:
		return out, false
	}
	return out, true
}

// activePeerPaths：近 5 分钟有活动的对端（最近握手在 5 分钟内，或收发字节比上次上报多），按 IP 排序
func activePeerPaths(st *tsStatusJSON, prev map[string][2]int64, now time.Time) []meshPeerPath {
	out := []meshPeerPath{}
	if st == nil {
		return out
	}
	for _, p := range st.Peer {
		if p == nil {
			continue
		}
		pp, ok := peerPathOf(p)
		if !ok {
			continue
		}
		recent := !p.LastHandshake.IsZero() && now.Sub(p.LastHandshake) < pathActiveWindow
		last, seen := prev[pp.IP]
		grew := !seen && (p.RxBytes > 0 || p.TxBytes > 0) || seen && (p.RxBytes > last[0] || p.TxBytes > last[1])
		if recent || grew {
			out = append(out, pp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// pathsSignature：路径变没变（某个对端的 path 或中继 / 直连地址 / 区域）
func pathsSignature(paths []meshPeerPath) string {
	var b strings.Builder
	for _, p := range paths {
		fmt.Fprintf(&b, "%s=%s|%s%s%s;", p.IP, p.Path, p.PeerRelay, p.Endpoint, p.DERPRegion)
	}
	return b.String()
}

// pathsDue：这一轮报不报。没有活动对端时只在「从有到无」那一次报空列表；路径变了隔上次至少 5 秒就报；否则每分钟一次
func pathsDue(paths []meshPeerPath, ts *meshTickState, now time.Time) (bool, string) {
	if ts.PathsOffUntil > now.Unix() {
		return false, "主控还没有路径接口"
	}
	since := now.Sub(time.Unix(ts.PathsAt, 0))
	if ts.PathsAt > 0 && since < relayPostSpacing {
		return false, "离上次上报不到 5 秒"
	}
	if len(paths) == 0 {
		if ts.PathsNonEmpty {
			return true, "对端都没有活动了"
		}
		return false, "没有活动的对端"
	}
	if pathsSignature(paths) != ts.PathsSig {
		return true, "路径变了"
	}
	if ts.PathsAt == 0 || since >= relayReportInterval {
		return true, "定时"
	}
	return false, "一分钟内报过"
}

// ---------- 中继对账（§2.5，纯函数） ----------

type relayDesired struct {
	Enabled         bool     `json:"enabled"`
	Port            int      `json:"port"`
	StaticEndpoints []string `json:"static_endpoints"`
	DDNSHost        string   `json:"ddns_host"`
}

// relayLocal：本机实际生效的中继设置
type relayLocal struct {
	Enabled   bool     `json:"enabled"`
	Port      int      `json:"port"`
	Endpoints []string `json:"endpoints"`
}

func normalizeEndpoint(s string) (string, bool) {
	ap, err := netip.ParseAddrPort(strings.TrimSpace(s))
	if err != nil || ap.Port() == 0 {
		return "", false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String(), true
}

// relayEndpoints：desired.static_endpoints + DDNS 解析结果拼上端口，去重，最多 8 个
func relayEndpoints(d relayDesired, ddns []string) []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(s string) {
		if n, ok := normalizeEndpoint(s); ok && !seen[n] && len(out) < relayMaxEndpoints {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, s := range d.StaticEndpoints {
		add(s)
	}
	if d.Port > 0 {
		for _, a := range ddns {
			if ip, err := netip.ParseAddr(a); err == nil {
				add(netip.AddrPortFrom(ip.Unmap(), uint16(d.Port)).String())
			}
		}
	}
	return out
}

func sameEndpoints(a, b []string) bool {
	norm := func(in []string) []string {
		out := []string{}
		for _, s := range in {
			if n, ok := normalizeEndpoint(s); ok {
				out = append(out, n)
			}
		}
		sort.Strings(out)
		return out
	}
	return strings.Join(norm(a), ",") == strings.Join(norm(b), ",")
}

// relayNeedsSet：desired 与本机实际值不一致
func relayNeedsSet(d relayDesired, endpoints []string, l relayLocal) bool {
	if !d.Enabled {
		return l.Enabled || len(l.Endpoints) > 0
	}
	return !l.Enabled || l.Port != d.Port || !sameEndpoints(endpoints, l.Endpoints)
}

// relaySetArgs：tailscale set 的参数（关闭 = 两个都给空串）
func relaySetArgs(d relayDesired, endpoints []string) []string {
	if !d.Enabled {
		return []string{"set", "--relay-server-port=", "--relay-server-static-endpoints="}
	}
	return []string{"set", "--relay-server-port=" + strconv.Itoa(d.Port), "--relay-server-static-endpoints=" + strings.Join(endpoints, ",")}
}

// versionAtLeast：tailscale 版本号（「1.104.5」「1.104.5-t…」）不低于 min；认不出来算低
func versionAtLeast(v, min string) bool {
	parse := func(s string) ([3]int, bool) {
		var out [3]int
		s = strings.TrimPrefix(strings.TrimSpace(s), "v")
		if i := strings.IndexAny(s, "-+ \n"); i >= 0 {
			s = s[:i]
		}
		parts := strings.Split(s, ".")
		if len(parts) < 2 || len(parts) > 3 {
			return out, false
		}
		for i, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 {
				return out, false
			}
			out[i] = n
		}
		return out, true
	}
	a, ok1 := parse(v)
	b, ok2 := parse(min)
	if !ok1 || !ok2 {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return true
}

// ddnsUsable：DDNS 解析出来的地址能不能交给 tailscaled（私网 / 喵窝 / fake-ip 段的不要）
func ddnsUsable(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsMulticast() {
		return false
	}
	for _, p := range []string{"100.64.0.0/10", "198.18.0.0/15", "fd7a:115c:a1e0::/48"} {
		if netip.MustParsePrefix(p).Contains(a) {
			return false
		}
	}
	return true
}

// relaySessionsForReport：LocalAPI 的 Sessions 换成上报格式（小写下划线，Client1 / Client2 合成 clients）
func relaySessionsForReport(srv *relayServerStatus) []map[string]any {
	out := []map[string]any{}
	if srv == nil {
		return out
	}
	for _, s := range srv.Sessions {
		clients := []map[string]any{}
		for _, c := range []relayClientInfo{s.Client1, s.Client2} {
			clients = append(clients, map[string]any{"endpoint": c.Endpoint, "short_disco": c.ShortDisco, "packets_tx": c.PacketsTx, "bytes_tx": c.BytesTx})
		}
		out = append(out, map[string]any{"vni": s.VNI, "clients": clients})
	}
	return out
}

func relayLocalOf(srv *relayServerStatus, prefs *tsPrefsJSON) relayLocal {
	l := relayLocal{Endpoints: []string{}}
	if srv != nil && srv.UDPPort != nil {
		l.Enabled, l.Port = true, int(*srv.UDPPort)
	} else if srv == nil && prefs != nil && prefs.RelayServerPort != nil {
		l.Enabled, l.Port = true, int(*prefs.RelayServerPort)
	}
	if prefs != nil {
		for _, e := range prefs.RelayServerStaticEndpoints {
			if n, ok := normalizeEndpoint(e); ok {
				l.Endpoints = append(l.Endpoints, n)
			}
		}
	}
	return l
}

// ---------- tick 的上次结果（<state>/mesh-tick.json） ----------

type meshTickState struct {
	DeviceID      uint64              `json:"device_id,omitempty"`
	PathsAt       int64               `json:"paths_at,omitempty"`
	PathsSig      string              `json:"paths_sig,omitempty"`
	PathsNonEmpty bool                `json:"paths_nonempty,omitempty"`
	Counters      map[string][2]int64 `json:"counters,omitempty"` // 上次上报时各对端的收 / 发字节
	PathsOffUntil int64               `json:"paths_off_until,omitempty"`

	ReportAt      int64         `json:"report_at,omitempty"`
	RelayOffUntil int64         `json:"relay_off_until,omitempty"`
	Desired       *relayDesired `json:"desired,omitempty"`
	State         string        `json:"state,omitempty"`
	Message       string        `json:"message,omitempty"`
	SetError      string        `json:"set_error,omitempty"`
	Sessions      int           `json:"sessions"`

	DDNSHost  string   `json:"ddns_host,omitempty"`
	DDNSAt    int64    `json:"ddns_at,omitempty"`
	DDNSAddrs []string `json:"ddns_addrs,omitempty"`

	RelayPort *int `json:"relay_port,omitempty"` // 上次交给平台放行的端口
}

func loadTickState(path string) *meshTickState {
	var ts meshTickState
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &ts)
	}
	return &ts
}

func (ts *meshTickState) save(path string) {
	data, _ := json.MarshalIndent(ts, "", "  ")
	tmp := path + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, path)
	}
}

// 同一时刻只跑一个 tick（cron 与页面可能同时触发）：锁文件，超过 2 分钟的当残留
func tickLock(dir string) (func(), bool) {
	path := filepath.Join(dir, "mesh-tick.lock")
	for i := 0; i < 2; i++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = f.WriteString(strconv.Itoa(os.Getpid()))
			_ = f.Close()
			return func() { _ = os.Remove(path) }, true
		}
		if fi, e := os.Stat(path); e == nil && time.Since(fi.ModTime()) > 2*time.Minute {
			_ = os.Remove(path)
			continue
		}
		return nil, false
	}
	return nil, false
}

// ddnsLookup：DDNS 域名的 A + AAAA（直接问公共 DNS，同 panelDial：路由器上的系统 DNS 在 fake-ip 下给假地址）。单测会换掉它
var ddnsLookup = func(host string) ([]string, error) {
	var lastErr error
	for _, server := range append(append([]string{}, panelDNSServers...), "") {
		resolver := &net.Resolver{PreferGo: true}
		if server != "" {
			srv := server
			resolver.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp", srv)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := resolver.LookupNetIP(ctx, "ip", host)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		out := []string{}
		for _, ip := range ips {
			if ddnsUsable(ip) {
				out = append(out, ip.Unmap().String())
			}
		}
		sort.Strings(out)
		return out, nil
	}
	return nil, lastErr
}

// ---------- 子命令 ----------

func flagValue(args []string, name string) (string, bool) {
	for i := 0; i < len(args); i++ {
		if args[i] == name && i+1 < len(args) {
			return args[i+1], true
		}
		if strings.HasPrefix(args[i], name+"=") {
			return strings.TrimPrefix(args[i], name+"="), true
		}
	}
	return "", false
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

// meshRelayLocal：本机中继状态（不经主控）。tailscaled 不支持中继时 supported=false
func meshRelayLocal(args []string) map[string]any {
	sock, ok := flagValue(args, "--socket")
	if !ok || sock == "" {
		sock = tsDefaultSocket
	}
	var srv relayServerStatus
	code, err := localAPIGet(sock, "debug-peer-relay-sessions", &srv)
	out := map[string]any{"success": err == nil, "supported": err == nil}
	if err != nil {
		out["error"] = err.Error()
		if relaySessionsUnsupported(code, err) {
			out["success"] = true
			out["error"] = "这个 tailscale 没有中继服务器功能（换成 MeowX 提供的 tailscale）"
		}
		return out
	}
	l := relayLocalOf(&srv, nil)
	out["enabled"], out["port"], out["sessions"] = l.Enabled, l.Port, relaySessionsForReport(&srv)
	return out
}

func meshRelayMain(st *panelState, args []string) (any, error) {
	if len(args) == 0 {
		return nil, errors.New("usage: meowx-core panel mesh relay get [<设备编号>] | set <设备编号> <JSON> | local [--socket <sock>]")
	}
	switch args[0] {
	case "get":
		path := "/user/mesh/relay"
		if len(args) > 1 {
			if !meshDigits.MatchString(args[1]) {
				return nil, errors.New("设备编号不对")
			}
			path += "?device_id=" + args[1]
		}
		obj, err := relayCall(st, path, "GET", nil)
		if err != nil {
			return nil, err
		}
		obj["success"] = true
		return obj, nil
	case "set":
		if len(args) < 3 || !meshDigits.MatchString(args[1]) {
			return nil, errors.New("usage: meowx-core panel mesh relay set <设备编号> <JSON>")
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(args[2]), &payload); err != nil || payload == nil {
			return nil, errors.New("中继设置不是合法的 JSON 对象")
		}
		if _, ok := payload["enabled"].(bool); !ok {
			return nil, errors.New("中继设置缺少 enabled")
		}
		clean := map[string]any{}
		for _, k := range []string{"enabled", "port", "static_endpoints", "ddns_host", "share"} {
			if v, ok := payload[k]; ok {
				clean[k] = v
			}
		}
		obj, err := relayCall(st, "/user/mesh/devices/"+args[1]+"/relay", "PUT", clean)
		if err != nil {
			return nil, err
		}
		obj["success"] = true
		return obj, nil
	default:
		return nil, fmt.Errorf("unknown relay command %q", args[0])
	}
}

func meshPaths(st *panelState, args []string) (any, error) {
	path := "/user/mesh/paths"
	if id, ok := flagValue(args, "--device"); ok {
		if !meshDigits.MatchString(id) {
			return nil, errors.New("设备编号不对")
		}
		path += "?device_id=" + id
	}
	obj, err := relayCall(st, path, "GET", nil)
	if err != nil {
		return nil, err
	}
	obj["success"] = true
	return obj, nil
}

// tickEnv：tick 用到的外部依赖（单测换成假的）
type tickEnv struct {
	cli, sock string
	now       func() time.Time
	sleep     func(time.Duration)
}

// meshTick：见文件头。总是 success:true（平台照 firewall 开 / 撤端口），出的问题写在 error
func meshTick(args []string) (any, error) {
	dir, _ := flagValue(args, "--state")
	if dir == "" {
		return nil, errors.New("缺少 --state <目录>")
	}
	cli, _ := flagValue(args, "--tailscale")
	if cli == "" {
		cli = "tailscale"
	}
	sock, ok := flagValue(args, "--socket")
	if !ok || sock == "" {
		sock = tsDefaultSocket
	}
	fwErr, _ := flagValue(args, "--fw-error")
	env := &tickEnv{cli: cli, sock: sock, now: time.Now, sleep: time.Sleep}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	unlock, ok := tickLock(dir)
	if !ok {
		ts := loadTickState(filepath.Join(dir, "mesh-tick.json"))
		return map[string]any{"success": true, "skipped": "busy", "firewall": map[string]any{"relay_port": portOrNil(ts.RelayPort)}}, nil
	}
	defer unlock()
	return runMeshTick(env, dir, hasFlag(args, "--force"), strings.TrimSpace(fwErr)), nil
}

func portOrNil(p *int) any {
	if p == nil || *p <= 0 {
		return nil
	}
	return *p
}

func runMeshTick(env *tickEnv, dir string, force bool, fwErr string) map[string]any {
	statePath := filepath.Join(dir, "mesh-tick.json")
	ts := loadTickState(statePath)
	out := map[string]any{"success": true}
	var errs []string
	finish := func(port *int) map[string]any {
		ts.RelayPort = port
		out["firewall"] = map[string]any{"relay_port": portOrNil(port)}
		if ts.State != "" {
			out["state"], out["message"] = ts.State, ts.Message
		}
		if ts.Desired != nil {
			out["desired"] = ts.Desired
		}
		out["error"] = strings.Join(errs, "；")
		ts.save(statePath)
		return out
	}

	var status tsStatusJSON
	if _, err := localAPIGet(env.sock, "status", &status); err != nil {
		errs = append(errs, err.Error())
		return finish(ts.RelayPort) // 一时问不到 tailscaled：防火墙照旧，别来回开撤
	}
	out["backend"] = status.BackendState
	if status.BackendState != "Running" || status.Self == nil {
		errs = append(errs, "tailscaled 不在运行状态（"+status.BackendState+"）")
		return finish(ts.RelayPort)
	}
	id, _ := strconv.ParseUint(strings.TrimSpace(status.Self.ID), 10, 64)
	if id == 0 {
		errs = append(errs, "没拿到本机在喵窝里的设备编号（Self.ID="+status.Self.ID+"）")
		return finish(ts.RelayPort)
	}
	ts.DeviceID = id
	out["device_id"] = id

	version := ""
	if v, err := tsCLI(env.cli, "", "version"); err == nil {
		version = strings.TrimSpace(strings.SplitN(v, "\n", 2)[0])
	}
	if version == "" {
		version = strings.SplitN(status.Version, "-", 2)[0]
	}
	out["version"] = version
	versionOK := versionAtLeast(version, relayMinVersion)

	// 本机中继：LocalAPI 的会话 + prefs 里的静态地址
	readLocal := func() (*relayServerStatus, relayLocal, error) {
		var srv relayServerStatus
		code, err := localAPIGet(env.sock, "debug-peer-relay-sessions", &srv)
		var prefs tsPrefsJSON
		var pp *tsPrefsJSON
		if _, perr := localAPIGet(env.sock, "prefs", &prefs); perr == nil {
			pp = &prefs
		}
		if err != nil {
			if relaySessionsUnsupported(code, err) {
				return nil, relayLocalOf(nil, pp), errRelayUnsupported
			}
			return nil, relayLocalOf(nil, pp), err
		}
		return &srv, relayLocalOf(&srv, pp), nil
	}
	srv, local, localErr := readLocal()
	supported := !errors.Is(localErr, errRelayUnsupported)
	out["relay_supported"] = supported
	if localErr != nil {
		if supported {
			errs = append(errs, localErr.Error())
		} else if !versionOK {
			errs = append(errs, fmt.Sprintf("tailscale %s 低于 %s，没有设备中继功能（换成 MeowX 提供的 tailscale）", version, relayMinVersion))
		} else {
			errs = append(errs, "这个 tailscale 没有中继服务器功能（debug-peer-relay-sessions 不可用；换成 MeowX 提供的 tailscale）")
		}
	}

	pst, perr := loadPanelState()
	if perr != nil {
		errs = append(errs, perr.Error())
		return finish(firewallPort(local))
	}
	now := env.now()

	// 1. 路径
	paths := activePeerPaths(&status, ts.Counters, now)
	pathsOut := map[string]any{"peers": len(paths), "reported": false}
	if send, why := pathsDue(paths, ts, now); send {
		pathsOut["reason"] = why
		_, err := relayCall(pst, "/user/mesh/paths", "POST", map[string]any{"device_id": id, "peers": paths})
		var re *relayError
		switch {
		case err == nil:
			pathsOut["reported"] = true
			ts.PathsAt, ts.PathsSig, ts.PathsNonEmpty = now.Unix(), pathsSignature(paths), len(paths) > 0
			ts.Counters = peerCounters(&status) // 所有对端的计数都记下：下次按「比这次多」判活动，空列表之后不会马上又判成有活动
		case errors.As(err, &re) && re.routeMissing():
			ts.PathsOffUntil = now.Add(relayOffRetry).Unix()
			pathsOut["error"] = re.msg
		case errors.As(err, &re) && re.status == 429:
			pathsOut["error"] = re.msg // 跳过这一轮
		default:
			pathsOut["error"] = err.Error() // 不重试、不积压，下一轮报新状态
		}
	} else {
		pathsOut["reason"] = why
	}
	out["paths"] = pathsOut

	// 2. 中继上报（每分钟；--force = 入网 / 改设置之后立刻对账；会话数变了也补报）
	report := func() error {
		if last := time.Unix(ts.ReportAt, 0); ts.ReportAt > 0 && env.now().Sub(last) < relayPostSpacing {
			env.sleep(relayPostSpacing - env.now().Sub(last))
		}
		errText := strings.Join(filterEmpty([]string{ts.SetError, fwErr, unsupportedText(supported, localErr)}), "；")
		port := 0
		if local.Enabled {
			port = local.Port
		}
		payload := map[string]any{
			"device_id": id, "tailscale_version": version, "enabled": local.Enabled, "port": port,
			"endpoints": local.Endpoints, "error": errText, "sessions": relaySessionsForReport(srv),
		}
		obj, err := relayCall(pst, "/user/mesh/relay/report", "POST", payload)
		ts.ReportAt = env.now().Unix()
		if err != nil {
			return err
		}
		var d relayDesired
		if raw, e := json.Marshal(obj["desired"]); e == nil && obj["desired"] != nil {
			_ = json.Unmarshal(raw, &d)
			if d.StaticEndpoints == nil {
				d.StaticEndpoints = []string{}
			}
			ts.Desired = &d
		}
		ts.State, _ = obj["state"].(string)
		ts.Message, _ = obj["message"].(string)
		ts.Sessions = len(relaySessionsForReport(srv))
		return nil
	}
	reported := false
	relayErr := func(err error) {
		var re *relayError
		if errors.As(err, &re) && re.routeMissing() {
			ts.RelayOffUntil = now.Add(relayOffRetry).Unix()
		}
		if !(errors.As(err, &re) && re.status == 429) {
			errs = append(errs, "上报中继状态："+err.Error())
		}
	}
	sessions := len(relaySessionsForReport(srv))
	if ts.RelayOffUntil <= now.Unix() &&
		(force || ts.Desired == nil || now.Sub(time.Unix(ts.ReportAt, 0)) >= relayReportInterval || sessions != ts.Sessions) {
		if err := report(); err != nil {
			relayErr(err)
		} else {
			reported = true
		}
	}
	out["reported"] = reported

	// 3. 对账：版本够、支持中继、主控没说版本太旧时，desired 与本机不一致就 tailscale set，然后立刻补报
	if ts.Desired != nil && supported && versionOK && ts.State != "version_too_old" && localErr == nil {
		d := *ts.Desired
		// DDNS：5 分钟解析一次（域名换了马上解析），结果变了 endpoints 跟着变
		if d.Enabled && d.DDNSHost != "" {
			if d.DDNSHost != ts.DDNSHost || now.Sub(time.Unix(ts.DDNSAt, 0)) >= ddnsInterval {
				addrs, err := ddnsLookup(d.DDNSHost)
				if err != nil {
					out["ddns_error"] = fmt.Sprintf("解析 %s 失败：%v", d.DDNSHost, err)
					if d.DDNSHost != ts.DDNSHost {
						ts.DDNSAddrs = nil
					}
				} else {
					ts.DDNSAddrs = addrs
				}
				ts.DDNSHost, ts.DDNSAt = d.DDNSHost, now.Unix()
			}
		} else {
			ts.DDNSHost, ts.DDNSAt, ts.DDNSAddrs = "", 0, nil
		}
		out["ddns_addrs"] = ts.DDNSAddrs
		endpoints := relayEndpoints(d, ts.DDNSAddrs)
		if relayNeedsSet(d, endpoints, local) {
			setOut, err := tsCLI(env.cli, env.sock, relaySetArgs(d, endpoints)...)
			if err != nil && strings.Contains(setOut, "relay-server-static-endpoints") && strings.Contains(setOut, "not defined") {
				// 老版本（1.86–1.9x）只有端口参数：不带静态地址再设一次
				args := relaySetArgs(d, endpoints)[:2]
				setOut, err = tsCLI(env.cli, env.sock, args...)
				if err == nil && len(endpoints) > 0 {
					err = errors.New("这个 tailscale 不支持静态地址（--relay-server-static-endpoints），只设了端口")
				}
			}
			if err != nil {
				msg := strings.TrimSpace(setOut)
				if msg == "" {
					msg = err.Error()
				}
				ts.SetError = "tailscale set 失败：" + msg
				if len(ts.SetError) > 400 {
					ts.SetError = ts.SetError[:400]
				}
			} else {
				ts.SetError = ""
			}
			out["set"] = map[string]any{"args": relaySetArgs(d, endpoints)[1:], "error": ts.SetError}
			srv, local, localErr = readLocal()
			if localErr != nil && !errors.Is(localErr, errRelayUnsupported) {
				errs = append(errs, localErr.Error())
			}
			if ts.RelayOffUntil <= env.now().Unix() {
				if err := report(); err != nil {
					relayErr(err)
				}
			}
		} else if ts.SetError != "" {
			ts.SetError = "" // 已经一致了，之前的失败不再报
		}
	}
	if ts.SetError != "" {
		errs = append(errs, ts.SetError)
	}
	out["local"] = map[string]any{"enabled": local.Enabled, "port": local.Port, "endpoints": local.Endpoints, "sessions": relaySessionsForReport(srv)}
	return finish(firewallPort(local))
}

// peerCounters：各对端（按喵窝 IPv4）此刻的收 / 发字节
func peerCounters(st *tsStatusJSON) map[string][2]int64 {
	out := map[string][2]int64{}
	for _, p := range st.Peer {
		if p == nil {
			continue
		}
		if ip := peerIPv4(p); ip != "" {
			out[ip] = [2]int64{p.RxBytes, p.TxBytes}
		}
	}
	return out
}

var errRelayUnsupported = errors.New("relay server unsupported")

func unsupportedText(supported bool, err error) string {
	if supported || err == nil {
		return ""
	}
	return "这个 tailscale 没有中继服务器功能（debug-peer-relay-sessions 不可用）"
}

// firewallPort：平台要放行的 UDP 端口 = 本机中继实际在听的端口（0 = 随机端口，没法放行）
func firewallPort(l relayLocal) *int {
	if !l.Enabled || l.Port <= 0 {
		return nil
	}
	p := l.Port
	return &p
}

func filterEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}
