// Package entryoverride 入口覆盖表（MeowX，规格 miaomiaowuC/Design/entry-realtime.md §1 / §6）。
//
// 主控经实时通道推来「转发链入口现在该用哪几个 IP」，连节点时把节点的 server 直接解析成这些 IP，不等 DNS 生效。
// 只影响「连节点时把 server 解析成哪个 IP」：TLS SNI、HTTP Host、端口都不变；普通流量的解析不经这里。
//
//   - 键 = 订阅里节点 server 的原文：域名一律小写、去掉结尾的点，IP 按规范写法（NormalizeKey）。只在当前配置里
//     有节点的 server 等于这个键时才用（服务器集合由 SetServerSource 注册的函数给出，配置重载时 InvalidateServers）。
//   - rev 是主控做决定时的毫秒时间戳，同一个键只增不减：只接受比手上大的。空的 IP 集合 = 撤销覆盖、回到 DNS
//     （留一条空记录记住 rev，免得乱序到达的旧推送又把它加回来）。
//   - 多个 IP 轮流用：每次查询从下一个开始，拨号器逐个试，一个不通当场换下一个（component/dialer）。
//   - 新集合里没有的旧 IP = 这个入口下线：经这个 server 正连着那个 IP 的连接立刻关掉（Track 登记的底层连接 +
//     SetTrackerCloser 注册的按连接表关），应用自己会重连；上线只加 IP，不动现有连接。
//   - 落盘到 Load 给的路径（<数据目录>/entry-overrides.json），启动 / 重连后先用落盘的表；7 天没被快照或推送确认的过期。
//
// 本包不依赖拨号器、连接表与配置（它们反过来依赖本包），这些都经注册的函数接进来（component/panelrt）。
package entryoverride

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"
)

// ExpireAfter 多久没被主控（快照或推送）确认就过期。
const ExpireAfter = 7 * 24 * time.Hour

// serverCacheTTL 服务器集合的缓存时长：配置重载时会立刻作废；代理集（proxy-provider）在后台换了节点时靠它跟上。
const serverCacheTTL = 30 * time.Second

// Origin 一次变更从哪来，只写日志。
const (
	OriginPush     = "主控推送"
	OriginSnapshot = "主控快照"
	OriginPull     = "主控拉取"
)

// ScopeUser 已登录（会话 / 用户 API token）的通道的范围：主控给它的快照是这个用户全部转发链入口的完整列表。
// 只读凭证（rt）的通道各用自己的范围（只覆盖那一份订阅用到的链），见 ApplySnapshot。
const ScopeUser = "user"

// Update 主控的一条入口状态（entry_failover 一条，或 entry_snapshot 里的一项）。
type Update struct {
	Server  string
	IPs     []netip.Addr
	Rev     int64
	ChainID int64
	Reason  string
}

// Result 应用一条 Update 的结果。
type Result struct {
	Server  string // 规范化后的键
	ChainID int64
	Applied bool  // rev 比手上的大，换上了
	Rev     int64 // 应用之后表里这个键的 rev（没换上时是原来的）
}

// View 给控制接口 / 界面看的一条记录。
type View struct {
	Server      string   `json:"server"`
	IPs         []string `json:"ips"`
	Rev         int64    `json:"rev"`
	ChainID     int64    `json:"chainId"`
	Source      string   `json:"source"`
	UpdatedAt   int64    `json:"updatedAt"`   // 本机换上这份集合的时间（毫秒）
	ConfirmedAt int64    `json:"confirmedAt"` // 上次被主控确认的时间（毫秒）
	Active      bool     `json:"active"`      // 当前配置里有节点的 server 等于这个键（只有这时才会用它）
}

type entry struct {
	server      string
	ips         []netip.Addr // 空 = 撤销覆盖（只留着记 rev）
	rev         int64
	chainID     int64
	source      string
	scopes      []string
	updatedAt   time.Time
	confirmedAt time.Time
	next        uint32 // 轮转起点（原子读写）
}

type table struct {
	mu      sync.Mutex
	entries map[string]*entry
	byIP    map[netip.Addr][]string // 只含非空记录：IP → 用着它的键
	path    string                  // 落盘路径；空 = 不落盘
}

var (
	tbl = &table{entries: map[string]*entry{}, byIP: map[netip.Addr][]string{}}
	// active 表里有非空记录：拨号器的热路径先看它，没有覆盖时一个锁都不碰
	active atomic.Bool
	// now 可在测试里换掉
	now = time.Now

	hookMu        sync.RWMutex
	serverSource  func() []string
	trackerCloser func(server string, removed []netip.Addr) int

	serverMu      sync.Mutex
	serverSet     map[string]struct{}
	serverSetAt   time.Time
	serverSetDirt = true
)

// SetServerSource 注册「当前配置里全部节点的 server」的来源（component/panelrt 注册，读 tunnel 的节点与代理集）。
// 没注册时不做键的限制。
func SetServerSource(fn func() []string) {
	hookMu.Lock()
	serverSource = fn
	hookMu.Unlock()
	InvalidateServers()
}

// SetTrackerCloser 注册按连接表关连接的函数：关掉经 server 为这个键的节点、远端地址是下线 IP 的连接，回关掉的条数。
func SetTrackerCloser(fn func(server string, removed []netip.Addr) int) {
	hookMu.Lock()
	trackerCloser = fn
	hookMu.Unlock()
}

// InvalidateServers 配置（或代理集）变了：下次查询时重新取服务器集合。
func InvalidateServers() {
	serverMu.Lock()
	serverSetDirt = true
	serverMu.Unlock()
}

// NormalizeKey 键的规范写法：IP 按 netip 的规范文本（IPv6 去掉方括号与 zone，IPv4-mapped 还原成 IPv4），域名小写、去掉结尾的点。
func NormalizeKey(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}
	if ip, err := netip.ParseAddr(s); err == nil {
		return ip.WithZone("").Unmap().String()
	}
	return strings.TrimSuffix(strings.ToLower(s), ".")
}

// isServerKey 键是不是当前配置里某个节点的 server。
func isServerKey(key string) bool {
	hookMu.RLock()
	source := serverSource
	hookMu.RUnlock()
	if source == nil {
		return true
	}
	serverMu.Lock()
	defer serverMu.Unlock()
	if serverSetDirt || serverSet == nil || now().Sub(serverSetAt) > serverCacheTTL {
		set := map[string]struct{}{}
		for _, s := range source() {
			if s = NormalizeKey(s); s != "" {
				set[s] = struct{}{}
			}
		}
		serverSet, serverSetAt, serverSetDirt = set, now(), false
	}
	_, ok := serverSet[key]
	return ok
}

// Lookup 节点 server 的覆盖 IP：没有覆盖（或键不在当前配置里、已过期）回 nil。family 4 / 6 只要该族，0 = 都要。
// 每次查询从下一个 IP 开始轮转，返回的切片归调用方。
func Lookup(host string, family int) []netip.Addr {
	if !active.Load() {
		return nil
	}
	key := NormalizeKey(host)
	if key == "" {
		return nil
	}
	tbl.mu.Lock()
	e := tbl.entries[key]
	if e == nil || len(e.ips) == 0 || now().Sub(e.confirmedAt) > ExpireAfter {
		tbl.mu.Unlock()
		return nil
	}
	ips := make([]netip.Addr, 0, len(e.ips))
	for _, ip := range e.ips {
		if family == 4 && !ip.Is4() || family == 6 && !ip.Is6() {
			continue
		}
		ips = append(ips, ip)
	}
	start := atomic.AddUint32(&e.next, 1) - 1
	tbl.mu.Unlock()
	if len(ips) == 0 || !isServerKey(key) {
		return nil
	}
	if n := uint32(len(ips)); n > 1 {
		k := int(start % n)
		ips = append(ips[k:], ips[:k]...)
	}
	return ips
}

// Active 表里有没有正在生效的覆盖（拨号器热路径上先看它）。
func Active() bool { return active.Load() }

// KeysOfIP 当前有哪些键的集合里有这个 IP（给只知道远端 IP 的 UDP socket 登记用）。
func KeysOfIP(ip netip.Addr) []string {
	if !active.Load() || !ip.IsValid() {
		return nil
	}
	ip = ip.Unmap()
	tbl.mu.Lock()
	defer tbl.mu.Unlock()
	keys := tbl.byIP[ip]
	if len(keys) == 0 {
		return nil
	}
	return append([]string(nil), keys...)
}

// Apply 应用一条推送（entry_failover / 拉取结果里的一项）。source = 来自哪个主控（base URL），scope 见 ScopeUser。
func Apply(source, scope, origin string, u Update) Result {
	results := apply(source, scope, origin, []Update{u}, false, time.Time{})
	if len(results) == 0 {
		return Result{Server: NormalizeKey(u.Server), ChainID: u.ChainID}
	}
	return results[0]
}

// ApplySnapshot 应用一份完整快照（entry_snapshot / 拉取接口）。ready = 主控已经跑完一轮轮询，这份是权威的：
// 这个主控来源的、快照里没有的键清掉——只清 asOf 之前确认过的（拉取请求在路上时推送新加的键不该被这份旧快照清掉）。
// 已登录的通道（ScopeUser）清这个主控来源的全部；只读凭证的通道只撤掉自己的认领，没有别的通道认领了才清。
// ready=false（主控刚重启）时只按 rev 合并，不清理。
func ApplySnapshot(source, scope, origin string, ready bool, asOf time.Time, list []Update) []Result {
	return apply(source, scope, origin, list, ready, asOf)
}

type change struct {
	server  string
	ips     []netip.Addr
	removed []netip.Addr
	rev     int64
	reason  string
	dropped bool // 快照里没有了 / 过期，整条删掉
	expired bool
}

func apply(source, scope, origin string, list []Update, ready bool, asOf time.Time) []Result {
	t := now()
	var results []Result
	var changes []change
	tbl.mu.Lock()
	changes = append(changes, tbl.expireLocked(t)...)
	listed := map[string]bool{}
	for _, u := range list {
		key := NormalizeKey(u.Server)
		if key == "" {
			continue
		}
		listed[key] = true
		ips := normalizeIPs(u.IPs)
		e := tbl.entries[key]
		res := Result{Server: key, ChainID: u.ChainID}
		if e == nil || u.Rev > e.rev {
			var old []netip.Addr
			if e == nil {
				e = &entry{server: key}
				tbl.entries[key] = e
			} else {
				old = e.ips
			}
			tbl.unindexLocked(e)
			e.ips, e.rev, e.chainID, e.source, e.updatedAt = ips, u.Rev, u.ChainID, source, t
			tbl.indexLocked(e)
			res.Applied = true
			if !sameIPs(old, ips) {
				var removed []netip.Addr
				if len(ips) > 0 {
					removed = diffIPs(old, ips)
				}
				changes = append(changes, change{server: key, ips: ips, removed: removed, rev: u.Rev, reason: u.Reason})
			}
		}
		e.confirmedAt = t
		e.scopes = addScope(e.scopes, scope)
		res.Rev = e.rev
		results = append(results, res)
	}
	if ready {
		for key, e := range tbl.entries {
			if listed[key] || e.source != source || !e.confirmedAt.Before(asOf) {
				continue
			}
			if scope != ScopeUser {
				if e.scopes = removeScope(e.scopes, scope); len(e.scopes) > 0 {
					continue
				}
			}
			tbl.unindexLocked(e)
			delete(tbl.entries, key)
			if len(e.ips) > 0 {
				changes = append(changes, change{server: key, dropped: true})
			}
		}
	}
	tbl.refreshActiveLocked()
	tbl.saveLocked()
	tbl.mu.Unlock()

	for _, c := range changes {
		closed := 0
		if len(c.removed) > 0 {
			closed = closeConnections(c.server, c.removed)
		}
		logChange(c, closed, origin)
	}
	return results
}

// ClearSource 清掉来自这个主控的全部记录（退出登录、删掉这个主控的全部订阅时）；source 为空清掉全部。回清掉的条数。
func ClearSource(source string) int {
	tbl.mu.Lock()
	n := 0
	for key, e := range tbl.entries {
		if source != "" && e.source != source {
			continue
		}
		tbl.unindexLocked(e)
		delete(tbl.entries, key)
		if len(e.ips) > 0 {
			n++
		}
	}
	tbl.refreshActiveLocked()
	tbl.saveLocked()
	tbl.mu.Unlock()
	if n > 0 {
		if source == "" {
			log.Infoln("[Entry] 已清空入口覆盖表（%d 条），回到 DNS", n)
		} else {
			log.Infoln("[Entry] 已清掉来自 %s 的 %d 条入口覆盖，回到 DNS", source, n)
		}
	}
	return n
}

// List 当前的覆盖表（不含撤销后留着记 rev 的空记录与已过期的），按键排序。
func List() []View {
	t := now()
	tbl.mu.Lock()
	views := make([]View, 0, len(tbl.entries))
	for _, e := range tbl.entries {
		if len(e.ips) == 0 || t.Sub(e.confirmedAt) > ExpireAfter {
			continue
		}
		v := View{Server: e.server, Rev: e.rev, ChainID: e.chainID, Source: e.source,
			UpdatedAt: e.updatedAt.UnixMilli(), ConfirmedAt: e.confirmedAt.UnixMilli()}
		for _, ip := range e.ips {
			v.IPs = append(v.IPs, ip.String())
		}
		views = append(views, v)
	}
	tbl.mu.Unlock()
	for i := range views {
		views[i].Active = isServerKey(views[i].Server)
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Server < views[j].Server })
	return views
}

// MARK: - 落盘

type fileEntry struct {
	Server      string   `json:"server"`
	IPs         []string `json:"ips"`
	Rev         int64    `json:"rev"`
	ChainID     int64    `json:"chainId,omitempty"`
	Source      string   `json:"source"`
	Scopes      []string `json:"scopes,omitempty"`
	UpdatedAt   int64    `json:"updatedAt"`
	ConfirmedAt int64    `json:"confirmedAt"`
}

type fileFormat struct {
	Version int         `json:"version"`
	Entries []fileEntry `json:"entries"`
}

// Load 设定落盘路径并读进来（同一路径只读一次；换了路径就换成那份）。文件不存在不算错。
func Load(path string) error {
	tbl.mu.Lock()
	if path == tbl.path {
		tbl.mu.Unlock()
		return nil
	}
	tbl.path = path
	tbl.entries = map[string]*entry{}
	tbl.byIP = map[netip.Addr][]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		tbl.refreshActiveLocked()
		tbl.mu.Unlock()
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var f fileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		tbl.refreshActiveLocked()
		tbl.mu.Unlock()
		return fmt.Errorf("入口覆盖表无法解析：%w", err)
	}
	for _, fe := range f.Entries {
		key := NormalizeKey(fe.Server)
		if key == "" {
			continue
		}
		e := &entry{server: key, rev: fe.Rev, chainID: fe.ChainID, source: fe.Source, scopes: fe.Scopes,
			updatedAt: time.UnixMilli(fe.UpdatedAt), confirmedAt: time.UnixMilli(fe.ConfirmedAt)}
		for _, s := range fe.IPs {
			if ip, err := netip.ParseAddr(s); err == nil {
				e.ips = append(e.ips, ip.Unmap())
			}
		}
		e.ips = normalizeIPs(e.ips)
		tbl.entries[key] = e
		tbl.indexLocked(e)
	}
	expired := tbl.expireLocked(now())
	tbl.refreshActiveLocked()
	if len(expired) > 0 {
		tbl.saveLocked()
	}
	n := 0
	for _, e := range tbl.entries {
		if len(e.ips) > 0 {
			n++
		}
	}
	tbl.mu.Unlock()
	for _, c := range expired {
		logChange(c, 0, "")
	}
	if n > 0 {
		log.Infoln("[Entry] 读入落盘的入口覆盖 %d 条", n)
	}
	return nil
}

func (t *table) saveLocked() {
	if t.path == "" {
		return
	}
	f := fileFormat{Version: 1, Entries: []fileEntry{}}
	for _, e := range t.entries {
		fe := fileEntry{Server: e.server, IPs: []string{}, Rev: e.rev, ChainID: e.chainID, Source: e.source,
			Scopes: e.scopes, UpdatedAt: e.updatedAt.UnixMilli(), ConfirmedAt: e.confirmedAt.UnixMilli()}
		for _, ip := range e.ips {
			fe.IPs = append(fe.IPs, ip.String())
		}
		f.Entries = append(f.Entries, fe)
	}
	sort.Slice(f.Entries, func(i, j int) bool { return f.Entries[i].Server < f.Entries[j].Server })
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return
	}
	if err := writeFileAtomic(t.path, data); err != nil {
		log.Warnln("[Entry] 入口覆盖表写盘失败：%s", err)
	}
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// MARK: - 内部

func (t *table) expireLocked(at time.Time) []change {
	var out []change
	for key, e := range t.entries {
		if at.Sub(e.confirmedAt) <= ExpireAfter {
			continue
		}
		t.unindexLocked(e)
		delete(t.entries, key)
		if len(e.ips) > 0 {
			out = append(out, change{server: key, dropped: true, expired: true})
		}
	}
	return out
}

func (t *table) indexLocked(e *entry) {
	for _, ip := range e.ips {
		t.byIP[ip] = append(t.byIP[ip], e.server)
	}
}

func (t *table) unindexLocked(e *entry) {
	for _, ip := range e.ips {
		keys := t.byIP[ip]
		for i, k := range keys {
			if k == e.server {
				keys = append(keys[:i:i], keys[i+1:]...)
				break
			}
		}
		if len(keys) == 0 {
			delete(t.byIP, ip)
		} else {
			t.byIP[ip] = keys
		}
	}
}

func (t *table) refreshActiveLocked() {
	active.Store(len(t.byIP) > 0)
}

// normalizeIPs 去掉无效与重复的，保持主控给的顺序。
func normalizeIPs(ips []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(ips))
	seen := map[netip.Addr]bool{}
	for _, ip := range ips {
		if !ip.IsValid() {
			continue
		}
		ip = ip.WithZone("").Unmap()
		if seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, ip)
	}
	return out
}

func sameIPs(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// diffIPs old 里有、new 里没有的。
func diffIPs(old, cur []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, ip := range old {
		found := false
		for _, c := range cur {
			if c == ip {
				found = true
				break
			}
		}
		if !found {
			out = append(out, ip)
		}
	}
	return out
}

func addScope(scopes []string, scope string) []string {
	if scope == "" {
		return scopes
	}
	for _, s := range scopes {
		if s == scope {
			return scopes
		}
	}
	return append(scopes, scope)
}

func removeScope(scopes []string, scope string) []string {
	out := scopes[:0:0]
	for _, s := range scopes {
		if s != scope {
			out = append(out, s)
		}
	}
	return out
}

// closeConnections 一个键的 IP 下线：先按连接表关（用户看得到的连接，远端地址认得出是这个 IP 的），
// 再关登记过、还开着的底层连接（多路复用的会话、QUIC、UDP socket、经链式代理的连接）。回关掉的条数。
func closeConnections(server string, removed []netip.Addr) int {
	hookMu.RLock()
	closer := trackerCloser
	hookMu.RUnlock()
	n := 0
	if closer != nil {
		n += closer(server, removed)
	}
	n += registry.closeFor(server, removed)
	return n
}

// logChange 一次变更一行，例如：
// [Entry] hk-entry.example.com → 203.0.113.11, 203.0.113.12，下线 203.0.113.10，关闭 3 条连接（主控推送 · unload · rev 1794000123456）
// 记成 warning：OpenWrt / 飞牛缺省的日志级别是 warning，入口切换很少发生、又是排查连不上时最要紧的一行，info 级别看不到。
func logChange(c change, closed int, origin string) {
	switch {
	case c.expired:
		log.Warnln("[Entry] %s 7 天没有主控确认，覆盖已过期，回到 DNS", c.server)
		return
	case c.dropped:
		log.Warnln("[Entry] %s 已不在主控快照里，撤销覆盖，回到 DNS（%s）", c.server, origin)
		return
	}
	var b strings.Builder
	b.WriteString("[Entry] ")
	b.WriteString(c.server)
	b.WriteString(" → ")
	if len(c.ips) == 0 {
		b.WriteString("撤销覆盖，回到 DNS")
	} else {
		b.WriteString(joinIPs(c.ips))
		if len(c.removed) > 0 {
			b.WriteString("，下线 ")
			b.WriteString(joinIPs(c.removed))
			b.WriteString("，关闭 ")
			b.WriteString(strconv.Itoa(closed))
			b.WriteString(" 条连接")
		}
	}
	var tags []string
	if origin != "" {
		tags = append(tags, origin)
	}
	if c.reason != "" {
		tags = append(tags, c.reason)
	}
	if c.rev != 0 {
		tags = append(tags, "rev "+strconv.FormatInt(c.rev, 10))
	}
	if len(tags) > 0 {
		b.WriteString("（")
		b.WriteString(strings.Join(tags, " · "))
		b.WriteString("）")
	}
	log.Warnln("%s", b.String())
}

func joinIPs(ips []netip.Addr) string {
	parts := make([]string, len(ips))
	for i, ip := range ips {
		parts[i] = ip.String()
	}
	return strings.Join(parts, ", ")
}
