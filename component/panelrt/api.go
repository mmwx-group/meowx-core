// Package panelrt 主控实时通道的内核实现（MeowX，规格 miaomiaowuC/Design/entry-realtime.md §2 / §3 / §5 / §6 / §7）：
// 连主控的加密 WS（/api/secure/ws），收入口切换（entry_failover / entry_snapshot → component/entryoverride 的入口覆盖表）
// 与订阅变更（subscription_changed / sub_snapshot → 外壳给的回调 / hook）；WS 连不上期间经加密 RPC 拉同样的状态。
//
// OpenWrt / 飞牛等以独立程序运行的外壳经控制接口用它（hub/route/meowx_realtime.go：PUT / GET / DELETE /meowx/realtime、
// GET /meowx/entries）；安卓 / Windows / Linux 客户端（meowC）经桥接直接调本包的函数：
//
//	Configure(channels, hook) / ApplyJSON(body)   接上（或换掉）通道；空列表 = 停掉
//	Stop()                                        停掉全部通道
//	Status() / Entries()                          各通道状态 / 当前入口覆盖表
//	SetSubscriptionCallback(func(base, key, rev)) 订阅变更回调
//	NoteSubscriptionRev(base, key, rev)           外壳刚拉过这份订阅，告诉内核它现在的 rev
//	ClearEntries(source)                          退出登录 / 删掉这个主控的全部订阅时清掉它的入口覆盖
//	Kick()                                        换网了（netreset.Run 也会叫）
package panelrt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/entryoverride"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// Channel 一条实时通道的配置：主控地址 + 会话 / 用户 API token（已登录），或订阅应答里拿到的只读凭证 rt（没登录）。
type Channel struct {
	Base  string `json:"base"`
	Token string `json:"token,omitempty"`
	RT    string `json:"rt,omitempty"`
}

func (c Channel) kind() string {
	if c.Token != "" {
		return "token"
	}
	return "rt"
}

func (c Channel) secret() string {
	if c.Token != "" {
		return c.Token
	}
	return c.RT
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// id 同一主控、同一份凭证 = 同一条通道（重新配置时不重连）。
func (c Channel) id() string { return c.Base + "|" + c.kind() + "|" + shortHash(c.secret()) }

// scope 入口快照的覆盖范围：已登录的通道看到这个用户全部的链；rt 只看到那一份订阅用到的链（见 entryoverride.ApplySnapshot）。
func (c Channel) scope() string {
	if c.Token != "" {
		return entryoverride.ScopeUser
	}
	return "rt:" + shortHash(c.RT)
}

// Config PUT /meowx/realtime 的正文（ApplyJSON 同一格式）。单个主控可以直接写 {"base","token"|"rt"}。
type Config struct {
	Channels []Channel `json:"channels,omitempty"`
	Hook     *Hook     `json:"hook,omitempty"`
	Subs     []SubRev  `json:"subs,omitempty"` // 可选：外壳手上各订阅的 rev（键与 rev 来自拉订阅时的 mmwx-sub-key / mmwx-sub-rev 头）
	// EntryIcon 可选：节点小标开关（见 entryoverride.SetProxyIcon，缺省关；只给 OpenWrt 上的 zashboard 用）。
	// 不写 = 不改现在的设置；DELETE /meowx/realtime 也不改。
	EntryIcon *bool  `json:"entryIcon,omitempty"`
	Base      string `json:"base,omitempty"`
	Token     string `json:"token,omitempty"`
	RT        string `json:"rt,omitempty"`
}

// ChannelStatus 一条通道的状态（不含凭证）。时间都是毫秒时间戳，0 = 没有。
type ChannelStatus struct {
	Base        string `json:"base"`
	Auth        string `json:"auth"`  // token | rt
	State       string `json:"state"` // connecting 连接中 | connected 已连 | backoff 退避中 | stopped
	ConnectedAt int64  `json:"connectedAt,omitempty"`
	NextRetryAt int64  `json:"nextRetryAt,omitempty"`
	Attempts    int    `json:"attempts"`
	AuthFailed  bool   `json:"authFailed,omitempty"`
	LastEvent   string `json:"lastEvent,omitempty"`
	LastEventAt int64  `json:"lastEventAt,omitempty"`
	LastError   string `json:"lastError,omitempty"`
	LastErrorAt int64  `json:"lastErrorAt,omitempty"`
	LastPullAt  int64  `json:"lastPullAt,omitempty"`
}

// StatusInfo GET /meowx/realtime 的应答。
type StatusInfo struct {
	Channels []ChannelStatus `json:"channels"`
	Hook     *Hook           `json:"hook,omitempty"`
	// EntryIcon 节点小标开着没有（PUT 的 "entryIcon"）
	EntryIcon bool `json:"entryIcon,omitempty"`
}

type manager struct {
	mu       sync.Mutex
	channels []*channel
	hook     *Hook
}

var mgr = &manager{}

func ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// NormalizeBase 主控地址的规范写法：scheme://host[:port]（host 小写，去掉路径与结尾斜杠；不写 scheme 按 https）。
func NormalizeBase(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("缺主控地址")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("主控地址无效：%s", raw)
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), nil
}

// normalizeChannels 规范化、去重：同一主控既有登录态又有 rt 时只连一条（用登录态，规格 §2.3）；
// 没登录时同一主控的几份 rt（几份订阅）各连一条。
func normalizeChannels(in []Channel) ([]Channel, error) {
	var out []Channel
	hasToken := map[string]bool{}
	seen := map[string]bool{}
	for _, ch := range in {
		base, err := NormalizeBase(ch.Base)
		if err != nil {
			return nil, err
		}
		ch.Base, ch.Token, ch.RT = base, strings.TrimSpace(ch.Token), strings.TrimSpace(ch.RT)
		if ch.Token == "" && ch.RT == "" {
			return nil, fmt.Errorf("%s 缺 token 或 rt", base)
		}
		if ch.Token != "" {
			ch.RT = ""
			if hasToken[base] {
				continue
			}
			hasToken[base] = true
		}
		if seen[ch.id()] {
			continue
		}
		seen[ch.id()] = true
		out = append(out, ch)
	}
	kept := out[:0]
	for _, ch := range out {
		if ch.Token == "" && hasToken[ch.Base] {
			continue
		}
		kept = append(kept, ch)
	}
	return kept, nil
}

func validateHook(h *Hook) (*Hook, error) {
	if h == nil || len(h.Exec) == 0 && strings.TrimSpace(h.URL) == "" {
		return nil, nil
	}
	out := &Hook{Exec: append([]string(nil), h.Exec...), URL: strings.TrimSpace(h.URL)}
	if len(out.Exec) > 0 && strings.TrimSpace(out.Exec[0]) == "" {
		return nil, errors.New("hook.exec 的命令为空")
	}
	if out.URL != "" {
		u, err := url.Parse(out.URL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, errors.New("hook.url 无效")
		}
	}
	return out, nil
}

// Configure 接上（或换掉）实时通道：同一主控、同一份凭证的通道保持连接，去掉的停掉，新加的连上。
// channels 为空 = 停掉全部。hook 为 nil = 不跑外部回调（Go 回调另设，见 SetSubscriptionCallback）。
func Configure(channels []Channel, hook *Hook) error {
	ensureState()
	list, err := normalizeChannels(channels)
	if err != nil {
		return err
	}
	if hook, err = validateHook(hook); err != nil {
		return err
	}
	mgr.mu.Lock()
	old := map[string]*channel{}
	for _, c := range mgr.channels {
		old[c.id] = c
	}
	next := make([]*channel, 0, len(list))
	for _, ch := range list {
		if c, ok := old[ch.id()]; ok {
			delete(old, ch.id())
			next = append(next, c)
			continue
		}
		c := newChannel(ch)
		next = append(next, c)
		c.start()
	}
	for _, c := range old {
		c.stop()
	}
	mgr.channels = next
	mgr.hook = hook
	mgr.mu.Unlock()
	subs.setHook(hook)
	if len(list) == 0 {
		subs.stop()
	}
	return nil
}

// ApplyJSON 同 PUT /meowx/realtime 的正文：{"channels":[…],"hook":{…},"subs":[…]} 或单个 {"base","token"|"rt","hook"}。
func ApplyJSON(body []byte) error {
	var cfg Config
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &cfg); err != nil {
			return fmt.Errorf("正文无法解析：%w", err)
		}
	}
	return ApplyConfig(cfg)
}

// ApplyConfig 见 ApplyJSON。
func ApplyConfig(cfg Config) error {
	channels := cfg.Channels
	if cfg.Base != "" {
		channels = append([]Channel{{Base: cfg.Base, Token: cfg.Token, RT: cfg.RT}}, channels...)
	}
	if err := Configure(channels, cfg.Hook); err != nil {
		return err
	}
	if cfg.EntryIcon != nil {
		entryoverride.SetProxyIcon(*cfg.EntryIcon)
	}
	for _, s := range cfg.Subs {
		NoteSubscriptionRev(s.Base, s.Key, s.Rev)
	}
	return nil
}

// Stop 停掉全部通道（入口覆盖表留着：退出登录时外壳另调 ClearEntries）。
func Stop() {
	_ = Configure(nil, nil)
}

// Status 各通道状态。
func Status() StatusInfo {
	mgr.mu.Lock()
	chans := append([]*channel(nil), mgr.channels...)
	info := StatusInfo{Channels: []ChannelStatus{}, Hook: mgr.hook, EntryIcon: entryoverride.ProxyIconEnabled()}
	mgr.mu.Unlock()
	for _, c := range chans {
		c.mu.Lock()
		info.Channels = append(info.Channels, ChannelStatus{
			Base: c.cfg.Base, Auth: c.cfg.kind(), State: c.state, ConnectedAt: ms(c.connectedAt), NextRetryAt: ms(c.nextRetryAt),
			Attempts: c.attempts, AuthFailed: c.authFailed, LastEvent: c.lastEvent, LastEventAt: ms(c.lastEventAt),
			LastError: c.lastError, LastErrorAt: ms(c.lastErrorAt), LastPullAt: ms(c.lastPullAt)})
		c.mu.Unlock()
	}
	return info
}

// Entries 当前的入口覆盖表。
// 每条带上当前配置里用到它的节点名（Nodes）。
func Entries() []entryoverride.View {
	ensureState()
	views := entryoverride.List()
	if len(views) == 0 {
		return views
	}
	byKey := map[string][]int{}
	for i, v := range views {
		byKey[v.Server] = append(byKey[v.Server], i)
	}
	seen := map[string]bool{}
	eachProxy(func(p C.Proxy) {
		h, port := proxyHost(p)
		if h == "" || seen[p.Name()] {
			return
		}
		for _, i := range byKey[h] {
			if views[i].MatchPort(port) {
				seen[p.Name()] = true
				views[i].Nodes = append(views[i].Nodes, p.Name())
			}
		}
	})
	for i := range views {
		sort.Strings(views[i].Nodes)
	}
	return views
}

// SetSubscriptionCallback 订阅变更回调（meowC 经桥接回 Dart）：主控 base 上键为 key 的订阅现在是 rev（key 为空 = 这个主控来的全部订阅）。
// 在单独的协程里调，nil = 取消。
func SetSubscriptionCallback(cb func(base, key, rev string)) {
	subs.setCallback(cb)
}

// NoteSubscriptionRev 外壳刚拉过这份订阅（应答头 mmwx-sub-key / mmwx-sub-rev），告诉内核：之后主控说的 rev 一样就不再通知。
func NoteSubscriptionRev(base, key, rev string) {
	if b, err := NormalizeBase(base); err == nil {
		ensureState()
		subs.note(b, strings.TrimSpace(key), strings.TrimSpace(rev))
	}
}

// ClearEntries 清掉来自这个主控的入口覆盖（退出登录、删掉这个主控的全部订阅时）；source 为空清掉全部。回清掉的条数。
func ClearEntries(source string) int {
	ensureState()
	if source != "" {
		if b, err := NormalizeBase(source); err == nil {
			source = b
		}
	}
	return entryoverride.ClearSource(source)
}

// Kick 换网了：退避中的通道提前重连（与上次尝试至少隔 15s），连不上的顺带拉一次状态。
func Kick() {
	mgr.mu.Lock()
	chans := append([]*channel(nil), mgr.channels...)
	mgr.mu.Unlock()
	for _, c := range chans {
		c.kick()
	}
}

// ensureState 按当前数据目录读入落盘的入口覆盖表与订阅 rev（同一目录只读一次）。
func ensureState() {
	home := C.Path.HomeDir()
	if home == "" {
		return
	}
	if err := entryoverride.Load(filepath.Join(home, "entry-overrides.json")); err != nil {
		log.Warnln("[Entry] 读落盘的入口覆盖表失败：%s", err)
	}
	subs.load(filepath.Join(home, "realtime-subs.json"))
}
