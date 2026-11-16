package panelrt

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"
)

// 订阅变更的通知（规格 §3.3）：主控推 subscription_changed（带 subs 时逐个键）/ 连上时给 sub_snapshot。
// 内核不拉订阅（订阅档在外壳手里），只告诉外壳「主控 base 上键为 key 的订阅现在是 rev」，外壳按自己存的 rev 判断要不要重拉：
// 注册的 Go 回调（meowC 经桥接）和 / 或配置的 hook（OpenWrt 跑命令、飞牛 POST 给 agent）。
//
//   - 每个 (主控, 键) 记着上次已知的 rev（通知过的，或外壳经 NoteSubscriptionRev / PUT 的 subs 告诉的），一样就不通知；
//     落盘到 <数据目录>/realtime-subs.json，内核重启后连上时的快照不会把全部订阅再通知一遍。
//   - 通知前随机等 0–10s（主控一次推给很多人时别同时砸过来）；同一份订阅 30s 内至多通知一次——不丢：
//     这期间又变了就等到 30s 满了再通知最新的 rev。
//   - 旧主控的 subscription_changed 不带 subs：通知键 ""（= 这个主控来的全部订阅），同样节流。
type SubscriptionCallback func(base, key, rev string)

// Hook 外壳给的订阅变更回调。
//   - Exec：跑这个命令，参数末尾追加订阅键（"" = 全部）；另有环境变量 MEOWX_SUB_BASE / MEOWX_SUB_KEY / MEOWX_SUB_REV。
//   - URL：POST JSON {"key","rev","base"}（本机的 agent，如飞牛的 http://127.0.0.1:7899/api/internal/subscription-changed）。
type Hook struct {
	Exec []string `json:"exec,omitempty"`
	URL  string   `json:"url,omitempty"`
}

// SubRev 一份订阅的 rev（PUT 的 subs / 快照里的一项）。
type SubRev struct {
	Base string `json:"base,omitempty"`
	Key  string `json:"key"`
	Rev  string `json:"rev"`
}

type subState struct {
	known         string // 上次已知的 rev
	pending       string // 等着通知的 rev
	pendingSet    bool   // 有一次通知在排队
	timer         *time.Timer
	lastDelivered time.Time
}

type subNotifier struct {
	mu       sync.Mutex
	subs     map[string]*subState // base + "\x00" + key
	path     string
	callback SubscriptionCallback
	hook     *Hook
}

var subs = &subNotifier{subs: map[string]*subState{}}

func subID(base, key string) string { return base + "\x00" + key }

func (n *subNotifier) setCallback(cb SubscriptionCallback) {
	n.mu.Lock()
	n.callback = cb
	n.mu.Unlock()
}

func (n *subNotifier) setHook(h *Hook) {
	n.mu.Lock()
	n.hook = h
	n.mu.Unlock()
}

// note 外壳告诉的已知 rev（它自己刚拉过），不通知。
func (n *subNotifier) note(base, key, rev string) {
	if key == "" || rev == "" {
		return
	}
	n.mu.Lock()
	st := n.stateLocked(base, key)
	if st.known != rev {
		st.known = rev
		n.saveLocked()
	}
	if st.pendingSet && st.pending == rev && st.timer != nil {
		st.timer.Stop() // 排着的就是这个 rev，外壳已经有了
		st.pendingSet = false
	}
	n.mu.Unlock()
}

func (n *subNotifier) stateLocked(base, key string) *subState {
	id := subID(base, key)
	st := n.subs[id]
	if st == nil {
		st = &subState{}
		n.subs[id] = st
	}
	return st
}

// changed 主控说这份订阅现在是 rev（key 为空 = 这个主控来的全部订阅）。
func (n *subNotifier) changed(base, key, rev string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	st := n.stateLocked(base, key)
	if key != "" && rev != "" && st.known == rev && !st.pendingSet {
		return
	}
	st.pending = rev
	if st.pendingSet {
		return // 已经排着了，到点时通知最新的 rev
	}
	st.pendingSet = true
	delay := randomJitter(timing.subJitterMax)
	if !st.lastDelivered.IsZero() {
		if wait := time.Until(st.lastDelivered.Add(timing.subMinInterval)); wait > delay {
			delay = wait
		}
	}
	st.timer = time.AfterFunc(delay, func() { n.fire(base, key) })
}

func (n *subNotifier) fire(base, key string) {
	n.mu.Lock()
	st := n.subs[subID(base, key)]
	if st == nil || !st.pendingSet {
		n.mu.Unlock()
		return
	}
	rev := st.pending
	st.pendingSet = false
	if key != "" && rev != "" && st.known == rev {
		n.mu.Unlock()
		return // 排队期间外壳已经告诉过这个 rev
	}
	st.lastDelivered = time.Now()
	if key != "" && rev != "" {
		st.known = rev
		n.saveLocked()
	}
	cb, hook := n.callback, n.hook
	n.mu.Unlock()
	deliver(cb, hook, base, key, rev)
}

// stop 取消排着的通知（停掉实时通道时）。
func (n *subNotifier) stop() {
	n.mu.Lock()
	for _, st := range n.subs {
		if st.timer != nil {
			st.timer.Stop()
		}
		st.pendingSet = false
	}
	n.mu.Unlock()
}

func deliver(cb SubscriptionCallback, hook *Hook, base, key, rev string) {
	what := key
	if what == "" {
		what = "全部订阅"
	}
	log.Infoln("[MeowX] 订阅变更：%s 的 %s（rev %s），通知外壳重拉", hostOf(base), what, rev)
	if cb != nil {
		go cb(base, key, rev)
	}
	if hook == nil {
		return
	}
	if len(hook.Exec) > 0 {
		go runExecHook(hook.Exec, base, key, rev)
	}
	if hook.URL != "" {
		go postHook(hook.URL, base, key, rev)
	}
}

func runExecHook(args []string, base, key, rev string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], append(append([]string{}, args[1:]...), key)...)
	cmd.Env = append(os.Environ(), "MEOWX_SUB_BASE="+base, "MEOWX_SUB_KEY="+key, "MEOWX_SUB_REV="+rev)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Warnln("[MeowX] 订阅变更回调 %s 失败：%s %s", args[0], err, strings.TrimSpace(string(out)))
	}
}

// hookClient 只给本机的 agent 用：IP 与 localhost 直接连，别的域名按内核的解析器解析（独立运行时不能碰 net.DefaultResolver）。
var hookClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			d := &net.Dialer{Timeout: 5 * time.Second}
			if strings.EqualFold(host, "localhost") {
				host = "127.0.0.1"
			}
			if _, err := netip.ParseAddr(host); err != nil {
				ip, err := resolver.ResolveIPWithResolver(ctx, host, resolver.DirectHostResolver)
				if err != nil {
					return nil, err
				}
				host = ip.String()
			}
			return d.DialContext(ctx, network, net.JoinHostPort(host, port))
		},
	},
}

func postHook(target, base, key, rev string) {
	body, _ := json.Marshal(map[string]string{"key": key, "rev": rev, "base": base})
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		log.Warnln("[MeowX] 订阅变更回调地址无效：%s", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hookClient.Do(req)
	if err != nil {
		log.Warnln("[MeowX] 订阅变更回调失败：%s", describeErr(err))
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		log.Warnln("[MeowX] 订阅变更回调返回 HTTP %d", resp.StatusCode)
	}
}

func hostOf(base string) string {
	if u, err := url.Parse(base); err == nil && u.Host != "" {
		return u.Host
	}
	return base
}

// MARK: - 落盘

type subsFile struct {
	Subs []SubRev `json:"subs"`
}

// load 换了数据目录就读那一份（同一路径只读一次）。
func (n *subNotifier) load(path string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if path == n.path {
		return
	}
	n.path = path
	for _, st := range n.subs {
		st.known = ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var f subsFile
	if json.Unmarshal(data, &f) != nil {
		return
	}
	for _, s := range f.Subs {
		if s.Key != "" && s.Rev != "" {
			n.stateLocked(s.Base, s.Key).known = s.Rev
		}
	}
}

func (n *subNotifier) saveLocked() {
	if n.path == "" {
		return
	}
	f := subsFile{Subs: []SubRev{}}
	for id, st := range n.subs {
		if st.known == "" {
			continue
		}
		i := strings.IndexByte(id, 0)
		if key := id[i+1:]; key != "" {
			f.Subs = append(f.Subs, SubRev{Base: id[:i], Key: key, Rev: st.known})
		}
	}
	sort.Slice(f.Subs, func(i, j int) bool {
		if f.Subs[i].Base != f.Subs[j].Base {
			return f.Subs[i].Base < f.Subs[j].Base
		}
		return f.Subs[i].Key < f.Subs[j].Key
	})
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return
	}
	tmp := n.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err == nil {
		_ = os.Rename(tmp, n.path)
	}
}
