package main

// AkileCDN 白名单（同客户端「AkileCDN 白名单」，五端同一套规则）：AkileCDN 的转发规则
// 可以开「入口白名单」，只放一个 IPv4。家宽出口 IP 会变，路由器用 Akile 的开放接口把自己的直连出口 IPv4 写进所选规则的入口白名单。
// 与 po0 / GGY 加白同一类、同一套时机，区别是 Akile 不看请求的来源 IP，而是看请求体里写的 IP——所以先查出口 IP 再 PUT。
//
//	meowx-core panel akile status | enable | disable | setkey <key> | clearkey
//	meowx-core panel akile nodes [<config.yaml>]                       订阅里的可选节点（缺省读当前在用的运行配置）
//	meowx-core panel akile rules <port>                                用存着的 Key 查监听这个端口的规则
//	meowx-core panel akile add <rule_id> <port> <name> [<label>]       开关开着时立刻报这一个
//	meowx-core panel akile remove <序号>
//	meowx-core panel akile report [--timer]                            --timer = 定时轮：出口 IP 与上一次成功写入的相同就跳过
//
// 设置存 uci（meowx.akile：option enabled、option key、list node「<rule_id>|<port>|<label>|<name>」）；没有 uci 的外壳（飞牛 NAS 版）
// 用 MEOWX_AKILE_STATE 指到 JSON 文件。本机偏好：退出登录不清、没登录也报。每个节点上一次的结果只放内存盘（/var/run/meowx/akile.json，
// MEOWX_AKILE_RESULT 可改，按 rule_id 记），重启后显示「还没更新过」、第一轮一定写。回给界面与写进日志的 Key 一律是脱敏写法。

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"go.yaml.in/yaml/v3"
)

const akileMaxNodes = 20

const (
	akileKindUpdated     = "updated"
	akileKindUnchanged   = "unchanged"
	akileKindInvalidKey  = "invalid_key"
	akileKindNotFound    = "not_found"
	akileKindRateLimited = "rate_limited"
	akileKindFailed      = "failed"
)

// 界面文字（规格 §1.2 / §2 / §7）
const (
	akileTextInvalidKey  = "API Key 无效或已删除"
	akileTextNotFound    = "规则不存在（已删除，或不属于这个 API Key 的账号）"
	akileTextRateLimited = "请求太频繁，稍后自动重试"
	akileTextBadReply    = "应答无法解析"
	akileTextNoIP        = "查不到本机直连出口 IPv4"
	akileTextNeedKey     = "先填写 API Key"
	akileTextBadKey      = "API Key 应以 ak_ 开头"
)

var (
	akileAPIBase = "https://cdnapi.akile.ai/api/open"
	// 查直连出口 IPv4：明文 HTTP，并发问、谁先给出合法地址用谁
	akileIPEndpoints  = []string{"http://ip.3322.net/", "http://myip.ipip.net/"}
	akileResultPath   = "/var/run/meowx/akile.json"
	akileDefaultNodes = "/etc/meowx/run/config.yaml" // OpenWrt 版的运行配置（init 的 RUN_PROFILE_PATH）
	// 只给测试用（信任测试服务器的自签证书）；正式运行为 nil = 照常按系统根证书校验
	akileTLSConfig  *tls.Config
	akileIPTimeout  = 5 * time.Second
	akileAPITimeout = 10 * time.Second
)

// 合法的 Key：ak_ 开头，后面 8–200 位 A–Z a–z 0–9 _ -
var akileKeyPattern = regexp.MustCompile(`^ak_[A-Za-z0-9_-]{8,200}$`)

// 输入框接受裸 Key，也接受从文档里连着请求头一起复制的「X-API-Key: ak_…」/「Bearer ak_…」（前缀不分大小写）
func parseAkileKey(input string) (string, bool) {
	s := strings.TrimSpace(input)
	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, "x-api-key:"):
		s = strings.TrimSpace(s[len("x-api-key:"):])
	case strings.HasPrefix(lower, "bearer "):
		s = strings.TrimSpace(s[len("bearer "):])
	}
	if !akileKeyPattern.MatchString(s) {
		return "", false
	}
	return s, true
}

// 脱敏：ak_••••<后 4 位>
func maskAkileKey(key string) string {
	if key == "" {
		return ""
	}
	tail := key
	if len(tail) > 4 {
		tail = tail[len(tail)-4:]
	}
	return "ak_••••" + tail
}

// 任何要显示 / 写日志的文字里都不留完整 Key
func akileRedact(text, key string) string {
	if key == "" {
		return text
	}
	return strings.ReplaceAll(text, key, maskAkileKey(key))
}

// ---------- 出口 IP ----------

var akileIPv4Pattern = regexp.MustCompile(`(?:^|[^0-9.])((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?:$|[^0-9.])`)

var akileReservedV4 = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, cidr := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3"} {
		_, n, _ := net.ParseCIDR(cidr)
		nets = append(nets, n)
	}
	return nets
}()

// 合法 = IPv4，且不在 0/8、10/8、100.64/10、127/8、169.254/16、172.16/12、192.168/16、198.18/15、224/4 及以上
func akilePublicIPv4(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil || ip.To4() == nil || strings.Contains(s, ":") {
		return false
	}
	for _, n := range akileReservedV4 {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// 从应答正文里取第一个 IPv4（ip.3322.net 正文就是一行 IP；myip.ipip.net 是「当前 IP：1.2.3.4  来自于：…」）
func akileExtractIPv4(body string) (string, error) {
	m := akileIPv4Pattern.FindStringSubmatch(body)
	if m == nil {
		return "", errors.New("应答里没有 IPv4")
	}
	if !akilePublicIPv4(m[1]) {
		return "", fmt.Errorf("不是公网 IPv4（%s）", m[1])
	}
	return net.ParseIP(m[1]).To4().String(), nil
}

// 直连（与 GGY 同一套：panelMain 一开始已把进程挪进 meowx 服务的 cgroup，panelDial 直接问公共 DNS），只按 IPv4 连
func akileFetchIP(ctx context.Context, endpoint string) (string, error) {
	host := endpoint
	if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
		host = u.Host
	}
	client := &http.Client{
		Timeout: akileIPTimeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return panelDial(ctx, "tcp4", addr)
			},
			DisableKeepAlives: true,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("%s：%v", host, err)
	}
	req.Header.Set("User-Agent", "curl/8.5.0") // 两家都按 UA 给纯文本 / 网页，curl 的最稳
	req.Close = true
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s：%s", host, akileNetError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s：HTTP %d", host, resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	ip, err := akileExtractIPv4(string(body))
	if err != nil {
		return "", fmt.Errorf("%s：%v", host, err)
	}
	return ip, nil
}

// 各端点并发问，谁先给出合法地址用谁；都不行时把各家的原因连起来
func akileEgressIPv4() (string, error) {
	if len(akileIPEndpoints) == 0 {
		return "", errors.New("没有可用的查询地址")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type answer struct {
		ip  string
		err error
	}
	ch := make(chan answer, len(akileIPEndpoints))
	for _, ep := range akileIPEndpoints {
		go func(ep string) {
			ip, err := akileFetchIP(ctx, ep)
			ch <- answer{ip, err}
		}(ep)
	}
	var reasons []string
	for range akileIPEndpoints {
		a := <-ch
		if a.err == nil {
			return a.ip, nil
		}
		reasons = append(reasons, a.err.Error())
	}
	return "", errors.New(strings.Join(reasons, "；"))
}

// url.Error 的文字里带整条地址，只留底下的原因；超时统一写「超时」
func akileNetError(err error) string {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		err = uerr.Err
	}
	if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
		return "超时"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "超时"
	}
	return err.Error()
}

// ---------- 开放接口 ----------

type akileRule struct {
	ID             int64  `json:"id"`
	EntryWhitelist string `json:"entry_whitelist"`
	Summary        string `json:"summary"`
	NodeID         string `json:"node_id"`
	ListenPort     int    `json:"listen_port"`
}

type akileOutcome struct {
	OK       bool
	Kind     string
	Changed  bool
	Previous string
	Error    string
}

func akileClient() *http.Client {
	return &http.Client{
		Timeout: akileAPITimeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return panelDial(ctx, "tcp", addr)
			},
			TLSClientConfig:     akileTLSConfig,
			TLSHandshakeTimeout: akileAPITimeout,
			DisableKeepAlives:   true,
		},
	}
}

// 发一次请求：返回状态码与正文；连不上时 err 是「连不上：<原因>」（已脱敏）
func akileDo(method, path, key string, body []byte) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, strings.TrimRight(akileAPIBase, "/")+path, reader)
	if err != nil {
		return 0, nil, errors.New("连不上：" + akileRedact(err.Error(), key))
	}
	req.Header.Set("X-API-Key", key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "MeowX")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := akileClient().Do(req)
	if err != nil {
		return 0, nil, errors.New("连不上：" + akileRedact(akileNetError(err), key))
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, data, nil
}

// 出错应答的文字：error（字符串，或对象里的 message）、message、msg、detail；都没有用「HTTP <码>」
func akileServerText(status int, body []byte) string {
	var obj map[string]any
	if json.Unmarshal(body, &obj) == nil && obj != nil {
		if v, ok := obj["error"]; ok {
			switch e := v.(type) {
			case string:
				if s := strings.TrimSpace(e); s != "" {
					return s
				}
			case map[string]any:
				if s, _ := e["message"].(string); strings.TrimSpace(s) != "" {
					return strings.TrimSpace(s)
				}
			}
		}
		for _, k := range []string{"message", "msg", "detail"} {
			if s, _ := obj[k].(string); strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return fmt.Sprintf("HTTP %d", status)
}

// 状态码归类（规格 §1.2）：200 由调用方自己判断
func akileClassify(status int, body []byte) (string, string) {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return akileKindInvalidKey, akileTextInvalidKey
	case http.StatusNotFound:
		return akileKindNotFound, akileTextNotFound
	case http.StatusTooManyRequests:
		return akileKindRateLimited, akileTextRateLimited
	}
	return akileKindFailed, akileServerText(status, body)
}

// 解析规则列表（宽松，规格 §1.1）：外层 data 数组 / data.items|list|rules / 顶层 rules|items / 顶层数组；
// id 必须是整数（数字或纯数字字符串）；应答里带 listen_port 且不等于查询的端口的丢掉（防服务端忽略过滤参数）
func parseAkileRules(body []byte, port int) ([]akileRule, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return nil, false
	}
	var items []any
	found := false
	pick := func(m map[string]any, keys ...string) {
		for _, k := range keys {
			if arr, ok := m[k].([]any); ok {
				items, found = arr, true
				return
			}
		}
	}
	switch v := root.(type) {
	case []any:
		items, found = v, true
	case map[string]any:
		switch d := v["data"].(type) {
		case []any:
			items, found = d, true
		case map[string]any:
			pick(d, "items", "list", "rules")
		}
		if !found {
			pick(v, "rules", "items")
		}
	}
	if !found {
		return nil, false
	}
	rules := make([]akileRule, 0, len(items))
	for _, it := range items {
		m, _ := it.(map[string]any)
		if m == nil {
			continue
		}
		id, ok := akileInt(m["id"])
		if !ok {
			continue
		}
		r := akileRule{ID: id}
		if lp, ok := akileInt(m["listen_port"]); ok {
			if port > 0 && lp != int64(port) {
				continue
			}
			r.ListenPort = int(lp)
		}
		r.EntryWhitelist, _ = m["entry_whitelist"].(string)
		r.EntryWhitelist = strings.TrimSpace(r.EntryWhitelist)
		for _, k := range []string{"name", "remark", "note", "description", "node_name", "target"} {
			if s, _ := m[k].(string); strings.TrimSpace(s) != "" {
				r.Summary = strings.TrimSpace(s)
				break
			}
		}
		switch n := m["node_id"].(type) {
		case json.Number:
			r.NodeID = n.String()
		case string:
			r.NodeID = strings.TrimSpace(n)
		}
		rules = append(rules, r)
	}
	return rules, true
}

// JSON 数字（整数）或纯数字字符串
func akileInt(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := strconv.ParseInt(n.String(), 10, 64)
		return i, err == nil
	case float64:
		if n == float64(int64(n)) {
			return int64(n), true
		}
	case string:
		s := strings.TrimSpace(n)
		if s != "" && strings.TrimLeft(s, "0123456789") == "" {
			i, err := strconv.ParseInt(s, 10, 64)
			return i, err == nil
		}
	}
	return 0, false
}

// GET /rules?listen_port=<端口>：出错时返回界面文字
func akileListRules(key string, port int) ([]akileRule, error) {
	status, body, err := akileDo(http.MethodGet, "/rules?listen_port="+strconv.Itoa(port), key, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		_, text := akileClassify(status, body)
		return nil, errors.New(akileRedact(text, key))
	}
	rules, ok := parseAkileRules(body, port)
	if !ok {
		return nil, errors.New(akileTextBadReply)
	}
	return rules, nil
}

// PUT /rules/<id>/entry-whitelist {"entry_whitelist":"<IP>"}：200 且 data.id 存在才算成功
func akilePut(key string, ruleID int64, ip string) akileOutcome {
	payload, _ := json.Marshal(map[string]string{"entry_whitelist": ip})
	status, body, err := akileDo(http.MethodPut, "/rules/"+strconv.FormatInt(ruleID, 10)+"/entry-whitelist", key, payload)
	if err != nil {
		return akileOutcome{Kind: akileKindFailed, Error: err.Error()}
	}
	if status == http.StatusOK {
		return judgeAkilePut(body)
	}
	kind, text := akileClassify(status, body)
	return akileOutcome{Kind: kind, Error: akileRedact(text, key)}
}

func judgeAkilePut(body []byte) akileOutcome {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var obj map[string]any
	if dec.Decode(&obj) != nil || obj == nil {
		return akileOutcome{Kind: akileKindFailed, Error: akileTextBadReply}
	}
	data, _ := obj["data"].(map[string]any)
	if data == nil {
		return akileOutcome{Kind: akileKindFailed, Error: akileTextBadReply}
	}
	if _, ok := data["id"]; !ok || data["id"] == nil {
		return akileOutcome{Kind: akileKindFailed, Error: akileTextBadReply}
	}
	out := akileOutcome{OK: true, Kind: akileKindUnchanged}
	if changed, _ := data["changed"].(bool); changed {
		out.Changed, out.Kind = true, akileKindUpdated
	}
	prev, _ := data["previous"].(string)
	out.Previous = strings.TrimSuffix(strings.TrimSpace(prev), "/32")
	return out
}

// ---------- 上报 ----------

type akileNode struct {
	Name   string `json:"name"`
	Port   int    `json:"port"`
	RuleID int64  `json:"rule_id"`
	Label  string `json:"label"`
}

type akileResult struct {
	OK       bool   `json:"ok"`
	Kind     string `json:"kind"`
	IP       string `json:"ip,omitempty"`
	Previous string `json:"previous,omitempty"`
	Error    string `json:"error,omitempty"`
	At       int64  `json:"at"`
}

func akileResultKey(ruleID int64) string { return strconv.FormatInt(ruleID, 10) }

// 日志一行（规格 §4）：AkileCDN 白名单 <节点名>（规则 #<id>）：已更新 a → b / ：已更新为 b / ：已是 b / ：失败（原因）
func akileLogLine(n akileNode, r akileResult) string {
	head := fmt.Sprintf("AkileCDN 白名单 %s（规则 #%d）：", n.Name, n.RuleID)
	switch {
	case r.OK && r.Kind == akileKindUpdated && r.Previous != "":
		return head + "已更新 " + r.Previous + " → " + r.IP
	case r.OK && r.Kind == akileKindUpdated:
		return head + "已更新为 " + r.IP
	case r.OK:
		return head + "已是 " + r.IP
	}
	return head + "失败（" + r.Error + "）"
}

func akileErrorText(kind string) string {
	switch kind {
	case akileKindInvalidKey:
		return akileTextInvalidKey
	case akileKindRateLimited:
		return akileTextRateLimited
	}
	return ""
}

// 一轮：查一次出口 IP，再按 rule_id 依次 PUT（顺序发，不并发）。timer = 定时轮：出口 IP 与这个节点上一次成功写入的相同就跳过
// （结果保持不变，不刷新时间、不记日志）。429 / 401 / 403 之后本轮剩下的不再发，记同一个原因。返回本轮报了的节点与查到的 IP
func akileReport(key string, nodes []akileNode, timer bool) ([]map[string]any, string) {
	saved := loadAkileResults()
	now := time.Now().Unix()
	out := make([]map[string]any, 0, len(nodes))
	var lines []string

	ip, err := akileEgressIPv4()
	if err != nil {
		lines = append(lines, "AkileCDN 白名单："+akileTextNoIP+"（"+akileRedact(err.Error(), key)+"）")
		for _, n := range nodes {
			r := akileResult{Kind: akileKindFailed, Error: akileTextNoIP, At: now}
			saved[akileResultKey(n.RuleID)] = r
			out = append(out, akileNodeEntry(n, &r))
		}
		saveAkileResults(saved, loadAkileConfig().Nodes)
		ggyLog(lines)
		return out, ""
	}

	stop := "" // 本轮停在这个原因上（invalid_key / rate_limited）
	for _, n := range nodes {
		k := akileResultKey(n.RuleID)
		if last, ok := saved[k]; timer && ok && last.OK && last.IP == ip {
			continue
		}
		var r akileResult
		if stop != "" {
			r = akileResult{Kind: stop, Error: akileErrorText(stop), At: now}
		} else {
			o := akilePut(key, n.RuleID, ip)
			r = akileResult{OK: o.OK, Kind: o.Kind, Error: akileRedact(o.Error, key), At: now}
			if o.OK {
				r.IP, r.Previous = ip, o.Previous
			}
			if o.Kind == akileKindInvalidKey || o.Kind == akileKindRateLimited {
				stop = o.Kind
			}
		}
		saved[k] = r
		lines = append(lines, akileLogLine(n, r))
		out = append(out, akileNodeEntry(n, &r))
	}
	saveAkileResults(saved, loadAkileConfig().Nodes)
	ggyLog(lines)
	return out, ip
}

func akileNodeEntry(n akileNode, r *akileResult) map[string]any {
	entry := map[string]any{"name": n.Name, "port": n.Port, "rule_id": n.RuleID, "label": n.Label}
	if r != nil {
		entry["result"] = *r
	}
	return entry
}

// ---------- 存储 ----------

type akileConfig struct {
	Enabled bool        `json:"enabled"`
	Key     string      `json:"key"`
	Nodes   []akileNode `json:"nodes"`
}

// 开着、Key 合法、至少一个节点：才上报
func (cfg akileConfig) active() bool {
	return cfg.Enabled && akileKeyPattern.MatchString(cfg.Key) && len(cfg.Nodes) > 0
}

// 节点名 / 说明里的控制字符换成空格（uci 的 list 值、日志都是一行一条）；说明里不能有 |（uci 值按前三个 | 切）
func akileCleanText(s string, label bool) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	if label {
		s = strings.ReplaceAll(s, "|", "/")
	}
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200])
	}
	return s
}

// uci list 值：<rule_id>|<port>|<label 可空>|<name>（name 放最后、按前三个 | 切，name 里有 | 也不怕）
func encodeAkileNode(n akileNode) string {
	return fmt.Sprintf("%d|%d|%s|%s", n.RuleID, n.Port, n.Label, n.Name)
}

func decodeAkileNode(v string) (akileNode, bool) {
	parts := strings.SplitN(v, "|", 4)
	if len(parts) != 4 {
		return akileNode{}, false
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || id <= 0 {
		return akileNode{}, false
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil || port < 1 || port > 65535 {
		return akileNode{}, false
	}
	n := akileNode{RuleID: id, Port: port, Label: parts[2], Name: parts[3]}
	if n.Name == "" {
		n.Name = "#" + parts[0]
	}
	return n, true
}

// `uci show` 的值是 shell 单引号写法：每项包在单引号里、项与项之间空格；值里的单引号写成「引号收、反斜杠转义的引号、
// 引号开」四个字符。拆回原值
func splitUCIValues(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote, have := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQuote:
			if c == '\'' {
				inQuote = false
			} else {
				cur.WriteByte(c)
			}
		case c == '\'':
			inQuote, have = true, true
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			have = true
		case c == ' ' || c == '\t' || c == '\n':
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteByte(c)
			have = true
		}
	}
	if have {
		out = append(out, cur.String())
	}
	return out
}

// 加进列表时的规范化与去重（不落盘）
func (cfg *akileConfig) addNode(n akileNode) error {
	if n.RuleID <= 0 {
		return errors.New("规则 ID 不对")
	}
	if n.Port < 1 || n.Port > 65535 {
		return errors.New("端口不对")
	}
	n.Name = akileCleanText(n.Name, false)
	n.Label = akileCleanText(n.Label, true)
	if n.Name == "" {
		return errors.New("缺少节点名")
	}
	for _, x := range cfg.Nodes {
		if x.RuleID == n.RuleID {
			return errors.New("这条规则已经添加过")
		}
	}
	if len(cfg.Nodes) >= akileMaxNodes {
		return fmt.Errorf("最多 %d 个节点", akileMaxNodes)
	}
	cfg.Nodes = append(cfg.Nodes, n)
	return nil
}

// 读进来的列表：手改坏了的跳过、按 rule_id 去重、最多 20 个
func (cfg *akileConfig) normalize() {
	if !akileKeyPattern.MatchString(cfg.Key) {
		cfg.Key = ""
	}
	nodes := cfg.Nodes
	cfg.Nodes = nil
	for _, n := range nodes {
		if n.RuleID <= 0 || n.Port < 1 || n.Port > 65535 {
			continue
		}
		dup := false
		for _, x := range cfg.Nodes {
			dup = dup || x.RuleID == n.RuleID
		}
		if !dup && len(cfg.Nodes) < akileMaxNodes {
			cfg.Nodes = append(cfg.Nodes, n)
		}
	}
}

func loadAkileConfig() akileConfig {
	var cfg akileConfig
	if path := os.Getenv("MEOWX_AKILE_STATE"); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(data, &cfg)
		}
		cfg.normalize()
		return cfg
	}
	switch v, _ := ggyUCI("get", "meowx.akile.enabled"); v {
	case "1", "true", "yes", "on":
		cfg.Enabled = true
	}
	cfg.Key, _ = ggyUCI("get", "meowx.akile.key")
	// list 用 show 读：get 只给带空白的项加引号，节点名里有单引号时拆不回来
	if out, err := exec.Command("uci", "-q", "show", "meowx.akile.node").Output(); err == nil {
		line := strings.TrimRight(string(out), "\n")
		if i := strings.Index(line, "="); i >= 0 {
			for _, v := range splitUCIValues(line[i+1:]) {
				if n, ok := decodeAkileNode(v); ok {
					cfg.Nodes = append(cfg.Nodes, n)
				}
			}
		}
	}
	cfg.normalize()
	return cfg
}

func (cfg akileConfig) save() error {
	if path := os.Getenv("MEOWX_AKILE_STATE"); path != "" {
		if cfg.Nodes == nil {
			cfg.Nodes = []akileNode{}
		}
		data, err := json.Marshal(cfg)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			return err
		}
		return os.Rename(tmp, path)
	}
	enabled := "0"
	if cfg.Enabled {
		enabled = "1"
	}
	run := func(args ...string) error {
		if _, err := ggyUCI(args...); err != nil {
			_, _ = ggyUCI("revert", "meowx.akile")
			return fmt.Errorf("保存设置失败（uci %s）", args[0])
		}
		return nil
	}
	if err := run("set", "meowx.akile=akile"); err != nil {
		return err
	}
	if err := run("set", "meowx.akile.enabled="+enabled); err != nil {
		return err
	}
	if cfg.Key != "" {
		if err := run("set", "meowx.akile.key="+cfg.Key); err != nil {
			return err
		}
	} else {
		_, _ = ggyUCI("delete", "meowx.akile.key")
	}
	_, _ = ggyUCI("delete", "meowx.akile.node") // 整个列表重写；没有这一项时报错，不要紧
	for _, n := range cfg.Nodes {
		if err := run("add_list", "meowx.akile.node="+encodeAkileNode(n)); err != nil {
			return err
		}
	}
	return run("commit", "meowx")
}

func loadAkileResults() map[string]akileResult {
	m := map[string]akileResult{}
	if data, err := os.ReadFile(akileResultPath); err == nil {
		_ = json.Unmarshal(data, &m)
	}
	return m
}

// 只留还在列表里的规则的结果
func saveAkileResults(m map[string]akileResult, nodes []akileNode) {
	keep := map[string]akileResult{}
	for _, n := range nodes {
		k := akileResultKey(n.RuleID)
		if r, ok := m[k]; ok {
			keep[k] = r
		}
	}
	data, err := json.Marshal(keep)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(akileResultPath), 0o755)
	tmp := akileResultPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err == nil {
		_ = os.Rename(tmp, akileResultPath)
	}
}

// ---------- 订阅里的节点 ----------

// 没有端口、不是代理的类型（规格 §5：不含代理组、DIRECT / REJECT、tailscale 等）
var akileSkipTypes = map[string]bool{"direct": true, "reject": true, "reject-drop": true, "pass": true, "dns": true,
	"compatible": true, "tailscale": true}

func akileConfigNodes(path string) ([]map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读不到配置文件（%s）", path)
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, errors.New("配置文件无法解析")
	}
	out := make([]map[string]any, 0, len(doc.Proxies))
	for _, p := range doc.Proxies {
		name, _ := p["name"].(string)
		typ, _ := p["type"].(string)
		server, _ := p["server"].(string)
		port := akileYAMLPort(p["port"])
		if strings.TrimSpace(name) == "" || port == 0 || akileSkipTypes[strings.ToLower(strings.TrimSpace(typ))] {
			continue
		}
		out = append(out, map[string]any{"name": name, "type": typ, "server": server, "port": port})
	}
	return out, nil
}

// port 可能写成数字或字符串；不在 1–65535 回 0
func akileYAMLPort(v any) int {
	var n int64
	switch p := v.(type) {
	case int:
		n = int64(p)
	case int64:
		n = p
	case uint64:
		n = int64(p)
	case float64:
		n = int64(p)
		if float64(n) != p {
			return 0
		}
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return 0
		}
		n = int64(i)
	}
	if n < 1 || n > 65535 {
		return 0
	}
	return int(n)
}

// ---------- 子命令 ----------

func akileParsePort(s string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("端口不对")
	}
	return port, nil
}

func akileMain(args []string) (any, error) {
	cfg := loadAkileConfig()
	cmd := "status"
	if len(args) > 0 {
		cmd = args[0]
	}
	var reportNow []akileNode
	timer := false
	switch cmd {
	case "status":
	case "enable":
		// 从关到开立刻报一次
		if !cfg.Enabled {
			reportNow = cfg.Nodes
		}
		cfg.Enabled = true
		if err := cfg.save(); err != nil {
			return nil, err
		}
	case "disable":
		cfg.Enabled = false
		if err := cfg.save(); err != nil {
			return nil, err
		}
	case "setkey":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			return nil, errors.New(akileTextNeedKey)
		}
		key, ok := parseAkileKey(args[1])
		if !ok {
			return nil, errors.New(akileTextBadKey)
		}
		cfg.Key = key
		if err := cfg.save(); err != nil {
			return nil, err
		}
		reportNow = cfg.Nodes // 换 Key 立刻报（开关关着时下面不报）
	case "clearkey":
		cfg.Key = ""
		if err := cfg.save(); err != nil {
			return nil, err
		}
	case "nodes":
		path := akileDefaultNodes
		if len(args) > 1 && args[1] != "" {
			path = args[1]
		}
		nodes, err := akileConfigNodes(path)
		if err != nil {
			return nil, err
		}
		return map[string]any{"success": true, "nodes": nodes}, nil
	case "rules":
		if len(args) < 2 {
			return nil, errors.New("用法：akile rules <端口>")
		}
		port, err := akileParsePort(args[1])
		if err != nil {
			return nil, err
		}
		if cfg.Key == "" {
			return nil, errors.New(akileTextNeedKey)
		}
		rules, err := akileListRules(cfg.Key, port)
		if err != nil {
			return nil, err
		}
		return map[string]any{"success": true, "rules": rules}, nil
	case "add":
		if len(args) < 4 {
			return nil, errors.New("用法：akile add <规则 ID> <端口> <节点名> [<说明>]")
		}
		if cfg.Key == "" {
			return nil, errors.New(akileTextNeedKey)
		}
		id, ok := akileInt(args[1])
		if !ok || id <= 0 {
			return nil, errors.New("规则 ID 不对")
		}
		port, err := akileParsePort(args[2])
		if err != nil {
			return nil, err
		}
		n := akileNode{RuleID: id, Port: port, Name: args[3]}
		if len(args) > 4 {
			n.Label = args[4]
		}
		if err := cfg.addNode(n); err != nil {
			return nil, err
		}
		if err := cfg.save(); err != nil {
			return nil, err
		}
		reportNow = cfg.Nodes[len(cfg.Nodes)-1:] // 新加的只报这一个
	case "remove":
		if len(args) < 2 {
			return nil, errors.New("用法：akile remove <序号>")
		}
		i, err := strconv.Atoi(args[1])
		if err != nil || i < 0 || i >= len(cfg.Nodes) {
			return nil, errors.New("没有这一项")
		}
		cfg.Nodes = append(cfg.Nodes[:i], cfg.Nodes[i+1:]...)
		if err := cfg.save(); err != nil {
			return nil, err
		}
		saveAkileResults(loadAkileResults(), cfg.Nodes)
	case "report":
		for _, a := range args[1:] {
			if a == "--timer" {
				timer = true
			}
		}
		reportNow = cfg.Nodes
	default:
		return nil, fmt.Errorf("unknown akile command %q", cmd)
	}
	var results []map[string]any
	ip := ""
	if len(reportNow) > 0 && cfg.active() {
		results, ip = akileReport(cfg.Key, reportNow, timer)
	}
	return akileStatus(cfg, results, ip), nil
}

func akileStatus(cfg akileConfig, results []map[string]any, ip string) map[string]any {
	saved := loadAkileResults()
	nodes := make([]map[string]any, 0, len(cfg.Nodes))
	for _, n := range cfg.Nodes {
		var r *akileResult
		if x, ok := saved[akileResultKey(n.RuleID)]; ok {
			r = &x
		}
		nodes = append(nodes, akileNodeEntry(n, r))
	}
	out := map[string]any{"success": true, "enabled": cfg.Enabled, "has_key": cfg.Key != "", "key": maskAkileKey(cfg.Key),
		"max": akileMaxNodes, "nodes": nodes}
	if results != nil {
		out["results"] = results
	}
	if ip != "" {
		out["ip"] = ip
	}
	return out
}
