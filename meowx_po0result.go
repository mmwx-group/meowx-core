package main

// po0 加白的结果与备注（五端共用规格 miaomiaowuC/Design/po0-ggy-results.md）：每台 po0 记下上一次上报的判定与 po0 回的白名单，
// 界面据此显示「已加白 · 3/5」与槽位气泡；自定义 po0 / GGY token 可写备注（只存本机，不进上报请求）。
//
// 结果文件（MEOWX_PO0_RESULTS，缺省与 GGY 结果同目录的 po0-results.json，OpenWrt 上是内存盘）按上报地址的哈希记，
// 文件里不留完整 token；回给界面的文字里混进的 token 一律换成脱敏写法。

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// 结果 kind（与客户端同名）
const (
	po0KindSuccess      = "success"
	po0KindDisabled     = "disabled"
	po0KindNotApplied   = "notApplied"
	po0KindSlotConflict = "slotConflict"
	po0KindInvalidToken = "invalidToken"
	po0KindFailed       = "failed"
)

// 名单里的一项：slot 为 nil = 普通条目（名单满了按写入时间先进先出挤掉）
type po0Entry struct {
	IP   string `json:"ip"`
	Slot *int   `json:"slot"`
}

// 一台 po0 上一次上报的结果（规格 §1.3）。enabled 只有 200 时有（应答没写按开启）；limit 应答写了才有；
// current_ip 是 po0 看到的本机出口（可能是 x.x.x.0/24）。entries 为 null = 应答里没有名单（界面不画名单），[] = 名单是空的
type po0Result struct {
	Kind      string     `json:"kind"`
	Message   string     `json:"message,omitempty"`
	At        int64      `json:"at"`
	Enabled   *bool      `json:"enabled,omitempty"`
	Limit     *int       `json:"limit,omitempty"`
	CurrentIP string     `json:"current_ip,omitempty"`
	Entries   []po0Entry `json:"entries"`
	Slot      *int       `json:"slot"`
}

var po0ResultPath = "" // 空 = 与 GGY 结果同目录的 po0-results.json（MEOWX_GGY_RESULTS 改了目录时跟着走）

func po0ResultFile() string {
	if po0ResultPath != "" {
		return po0ResultPath
	}
	return filepath.Join(filepath.Dir(ggyResultPath), "po0-results.json")
}

// ---------- 判定（纯函数） ----------

// 同段判断（同 po0 官方脚本 sameC24）：字符串相等算同一个；任一边以 /24 结尾时，去掉 /24 后按 . 分成 4 段、前三段相同算同一个；
// 两边都是精确 IP 时必须全等。IPv6 只按全等（带冒号的分不出 4 段，自然不会命中前三段比较）
func po0SameC24(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	if !strings.HasSuffix(a, "/24") && !strings.HasSuffix(b, "/24") {
		return false
	}
	pa := strings.Split(strings.TrimSuffix(a, "/24"), ".")
	pb := strings.Split(strings.TrimSuffix(b, "/24"), ".")
	if len(pa) != 4 || len(pb) != 4 {
		return false
	}
	return pa[0] == pb[0] && pa[1] == pb[1] && pa[2] == pb[2]
}

// 上报地址里的 ?slot=N（没有 / 写坏了返回 nil）
func po0SlotFromURL(raw string) *int {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	v := u.Query().Get("slot")
	if v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return nil
	}
	return &n
}

// 槽位：数字或数字字符串；null / 别的都算没有
func po0JSONInt(v any) *int {
	switch x := v.(type) {
	case float64:
		if x == float64(int(x)) {
			n := int(x)
			return &n
		}
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
			return &n
		}
	}
	return nil
}

// 名单：每项是 {"ip": "...", "slot": N|null}，旧版服务端是纯 IP 字符串（= 没有槽位）；空的 / 认不得的项跳过。
// 不是数组（没有这个字段、null）返回 nil = 没有名单
func po0ParseWhitelist(v any) []po0Entry {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]po0Entry, 0, len(list))
	for _, it := range list {
		switch x := it.(type) {
		case string:
			if s := strings.TrimSpace(x); s != "" {
				out = append(out, po0Entry{IP: s})
			}
		case map[string]any:
			ip, _ := x["ip"].(string)
			if ip = strings.TrimSpace(ip); ip != "" {
				out = append(out, po0Entry{IP: ip, Slot: po0JSONInt(x["slot"])})
			}
		}
	}
	return out
}

// 一次上报的应答 → 结果（不含时间）。slot = 这次上报用的槽位（上报地址带 ?slot=N 时）。
// 200（规格 §1.1「缺字段时信 200」）：enabled 缺省按开启；enabled == false → disabled；名单与 currentIp 都有时，
// 名单里有与 currentIp 同段的 → success，否则 notApplied；名单或 currentIp 任一缺失无从比对 → success（老版 po0 只回个确认）。
// 403：带槽位 = 槽位冲突，不带 = token 无效。其它状态码 / 正文为空或不是 JSON 对象：失败
func judgePo0Response(status int, body []byte, slot *int) po0Result {
	res := po0Result{Slot: slot}
	var obj map[string]any
	isObject := json.Unmarshal(body, &obj) == nil && obj != nil
	switch status {
	case http.StatusOK:
	case http.StatusForbidden:
		if isObject {
			res.CurrentIP, _ = obj["currentIp"].(string)
		}
		if slot != nil {
			res.Kind = po0KindSlotConflict
			res.Message = "本机 IP 已在这台 po0 的其它槽位，先到 po0 面板删除旧槽位"
		} else {
			res.Kind = po0KindInvalidToken
		}
		return res
	default:
		res.Kind, res.Message = po0KindFailed, fmt.Sprintf("HTTP %d", status)
		return res
	}
	if !isObject {
		res.Kind, res.Message = po0KindFailed, "应答无法解析"
		return res
	}
	enabled := true
	if b, ok := obj["enabled"].(bool); ok {
		enabled = b
	}
	currentIP, _ := obj["currentIp"].(string)
	res.Enabled = &enabled
	res.Limit = po0JSONInt(obj["limit"])
	res.CurrentIP = strings.TrimSpace(currentIP)
	res.Entries = po0ParseWhitelist(obj["whitelist"])
	if !enabled {
		res.Kind = po0KindDisabled
		return res
	}
	if res.Entries == nil || res.CurrentIP == "" {
		res.Kind = po0KindSuccess
		return res
	}
	res.Kind = po0KindNotApplied
	for _, e := range res.Entries {
		if po0SameC24(e.IP, res.CurrentIP) {
			res.Kind = po0KindSuccess
			break
		}
	}
	return res
}

// 同一台 po0 的 IPv4 / IPv6 两发各有一个结果时选哪个：200 的优先（加白成功 > 未生效 > 防火墙没开），再是 403，最后是失败；
// 一样好时取前一个（IPv4 在前）
func po0ResultRank(kind string) int {
	switch kind {
	case po0KindSuccess:
		return 0
	case po0KindNotApplied:
		return 1
	case po0KindDisabled:
		return 2
	case po0KindSlotConflict:
		return 3
	case po0KindInvalidToken:
		return 4
	}
	return 5
}

func po0PickResult(results []po0Result) (po0Result, bool) {
	if len(results) == 0 {
		return po0Result{}, false
	}
	best := results[0]
	for _, r := range results[1:] {
		if po0ResultRank(r.Kind) < po0ResultRank(best.Kind) {
			best = r
		}
	}
	return best, true
}

// 结果的一句话（中文，写日志用；界面按 kind 自己拼、走各自的翻译）
func po0ResultText(r po0Result) string {
	count := func() string {
		if r.Limit != nil {
			return fmt.Sprintf("%d/%d", len(r.Entries), *r.Limit)
		}
		return strconv.Itoa(len(r.Entries))
	}
	switch r.Kind {
	case po0KindSuccess:
		// 有 limit 才带「条数/limit」；应答里没有名单时条数无从说起，也只写「已加白」
		if r.Limit == nil || r.Entries == nil {
			return "已加白"
		}
		return "已加白 · " + count()
	case po0KindDisabled:
		return "po0 没有开启防火墙"
	case po0KindNotApplied:
		return "加白未生效 · " + count()
	case po0KindSlotConflict:
		return "槽位冲突：本机 IP 已在这台 po0 的其它槽位，先到 po0 面板删除旧槽位"
	case po0KindInvalidToken:
		return "token 无效"
	}
	msg := r.Message
	if msg == "" {
		msg = "未知错误"
	}
	return "失败：" + msg
}

// 任何要显示的文字里出现的 po0 token 都换成脱敏写法（错误信息里可能带着上报地址）
var po0TokenInText = regexp.MustCompile(`pgnfw_[A-Za-z0-9_-]{4,200}`)

func redactPo0Tokens(text string) string {
	return po0TokenInText.ReplaceAllStringFunc(text, maskPo0Token)
}

// ---------- 备注 ----------

const noteMaxRunes = 40

// 备注：去掉首尾空白，换行 / 制表等控制字符换成空格，最多 40 个字符（按 Unicode 字符数）；空串 = 没有备注
func normalizeNote(raw string) (string, error) {
	if !utf8.ValidString(raw) {
		return "", errors.New("备注含有无效字符")
	}
	s := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, raw)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > noteMaxRunes {
		return "", fmt.Errorf("备注最多 %d 个字", noteMaxRunes)
	}
	return s, nil
}

// ---------- 存储 ----------

func po0ResultKey(reportURL string) string {
	sum := sha256.Sum256([]byte(reportURL))
	return hex.EncodeToString(sum[:8])
}

func loadPo0Results() map[string]po0Result {
	m := map[string]po0Result{}
	if data, err := os.ReadFile(po0ResultFile()); err == nil {
		_ = json.Unmarshal(data, &m)
	}
	return m
}

// 只留还在上报列表里的地址的结果（删掉的服务器、关掉总开关时对应的结果一起删）
func savePo0Results(m map[string]po0Result, urls []string) {
	keep := map[string]po0Result{}
	for _, u := range urls {
		if r, ok := m[po0ResultKey(u)]; ok {
			keep[po0ResultKey(u)] = r
		}
	}
	path := po0ResultFile()
	if len(keep) == 0 {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return // 一直没有结果就别为空表新建文件
		}
	}
	data, err := json.Marshal(keep)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err == nil {
		_ = os.Rename(tmp, path)
	}
}
