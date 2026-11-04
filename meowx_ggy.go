package main

// GGY 加白（同客户端「GGY 加白」）：GGY（咕咕云）「腾讯云 ECS 防火墙」插件的白名单分享链接——谁打开它，就把发起请求的
// 公网 IP 加进那台服务器的防火墙白名单。节点在 GGY 的服务器上时，路由器要定期用自己的直连出口 IP 打开它（与 po0 加白同一类）。
//
//	meowx-core panel ggy status | enable | disable | add <token 或整条分享链接> | remove <序号> | report
//
// 开关与 token 列表存 uci（meowx.ggy：option enabled、list token），本机偏好：退出登录不清、没登录也报。上一次的结果只放
// 内存盘（/var/run/meowx/ggy.json，按 token 的哈希记），重启后显示「还没报过」，免得每 10 分钟写一次闪存。
// 回给界面（rpcd）与写进日志的 token 一律是脱敏写法。

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
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
	"sync"
	"time"
	"unicode/utf8"
)

const ggyMaxTokens = 20

var (
	ggyReportBase = "https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token="
	ggyResultPath = "/var/run/meowx/ggy.json"
	ggyAppLogPath = "/var/log/meowx/app.log"
	// 只给测试用（信任测试服务器的自签证书）；正式运行为 nil = 照常按系统根证书校验（与 po0 不同，GGY 的证书是正规的）
	ggyTLSConfig *tls.Config
)

// 合法的 token：去掉首尾空白后只含 A–Z a–z 0–9 _ -，8–200 位；不强制前缀（现在的都是 ctecsfw_ 开头，以后可能有别的）
var ggyTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,200}$`)

// 输入框接受裸 token 或整条分享链接：带 ? 的当链接，取查询串里 token 的值
func parseGGYToken(input string) (string, bool) {
	s := strings.TrimSpace(input)
	if i := strings.Index(s, "?"); i >= 0 {
		query := s[i+1:]
		if j := strings.Index(query, "#"); j >= 0 {
			query = query[:j]
		}
		values, _ := url.ParseQuery(query) // 个别参数写坏了不要紧，能解出 token 就行
		s = strings.TrimSpace(values.Get("token"))
	}
	if !ggyTokenPattern.MatchString(s) {
		return "", false
	}
	return s, true
}

func ggyReportURL(token string) string { return ggyReportBase + token } // token 只含安全字符，不必再编码

// 脱敏：含 _ 时 <第一个 _ 及之前>••••<后 4 位>（如 ctecsfw_••••AAAA），否则 ••••<后 4 位>
func maskGGYToken(token string) string {
	tail := token
	if len(tail) > 4 {
		tail = tail[len(tail)-4:]
	}
	if i := strings.Index(token, "_"); i >= 0 {
		return token[:i+1] + "••••" + tail
	}
	return "••••" + tail
}

// ---------- 应答判断 ----------

type ggyOutcome struct {
	OK      bool
	Invalid bool   // token 无效或已失效：界面提示到 GGY 重新生成分享链接
	Reason  string // 失败原因；成功时是应答里的 msg（可能为空）
	Head    string // 应答没有 status 字段 / 解析不出时的应答开头 160 字节，只进日志（以后好对照）
}

// 无效 token 实测是 HTTP 200 + {"status":400,"msg":"白名单分享链接无效或已失效","data":[]}：不能按 HTTP 状态码判断，要看 status。
// 不是 JSON 对象（HTML、空、数组）算失败「应答无法解析」；成功时的应答没实测过（不能拿真 token 试），没有 status 字段当作成功
func judgeGGYResponse(httpStatus int, body []byte) ggyOutcome {
	if httpStatus != http.StatusOK {
		return ggyOutcome{Reason: fmt.Sprintf("HTTP %d", httpStatus)}
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
		return ggyOutcome{Reason: "应答无法解析", Head: ggySnippet(body)}
	}
	msg := ""
	if v, ok := obj["msg"]; ok && v != nil {
		msg = strings.TrimSpace(fmt.Sprint(v))
	}
	status, has := obj["status"]
	if !has {
		return ggyOutcome{OK: true, Reason: msg, Head: ggySnippet(body)}
	}
	if ggyStatusIs(status, 200) {
		return ggyOutcome{OK: true, Reason: msg}
	}
	out := ggyOutcome{Reason: msg}
	if out.Reason == "" {
		out.Reason = "status " + ggyStatusText(status)
	}
	out.Invalid = ggyStatusIs(status, 400) && (strings.Contains(msg, "无效") || strings.Contains(msg, "失效"))
	return out
}

// 日志一行：GGY 加白 <脱敏 token>：成功[（msg；应答没有 status：<应答开头>）] / GGY 加白 <脱敏 token>：失败（原因[：应答开头]）
func ggyLogLine(masked string, o ggyOutcome) string {
	if o.OK {
		var extra []string
		if o.Reason != "" {
			extra = append(extra, o.Reason)
		}
		if o.Head != "" {
			extra = append(extra, "应答没有 status："+o.Head)
		}
		line := "GGY 加白 " + masked + "：成功"
		if len(extra) > 0 {
			line += "（" + strings.Join(extra, "；") + "）"
		}
		return line
	}
	reason := o.Reason
	if o.Head != "" {
		reason += "：" + o.Head
	}
	return "GGY 加白 " + masked + "：失败（" + reason + "）"
}

// status 可能是数字也可能是字符串（200 / 200.0 / "200" / " 200 " 一样看待）
func ggyStatusIs(status any, code int) bool {
	switch v := status.(type) {
	case float64:
		return v == float64(code)
	case string:
		return strings.TrimSpace(v) == strconv.Itoa(code)
	}
	return false
}

func ggyStatusText(status any) string {
	switch v := status.(type) {
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case string:
		return strings.TrimSpace(v)
	case nil:
		return "null"
	}
	b, _ := json.Marshal(status)
	return string(b)
}

// 应答开头 160 字节（不切断 UTF-8 字符，换行换成空格）
func ggySnippet(body []byte) string {
	if len(body) > 160 {
		body = body[:160]
		for len(body) > 0 && !utf8.Valid(body) {
			body = body[:len(body)-1]
		}
	}
	return strings.Join(strings.Fields(string(body)), " ")
}

// ---------- 上报 ----------

// 必须直连（GGY 按来源 IP 加白，走代理会把节点的 IP 加进去）：与 po0 同一套——panelMain 一开始已把进程挪进 meowx 服务的
// cgroup（透明代理放行），panelDial 直接问公共 DNS。只走 IPv4：www.guguyun.com 只有 A 记录，节点也基本按 IPv4 连，
// 以后它加了 AAAA 也别让路由器的 IPv6 出口顶替 IPv4 去加白。GET、不带 body，头只要 Host / Accept / Connection: close，10 秒超时
func reportGGY(token string) ggyOutcome {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return panelDial(ctx, "tcp4", addr)
			},
			TLSClientConfig:     ggyTLSConfig,
			TLSHandshakeTimeout: 10 * time.Second,
			DisableKeepAlives:   true,
			DisableCompression:  true, // 不加 Accept-Encoding
		},
	}
	req, err := http.NewRequest(http.MethodGet, ggyReportURL(token), nil)
	if err != nil {
		return ggyOutcome{Reason: ggyRedact(err.Error(), token)}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "") // 空值 = 不发 User-Agent
	req.Close = true                 // Connection: close
	resp, err := client.Do(req)
	if err != nil {
		// url.Error 的文字里带整条地址（含 token），只留底下的原因
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			return ggyOutcome{Reason: "连不上：超时"}
		}
		return ggyOutcome{Reason: "连不上：" + ggyRedact(err.Error(), token)}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil && resp.StatusCode == http.StatusOK {
		return ggyOutcome{Reason: "读应答失败：" + ggyRedact(err.Error(), token)}
	}
	out := judgeGGYResponse(resp.StatusCode, body)
	out.Reason = ggyRedact(out.Reason, token)
	out.Head = ggyRedact(out.Head, token)
	return out
}

// 任何要显示 / 写日志的文字里都不留完整 token
func ggyRedact(text, token string) string {
	return strings.ReplaceAll(text, token, maskGGYToken(token))
}

type ggyResult struct {
	OK      bool   `json:"ok"`
	Invalid bool   `json:"invalid,omitempty"`
	Error   string `json:"error,omitempty"`
	At      int64  `json:"at"`
}

// 每个 token 各报一次（并发：开关打开 / 添加时由界面同步等结果，最多 10 秒），结果记进内存盘、每个一行写进插件日志
func ggyReport(tokens []string) []map[string]any {
	outcomes := make([]ggyOutcome, len(tokens))
	var wg sync.WaitGroup
	for i, token := range tokens {
		wg.Add(1)
		go func(i int, token string) {
			defer wg.Done()
			outcomes[i] = reportGGY(token)
		}(i, token)
	}
	wg.Wait()

	now := time.Now().Unix()
	saved := loadGGYResults()
	lines := make([]string, 0, len(tokens))
	out := make([]map[string]any, 0, len(tokens))
	for i, token := range tokens {
		o := outcomes[i]
		masked := maskGGYToken(token)
		res := map[string]any{"kind": "ggy", "token": masked, "ok": o.OK}
		if o.OK {
			saved[ggyKey(token)] = ggyResult{OK: true, At: now}
		} else {
			saved[ggyKey(token)] = ggyResult{Invalid: o.Invalid, Error: o.Reason, At: now}
			res["error"] = o.Reason
			if o.Invalid {
				res["invalid"] = true
			}
		}
		lines = append(lines, ggyLogLine(masked, o))
		out = append(out, res)
	}
	saveGGYResults(saved, loadGGYConfig().Tokens)
	ggyLog(lines)
	return out
}

// 写进插件日志（/var/log/meowx/app.log，格式同 init 的 log）。时间取 date 的输出：Go 不认 OpenWrt 的 /etc/TZ，
// 自己取会是 UTC，和前后几行对不上
func ggyLog(lines []string) {
	if len(lines) == 0 {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	if out, err := exec.Command("date", "+%Y-%m-%d %H:%M:%S").Output(); err == nil && len(strings.TrimSpace(string(out))) > 0 {
		ts = strings.TrimSpace(string(out))
	}
	_ = os.MkdirAll(filepath.Dir(ggyAppLogPath), 0o755)
	f, err := os.OpenFile(ggyAppLogPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	for _, line := range lines {
		_, _ = fmt.Fprintf(f, "[%s] [Whitelist] %s\n", ts, line)
	}
}

// ---------- 存储 ----------

type ggyConfig struct {
	Enabled bool
	Tokens  []string
}

func ggyUCI(args ...string) (string, error) {
	out, err := exec.Command("uci", append([]string{"-q"}, args...)...).Output()
	return strings.TrimSpace(string(out)), err
}

func loadGGYConfig() ggyConfig {
	var cfg ggyConfig
	switch v, _ := ggyUCI("get", "meowx.ggy.enabled"); v {
	case "1", "true", "yes", "on":
		cfg.Enabled = true
	}
	// list 由 uci get 以空格连成一行；token 里没有空白。手改坏了的条目跳过
	if v, err := ggyUCI("get", "meowx.ggy.token"); err == nil {
		for _, t := range strings.Fields(v) {
			if ggyTokenPattern.MatchString(t) && !ggyContains(cfg.Tokens, t) {
				cfg.Tokens = append(cfg.Tokens, t)
			}
		}
	}
	return cfg
}

func (cfg ggyConfig) save() error {
	enabled := "0"
	if cfg.Enabled {
		enabled = "1"
	}
	run := func(args ...string) error {
		if _, err := ggyUCI(args...); err != nil {
			_, _ = ggyUCI("revert", "meowx.ggy")
			return fmt.Errorf("保存设置失败（uci %s）", args[0])
		}
		return nil
	}
	if err := run("set", "meowx.ggy=ggy"); err != nil {
		return err
	}
	if err := run("set", "meowx.ggy.enabled="+enabled); err != nil {
		return err
	}
	_, _ = ggyUCI("delete", "meowx.ggy.token") // 整个列表重写；没有这一项时报错，不要紧
	for _, t := range cfg.Tokens {
		if err := run("add_list", "meowx.ggy.token="+t); err != nil {
			return err
		}
	}
	return run("commit", "meowx")
}

// 加进列表（不落盘）：解析 / 校验输入，去重按规范化后的 token，最多 20 个
func (cfg *ggyConfig) add(input string) (string, error) {
	if strings.TrimSpace(input) == "" {
		return "", errors.New("请填写 token")
	}
	token, ok := parseGGYToken(input)
	if !ok {
		return "", errors.New("token 格式不对")
	}
	if ggyContains(cfg.Tokens, token) {
		return "", errors.New("这个 token 已经添加过")
	}
	if len(cfg.Tokens) >= ggyMaxTokens {
		return "", fmt.Errorf("最多添加 %d 个 token", ggyMaxTokens)
	}
	cfg.Tokens = append(cfg.Tokens, token)
	return token, nil
}

func ggyContains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func ggyKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:8])
}

func loadGGYResults() map[string]ggyResult {
	m := map[string]ggyResult{}
	if data, err := os.ReadFile(ggyResultPath); err == nil {
		_ = json.Unmarshal(data, &m)
	}
	return m
}

// 只留还在列表里的 token 的结果
func saveGGYResults(m map[string]ggyResult, tokens []string) {
	keep := map[string]ggyResult{}
	for _, t := range tokens {
		if r, ok := m[ggyKey(t)]; ok {
			keep[ggyKey(t)] = r
		}
	}
	data, err := json.Marshal(keep)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(ggyResultPath), 0o755)
	tmp := ggyResultPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err == nil {
		_ = os.Rename(tmp, ggyResultPath)
	}
}

// ---------- 子命令 ----------

func ggyMain(args []string) (any, error) {
	cfg := loadGGYConfig()
	cmd := "status"
	if len(args) > 0 {
		cmd = args[0]
	}
	var reportNow []string
	switch cmd {
	case "status":
	case "enable":
		// 从关到开立刻报一次
		if !cfg.Enabled {
			reportNow = cfg.Tokens
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
	case "add":
		if len(args) < 2 {
			return nil, errors.New("用法：ggy add <token 或分享链接>")
		}
		token, err := cfg.add(args[1])
		if err != nil {
			return nil, err
		}
		if err := cfg.save(); err != nil {
			return nil, err
		}
		// 开着时新加的立刻报一次
		if cfg.Enabled {
			reportNow = []string{token}
		}
	case "remove":
		if len(args) < 2 {
			return nil, errors.New("用法：ggy remove <序号>")
		}
		i, err := strconv.Atoi(args[1])
		if err != nil || i < 0 || i >= len(cfg.Tokens) {
			return nil, errors.New("没有这一项")
		}
		cfg.Tokens = append(cfg.Tokens[:i], cfg.Tokens[i+1:]...)
		if err := cfg.save(); err != nil {
			return nil, err
		}
		saveGGYResults(loadGGYResults(), cfg.Tokens)
	case "report":
		if cfg.Enabled {
			reportNow = cfg.Tokens
		}
	default:
		return nil, fmt.Errorf("unknown ggy command %q", cmd)
	}
	var results []map[string]any
	if len(reportNow) > 0 {
		results = ggyReport(reportNow)
	}
	return ggyStatus(cfg, results), nil
}

func ggyStatus(cfg ggyConfig, results []map[string]any) map[string]any {
	saved := loadGGYResults()
	tokens := make([]map[string]any, 0, len(cfg.Tokens))
	for _, t := range cfg.Tokens {
		entry := map[string]any{"token": maskGGYToken(t)}
		if r, ok := saved[ggyKey(t)]; ok {
			entry["result"] = r
		}
		tokens = append(tokens, entry)
	}
	out := map[string]any{"success": true, "enabled": cfg.Enabled, "tokens": tokens, "max": ggyMaxTokens}
	if results != nil {
		out["results"] = results
	}
	return out
}
