package entryoverride

import (
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
)

// 节点小标（给 OpenWrt 上的外部面板 zashboard 用，缺省关）：开着时，有生效中入口覆盖的节点在控制接口的节点对象
// （GET /proxies、/proxies/{name}、/providers/proxies，见 adapter.Proxy.MarshalJSON）里多一个 icon 字段，
// 值是 data:image/svg+xml,<svg>…</svg>。zashboard 的 ProxyIcon 对这种写法不解码、把后面的 SVG 经 DOMPurify 净化后
// 内联成 16×16 的小图，SVG 里的 <title> 就是悬停提示。所以 SVG 原样拼在前缀后面、不做百分号编码（那边不解码，
// 编了会显示成乱码），也避开 % 与 #（宽高写死 16，不写 100%；没有宽高时内联 SVG 是 300×150）。
// 图形的颜色见 iconPath。
// meowC 等别的外壳不打开：它们读到节点带 icon 会怎样没查过。

var proxyIcon atomic.Bool

// SetProxyIcon 打开 / 关掉节点小标（PUT /meowx/realtime 的 "entryIcon"）。
func SetProxyIcon(on bool) { proxyIcon.Store(on) }

// ProxyIconEnabled 节点小标开着没有。
func ProxyIconEnabled() bool { return proxyIcon.Load() }

// iconPath 分叉箭头（意思同 SF Symbols 的 arrow.triangle.branch / Material 的 alt_route）：下面一根竖线，往上分成两支、
// 各带一个角形箭头。实心形状、不写 fill：zashboard 按所在位置给小标容器套 fill-primary / fill-base-content /
// 选中卡片上的 fill-primary-content，形状继承它就和面板别处的图标同色，深浅色、选没选中都看得清
// （第一版用 stroke="currentColor"，选中的浅底卡片上那里的文字色仍是浅色，几乎看不见）。各段同一绕向，重叠处照样填满。
const iconPath = `<path d="M4 4 10 4 4 10ZM20 4 20 10 14 4ZM6.71 5.29 12.71 11.29 11.29 12.71 5.29 6.71Z` +
	`M18.71 6.71 12.71 12.71 11.29 11.29 17.29 5.29ZM11 12 13 12 13 20 11 20Z"/>`

// ProxyIcon 节点（server + 端口）现在生效的入口覆盖的小标；节点小标没开、没有覆盖、端口不在入口端口里回空。
// 只读，不推进 Lookup 的轮转。
func ProxyIcon(host string, port uint16) string {
	if !proxyIcon.Load() || !active.Load() {
		return ""
	}
	key := NormalizeKey(host)
	if key == "" {
		return ""
	}
	t := now()
	tbl.mu.Lock()
	e := tbl.entries[key]
	if e == nil || len(e.ips) == 0 || t.Sub(e.confirmedAt) > ExpireAfter || !e.ports.Match(port) {
		tbl.mu.Unlock()
		return ""
	}
	title := iconTitle(e.ips, e.names, e.updatedAt, t)
	tbl.mu.Unlock()
	return "data:image/svg+xml," +
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16" height="16"><title>` + xmlEscape(title) + `</title>` +
		iconPath + `</svg>`
}

// iconTitle 悬停提示：「主控指定入口 香港入口 A（203.0.113.11）, 203.0.113.12 · 切换于 14:05」。
// 有名称写「名称（IP）」，没名称只写 IP；时间按本机时区，今天只写时刻，今年别的日子带月日，往年带年份。
func iconTitle(ips []netip.Addr, names map[netip.Addr]string, switched, at time.Time) string {
	parts := make([]string, len(ips))
	for i, ip := range ips {
		if name := names[ip]; name != "" {
			parts[i] = name + "（" + ip.String() + "）"
		} else {
			parts[i] = ip.String()
		}
	}
	s := "主控指定入口 " + strings.Join(parts, ", ")
	if switched.IsZero() || switched.Unix() <= 0 {
		return s
	}
	sw, cur := switched.Local(), at.Local()
	layout := "15:04"
	switch {
	case sw.Year() != cur.Year():
		layout = "2006-01-02 15:04"
	case sw.YearDay() != cur.YearDay():
		layout = "01-02 15:04"
	}
	return s + " · 切换于 " + sw.Format(layout)
}

var xmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")

func xmlEscape(s string) string { return xmlEscaper.Replace(s) }
