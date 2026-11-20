package entryoverride

import (
	"encoding/binary"
	"os"
	"sync"
	"time"
)

// 节点小标里「切换于 HH:mm」用的显示时区。
//
// OpenWrt 没有 zoneinfo（/usr/share/zoneinfo 不存在，/etc/localtime 是指向 /tmp/localtime 的空链接），时区只在
// /etc/TZ 里写成一条 POSIX TZ 串（「CST-8」「CET-1CEST,M3.5.0,M10.5.0/3」），进程环境里也没有 TZ。Go 不认 POSIX TZ 串，
// time.Local 落成 UTC，提示里的时刻差 8 小时（用户路由器 iStoreOS 25.12 实报）。
//
// 所以：环境变量 TZ 为空、time.Local 是 Go 找不到本地时区时的回落（名字是 "UTC"；/etc/localtime 读得到时名字是
// "Local"，那就信它）、/etc/TZ 读得到且非空时，用它构造时区；否则照旧 time.Local。
// 构造不自己解析规则：在内存里拼一份没有跳变、只有一个时间类型的 TZif v2 数据，footer 写这条 TZ 串，交给
// time.LoadLocationFromTZData，夏令时由 Go 按 footer 的规则算。唯一那个时间类型的偏移取 TZ 串的标准时偏移，
// 夏令时那段 Go 解析不了时至少标准时是对的。只管这处显示：不改全局 time.Local，也不碰日志时间戳。

// etcTZPath /etc/TZ（测试里换掉）
var etcTZPath = "/etc/TZ"

// displayZone 小标提示用的时区（测试里换掉）
var displayZone = defaultDisplayZone

// tzRecheck /etc/TZ 至多这么久重读一次：/proxies 每个节点都要算一次提示，别每次都读文件
const tzRecheck = 30 * time.Second

var tzCache struct {
	mu      sync.Mutex
	checked time.Time
	content string
	loc     *time.Location
}

func defaultDisplayZone() *time.Location {
	if os.Getenv("TZ") != "" || time.Local.String() != "UTC" {
		return time.Local
	}
	t := time.Now()
	tzCache.mu.Lock()
	defer tzCache.mu.Unlock()
	if !tzCache.checked.IsZero() && t.Sub(tzCache.checked) < tzRecheck {
		return orLocal(tzCache.loc)
	}
	tzCache.checked = t
	data, err := os.ReadFile(etcTZPath)
	if err != nil {
		tzCache.content, tzCache.loc = "", nil
		return time.Local
	}
	s := trimTZ(string(data))
	if s != tzCache.content || tzCache.loc == nil {
		tzCache.content, tzCache.loc = s, posixTZLocation(s)
	}
	return orLocal(tzCache.loc)
}

func orLocal(l *time.Location) *time.Location {
	if l == nil {
		return time.Local
	}
	return l
}

// trimTZ 去掉首尾空白（文件末尾通常有换行）
func trimTZ(s string) string {
	start, end := 0, len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// posixTZLocation 按 POSIX TZ 串构造时区；串不合法（空、标准时名字或偏移写不对）回 nil。
func posixTZLocation(tz string) *time.Location {
	name, offset, ok := posixStd(tz)
	if !ok {
		return nil
	}
	loc, err := time.LoadLocationFromTZData(tz, tzifWithFooter(name, offset, tz))
	if err != nil {
		return nil
	}
	return loc
}

// posixStd 读 TZ 串开头的标准时名字与偏移（秒，东正西负——POSIX 写法是西正，CST-8 = UTC+8）。
// 名字是三个以上字母，或尖括号里的写法（<+0330>）；偏移 [+-]hh[:mm[:ss]]，小时 0–24。后面的夏令时部分不看。
func posixStd(s string) (name string, offset int, ok bool) {
	i := 0
	if i < len(s) && s[i] == '<' {
		j := i + 1
		for j < len(s) && s[j] != '>' {
			j++
		}
		if j >= len(s) || j-i-1 < 3 {
			return "", 0, false
		}
		name, i = s[i+1:j], j+1
	} else {
		for i < len(s) && (s[i] >= 'A' && s[i] <= 'Z' || s[i] >= 'a' && s[i] <= 'z') {
			i++
		}
		if i < 3 {
			return "", 0, false
		}
		name = s[:i]
	}
	sign := 1
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		if s[i] == '-' {
			sign = -1
		}
		i++
	}
	secs := 0
	for part, mul := 0, 3600; part < 3; part, mul = part+1, mul/60 {
		if part > 0 {
			if i >= len(s) || s[i] != ':' {
				break
			}
			i++
		}
		n, digits := 0, 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' && digits < 2 {
			n = n*10 + int(s[i]-'0')
			i++
			digits++
		}
		if digits == 0 || (part == 0 && n > 24) || (part > 0 && n > 59) {
			return "", 0, false
		}
		secs += n * mul
	}
	return name, -sign * secs, true
}

// tzifWithFooter 最小的 TZif v2：没有跳变、一个时间类型（偏移 offset、名字 name），footer 是「\n<tz>\n」。
// Go 没有跳变时整条时间轴都按 footer 的规则算（规则解析不了才用这个时间类型）。
func tzifWithFooter(name string, offset int, tz string) []byte {
	chars := append([]byte(name), 0)
	block := func(b []byte) []byte {
		// 头：魔数、版本、15 字节保留、六个计数（isut, isstd, leap, time, type, char）
		b = append(b, "TZif2"...)
		b = append(b, make([]byte, 15)...)
		for _, n := range []uint32{0, 0, 0, 0, 1, uint32(len(chars))} {
			b = binary.BigEndian.AppendUint32(b, n)
		}
		// 时间类型：utoff、isdst、名字下标
		b = binary.BigEndian.AppendUint32(b, uint32(int32(offset)))
		b = append(b, 0, 0)
		return append(b, chars...)
	}
	b := block(nil) // v1 数据
	b = block(b)    // v2 数据（没有跳变，8 字节时间戳也就无从谈起，两块一样）
	return append(append(append(b, '\n'), tz...), '\n')
}
