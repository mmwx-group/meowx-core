package panelrt

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/entryoverride"
)

// 主控 → 客户端的消息（规格 §2.2，扁平 JSON，type 判别）。rev 在入口消息里是毫秒时间戳（数字），
// 在订阅消息里是指纹（字符串），所以先按原样收下再分别解析。
type message struct {
	Type       string             `json:"type"`
	Domain     string             `json:"domain"`
	HealthyIPs []string           `json:"healthyIPs"`
	ChainID    json.RawMessage    `json:"chainId"`
	Rev        json.RawMessage    `json:"rev"`
	Reason     string             `json:"reason"`
	Ports      *[]json.RawMessage `json:"ports"` // 入口端口；没有这个字段（老主控）= 只比 server，[] = 不匹配任何节点
	Ready      *bool              `json:"ready"`
	Entries    []snapshotEntry    `json:"entries"`
	Subs       *[]rawSubRev       `json:"subs"` // 没有这个字段（旧主控）= 这个主控来的全部订阅
}

type snapshotEntry struct {
	Server  string             `json:"server"`
	ChainID json.RawMessage    `json:"chainId"`
	IPs     []string           `json:"ips"`
	Rev     json.RawMessage    `json:"rev"`
	Ports   *[]json.RawMessage `json:"ports"` // 同 message.Ports
}

type rawSubRev struct {
	Key string          `json:"key"`
	Rev json.RawMessage `json:"rev"`
}

// parseInt64 数字或数字字符串。
func parseInt64(raw json.RawMessage) (int64, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return 0, false
	}
	s := string(raw)
	if raw[0] == '"' {
		if err := json.Unmarshal(raw, &s); err != nil {
			return 0, false
		}
	}
	if n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
		return n, true
	}
	if f, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
		return int64(f), true
	}
	return 0, false
}

// parseString 字符串或数字（订阅 rev 主控定为字符串，容一手数字）。
func parseString(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	if raw[0] == '"' {
		var s string
		_ = json.Unmarshal(raw, &s)
		return s
	}
	return string(raw)
}

func parseIPs(list []string) []netip.Addr {
	out := make([]netip.Addr, 0, len(list))
	for _, s := range list {
		s = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(s), "["), "]")
		if ip, err := netip.ParseAddr(s); err == nil {
			out = append(out, ip.Unmap())
		}
	}
	return out
}

// parsePorts 入口端口（规格 §1）：没有字段 = 零值（只比 server）；有字段时取其中合法的端口（数字或数字字符串），
// 一个都没有也是「给了、为空」= 不匹配任何节点。
func parsePorts(raw *[]json.RawMessage) entryoverride.Ports {
	if raw == nil {
		return entryoverride.Ports{}
	}
	list := make([]uint16, 0, len(*raw))
	for _, r := range *raw {
		if n, ok := parseInt64(r); ok && n > 0 && n <= 65535 {
			list = append(list, uint16(n))
		}
	}
	return entryoverride.PortList(list...)
}

// ack 回执（规格 §2.5）：应用完一个键的变更后发 {"type":"entry_ack","chainId","rev"}。
type ack struct {
	ChainID int64
	Rev     int64
}

// handleMessage 处理一条消息，回要发的回执（只有经 WS 收到时才发）。origin 为空 = 经 WS 推来的。
func (c *channel) handleMessage(m *message, origin string, received time.Time) []ack {
	switch m.Type {
	case "entry_failover":
		c.noteEvent(m.Type)
		if origin == "" {
			origin = entryoverride.OriginPush
		}
		rev, hasRev := parseInt64(m.Rev)
		if !hasRev {
			rev = received.UnixMilli() // 旧主控不带 rev：按收到的时间
		}
		chainID, _ := parseInt64(m.ChainID)
		res := entryoverride.Apply(c.cfg.Base, c.scope, origin, entryoverride.Update{
			Server: m.Domain, IPs: parseIPs(m.HealthyIPs), Ports: parsePorts(m.Ports), Rev: rev, ChainID: chainID, Reason: m.Reason})
		// 推送的决定本机已经在用了（刚换上，或者之前就收到过）才回执；旧主控不带 rev，不回
		if hasRev && res.Server != "" && res.Rev >= rev {
			return []ack{{ChainID: chainID, Rev: rev}}
		}
	case "entry_snapshot":
		c.noteEvent(m.Type)
		if origin == "" {
			origin = entryoverride.OriginSnapshot
		}
		return c.applySnapshot(m.Ready != nil && *m.Ready, m.Entries, origin, received)
	case "subscription_changed":
		c.noteEvent(m.Type)
		if m.Subs == nil {
			subs.changed(c.cfg.Base, "", parseString(m.Rev))
			return nil
		}
		for _, s := range *m.Subs {
			if s.Key != "" {
				subs.changed(c.cfg.Base, s.Key, parseString(s.Rev))
			}
		}
	case "sub_snapshot":
		c.noteEvent(m.Type)
		if m.Subs != nil {
			c.applySubSnapshot(*m.Subs)
		}
	}
	return nil
}

func (c *channel) applySnapshot(ready bool, entries []snapshotEntry, origin string, asOf time.Time) []ack {
	list := make([]entryoverride.Update, 0, len(entries))
	for _, e := range entries {
		rev, ok := parseInt64(e.Rev)
		if !ok {
			rev = asOf.UnixMilli()
		}
		chainID, _ := parseInt64(e.ChainID)
		list = append(list, entryoverride.Update{Server: e.Server, IPs: parseIPs(e.IPs), Ports: parsePorts(e.Ports),
			Rev: rev, ChainID: chainID})
	}
	results := entryoverride.ApplySnapshot(c.cfg.Base, c.scope, origin, ready, asOf, list)
	var acks []ack
	for _, r := range results {
		if r.Applied {
			acks = append(acks, ack{ChainID: r.ChainID, Rev: r.Rev})
		}
	}
	return acks
}

func (c *channel) applySubSnapshot(list []rawSubRev) {
	for _, s := range list {
		if s.Key != "" {
			subs.changed(c.cfg.Base, s.Key, parseString(s.Rev))
		}
	}
}
