package main

// 喵窝 status / devices 应答的整理与出错提示（纯函数，单测在 meowx_mesh_view_test.go）。
// 规格：miaomiaowuC/Design/meshnet-whitelist-direct.md §A；主控接口：mmwx-mesh/docs/MEOWX_MESH_CLIENT_API.md。

import (
	"fmt"
	"strings"
)

// meshError 喵窝管理接口的业务错误：带状态码（panelMain 输出 http_status）
type meshError struct {
	status int
	msg    string
}

func (e *meshError) Error() string   { return e.msg }
func (e *meshError) HTTPStatus() int { return e.status }

// meshErrorText 按业务状态码给提示。serverMsg 是主控回的 error（可能为空）；status 只在 409 时用来重查喵窝状态
// （nil 或拿不到就按「设备数达上限」说，那是 409 最常见的原因）。
//
//	401       登录失效（外壳没法自己续期，只能重新用登录链接登录）
//	403       多半已被移出喵窝名单
//	409       主控关了喵窝 / 设备数到上限
//	429 / 503 稍后再试（入网每账号每分钟最多 5 次）
//	502       主控连不上组网服务；本机设备身份照旧保留
func meshErrorText(code int, serverMsg string, status func() map[string]any) string {
	serverMsg = strings.TrimSpace(serverMsg)
	switch code {
	case 401:
		return "登录已失效，请重新登录主控账户"
	case 403:
		return "这个账号不能用喵窝了（可能已被移出喵窝名单）"
	case 409:
		var st map[string]any
		if status != nil {
			st = status()
		}
		if reason, _ := st["reason"].(string); reason == "disabled" {
			return "主控已关闭喵窝"
		}
		if reason, _ := st["reason"].(string); reason == "not_admin" {
			return "这个账号不能用喵窝了（可能已被移出喵窝名单）"
		}
		if n := meshInt(st["device_limit"]); n > 0 {
			return fmt.Sprintf("设备数已达上限（%d 台）", n)
		}
		return "设备数已达上限"
	case 429, 503:
		return "主控忙，请稍后再试"
	case 502:
		return "主控暂时连不上组网服务，请稍后再试（本机的喵窝身份不受影响）"
	}
	if serverMsg != "" {
		return serverMsg
	}
	return fmt.Sprintf("主控回 HTTP %d", code)
}

// normalizeMeshStatus 整理 status：access_scope 只认三个值（旧主控没有 = 不输出）；in_list = 账号在喵窝名单里
// （available，或原因不是 not_admin——主控关了 / 启动中也算在名单里）；servers（预留，可能没有）只留有名称与喵窝地址的条目。
// 其余字段原样保留。
func normalizeMeshStatus(obj map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range obj {
		out[k] = v
	}
	available, _ := obj["available"].(bool)
	reason, _ := obj["reason"].(string)
	out["in_list"] = available || (reason != "" && reason != "not_admin")
	switch scope, _ := obj["access_scope"].(string); scope {
	case "servers", "sites", "full":
	default:
		delete(out, "access_scope")
	}
	out["device_limit"] = meshInt(obj["device_limit"])
	servers := []any{}
	if list, ok := obj["servers"].([]any); ok {
		for _, it := range list {
			m, _ := it.(map[string]any)
			name, _ := m["name"].(string)
			ip, _ := m["mesh_ip"].(string)
			name, ip = strings.TrimSpace(name), strings.TrimSpace(ip)
			if name == "" || ip == "" {
				continue
			}
			e := map[string]any{"name": name, "mesh_ip": ip}
			if id, ok := m["server_id"]; ok && id != nil {
				e["server_id"] = id
			}
			servers = append(servers, e)
		}
	}
	if len(servers) > 0 {
		out["servers"] = servers
	} else {
		delete(out, "servers")
	}
	return out
}

// normalizeMeshDevices 整理 devices：devices / sites / shared_devices 一律是列表（缺字段、null 当空），各设备的 routes /
// pending_routes 同样；共享设备里 ipv4 与 dns_name 都空、只有网段的是站点路由器（sites 范围下主控只给这种），标 kind=site，
// 其余 kind=device。每次都按这次的应答整份给出，外壳整份替换（管理员收紧范围后旧条目要消失）。
func normalizeMeshDevices(obj map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range obj {
		out[k] = v
	}
	out["devices"] = meshDeviceList(obj["devices"], false)
	out["shared_devices"] = meshDeviceList(obj["shared_devices"], true)
	sites := []any{}
	if list, ok := obj["sites"].([]any); ok {
		for _, it := range list {
			if m, ok := it.(map[string]any); ok {
				sites = append(sites, m)
			}
		}
	}
	out["sites"] = sites
	return out
}

func meshDeviceList(v any, shared bool) []any {
	out := []any{}
	list, _ := v.([]any)
	for _, it := range list {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		d := map[string]any{}
		for k, val := range m {
			d[k] = val
		}
		routes := meshStrings(m["routes"])
		d["routes"] = routes
		d["pending_routes"] = meshStrings(m["pending_routes"])
		if shared {
			ip, _ := m["ipv4"].(string)
			dns, _ := m["dns_name"].(string)
			if strings.TrimSpace(ip) == "" && strings.TrimSpace(dns) == "" {
				if len(routes) == 0 {
					continue // 没有地址也没有网段：什么都显示不了
				}
				d["kind"] = "site"
			} else {
				d["kind"] = "device"
			}
		}
		out = append(out, d)
	}
	return out
}

func meshStrings(v any) []any {
	out := []any{}
	list, _ := v.([]any)
	for _, it := range list {
		if s, ok := it.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func meshInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	}
	return 0
}
