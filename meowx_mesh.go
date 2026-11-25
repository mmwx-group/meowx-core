package main

// 喵窝（主控内置的组网，Tailscale 协议）：路由器用官方 tailscale 程序入网，把局域网开放给本账号的其它设备。
// 这里只负责和主控打交道（加密 RPC，同客户端）；tailscale up、防火墙与网段映射在 /etc/meowx/ucode/mesh_cli.uc。
//
//	meowx-core panel mesh status                           主控开没开喵窝、本账号能不能用
//	meowx-core panel mesh sites --router <标识> [--force-map] [<网段>…]
//	                                                       申报这台路由器要开放的局域网网段（整份），返回本账号各站点在喵窝里用的
//	                                                       地址（router 字段是哪台的）；标识是路由器自己的稳定编号，同一账号下
//	                                                       多台路由器各申报各的
//	meowx-core panel mesh enroll <主机名> [<上次的设备编号>]  拿一次性入网 key（10 分钟内有效）
//	meowx-core panel mesh devices                          本账号的设备与站点
//	meowx-core panel mesh view                             喵窝页用：status + （在名单里时）devices，一次拿齐（devices 回 403 时重查 status）
//	meowx-core panel mesh delete <设备编号>                  从喵窝删掉一台设备
//
// status / devices 的应答先整理一遍再输出（meowx_mesh_view.go）：缺字段、null 一律当空列表，共享设备里只有网段的站点路由器
// 标成 kind=site，预留的 servers 只留有名称与喵窝地址的条目。出错时按业务状态码给出提示（401 / 403 / 409 / 429 / 503 / 502），
// 并在输出里带 http_status（见 panelMain）。

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"

	C "github.com/metacubex/mihomo/constant"
)

var meshDigits = regexp.MustCompile(`^[0-9]{1,19}$`)

func meshMain(args []string) (any, error) {
	if len(args) == 0 {
		return nil, errors.New("usage: meowx-core panel mesh status | sites --router <标识> [--force-map] <网段>… | enroll <主机名> [<设备编号>] | devices | view | delete <设备编号>")
	}
	st, err := loadPanelState()
	if err != nil {
		return nil, err
	}
	switch args[0] {
	case "status":
		obj, err := meshCall(st, "/user/mesh/status", "GET", nil)
		if err != nil {
			return nil, err
		}
		return normalizeMeshStatus(obj), nil
	case "sites":
		force := false
		router := ""
		networks := []string{}
		rest := args[1:]
		for i := 0; i < len(rest); i++ {
			switch rest[i] {
			case "--force-map":
				force = true
			case "--router":
				if i+1 < len(rest) {
					router = rest[i+1]
					i++
				}
			default:
				networks = append(networks, rest[i])
			}
		}
		if router == "" {
			return nil, errors.New("缺少路由器标识")
		}
		return meshCall(st, "/user/mesh/sites", "POST", map[string]any{"networks": networks, "force_map": force, "router": router})
	case "enroll":
		if len(args) < 2 || args[1] == "" {
			return nil, errors.New("缺少主机名")
		}
		// 系统名 / 客户端名：OpenWrt 版用缺省值，别的外壳（飞牛 NAS 版）经环境变量给
		meshOS, meshClient := os.Getenv("MEOWX_MESH_OS"), os.Getenv("MEOWX_MESH_CLIENT")
		if meshOS == "" {
			meshOS = "openwrt"
		}
		if meshClient == "" {
			meshClient = "meowx-openwrt"
		}
		payload := map[string]any{"hostname": args[1], "os": meshOS, "client": meshClient, "version": C.Version}
		if len(args) > 2 && meshDigits.MatchString(args[2]) {
			if id, err := strconv.ParseUint(args[2], 10, 64); err == nil && id > 0 {
				payload["previous_node_id"] = id
			}
		}
		return meshCall(st, "/user/mesh/enroll", "POST", payload)
	case "devices":
		obj, err := meshCall(st, "/user/mesh/devices", "GET", nil)
		if err != nil {
			return nil, err
		}
		return normalizeMeshDevices(obj), nil
	case "view":
		return meshView(st), nil
	case "delete":
		if len(args) < 2 || !meshDigits.MatchString(args[1]) {
			return nil, errors.New("设备编号不对")
		}
		return meshCall(st, "/user/mesh/devices/"+args[1], "DELETE", nil)
	default:
		return nil, fmt.Errorf("unknown mesh command %q", args[0])
	}
}

// meshView 喵窝页的一次读取：status 拿不到就整体报错（外壳显示原因）；devices 失败不影响 status，原因放 devices_error。
// devices 回 403（多半刚被移出名单）时重查一次 status，按新的 status 画（not_admin 就不再列共享设备）。
func meshView(st *panelState) map[string]any {
	out := map[string]any{"success": true}
	status, err := meshCall(st, "/user/mesh/status", "GET", nil)
	if err != nil {
		out["success"] = false
		out["error"] = err.Error()
		if he, ok := err.(*meshError); ok {
			out["http_status"] = he.status
		}
		return out
	}
	ns := normalizeMeshStatus(status)
	out["status"] = ns
	if in, _ := ns["in_list"].(bool); !in {
		return out
	}
	devices, err := meshCall(st, "/user/mesh/devices", "GET", nil)
	if err != nil {
		out["devices_error"] = err.Error()
		if he, ok := err.(*meshError); ok {
			out["devices_http_status"] = he.status
			if he.status == 403 {
				if again, e := meshCall(st, "/user/mesh/status", "GET", nil); e == nil {
					out["status"] = normalizeMeshStatus(again)
				}
			}
		}
		return out
	}
	out["devices"] = normalizeMeshDevices(devices)
	return out
}

// meshCall 发一次加密 RPC。加密 RPC 保留业务状态码：出错（{"error": "…"} 或 4xx / 5xx）时按状态码换成提示（meshErrorText），
// 409 先重查一次 status 分清「主控关了喵窝」与「设备数到上限」。devices 在服务未就绪时会回 200 + error（照样带着已登记的站点），
// 那种不当失败，原样交给外壳。
func meshCall(st *panelState, path, method string, payload map[string]any) (map[string]any, error) {
	raw, code, err := panelRPCRawStatus(st.Base, path, method, st.Token, payload)
	if err != nil {
		if code >= 400 {
			return nil, &meshError{status: code, msg: meshErrorText(code, err.Error(), nil)}
		}
		return nil, err
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		if code >= 400 {
			return nil, &meshError{status: code, msg: meshErrorText(code, "", nil)}
		}
		return nil, fmt.Errorf("主控应答无法解析：%v", err)
	}
	msg, _ := obj["error"].(string)
	if code >= 400 {
		var status func() map[string]any
		if code == 409 && path != "/user/mesh/status" {
			status = func() map[string]any {
				raw, c, err := panelRPCRawStatus(st.Base, "/user/mesh/status", "GET", st.Token, nil)
				if err != nil || c >= 400 {
					return nil
				}
				var s map[string]any
				if json.Unmarshal(raw, &s) != nil {
					return nil
				}
				return s
			}
		}
		return nil, &meshError{status: code, msg: meshErrorText(code, msg, status)}
	}
	if msg != "" && path != "/user/mesh/devices" {
		return nil, errors.New(msg)
	}
	return obj, nil
}
