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
//	meowx-core panel mesh delete <设备编号>                  从喵窝删掉一台设备

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
		return nil, errors.New("usage: meowx-core panel mesh status | sites --router <标识> [--force-map] <网段>… | enroll <主机名> [<设备编号>] | devices | delete <设备编号>")
	}
	st, err := loadPanelState()
	if err != nil {
		return nil, err
	}
	switch args[0] {
	case "status":
		return meshCall(st, "/user/mesh/status", "GET", nil)
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
		return meshCall(st, "/user/mesh/devices", "GET", nil)
	case "delete":
		if len(args) < 2 || !meshDigits.MatchString(args[1]) {
			return nil, errors.New("设备编号不对")
		}
		return meshCall(st, "/user/mesh/devices/"+args[1], "DELETE", nil)
	default:
		return nil, fmt.Errorf("unknown mesh command %q", args[0])
	}
}

// meshCall 发一次加密 RPC。主控出错时回 {"error": "…"}（HTTP 状态码在信封外面，这里看不到），当错误返回。
func meshCall(st *panelState, path, method string, payload map[string]any) (any, error) {
	raw, err := panelRPCRaw(st.Base, path, method, st.Token, payload)
	if err != nil {
		return nil, err
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("主控应答无法解析：%v", err)
	}
	if msg, _ := obj["error"].(string); msg != "" {
		return nil, errors.New(msg)
	}
	return obj, nil
}
