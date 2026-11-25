package main

// 喵窝 status / devices 整理与出错提示的单元测试。跑法同 meowx_panel_test.go：
// go test -c -tags with_gvisor -o meowx.test . && ./meowx.test -test.run Mesh

import (
	"encoding/json"
	"testing"
)

func meshJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMeshStatusScope(t *testing.T) {
	cases := []struct {
		in       string
		scope    string
		inList   bool
		limit    int
		nServers int
	}{
		{`{"available":true,"access_scope":"servers","device_limit":5}`, "servers", true, 5, 0},
		{`{"available":true,"access_scope":"sites","device_limit":0}`, "sites", true, 0, 0},
		{`{"available":true,"access_scope":"full","joined_admin":"admin"}`, "full", true, 0, 0},
		// 旧主控没有 access_scope；写了不认识的值也不输出
		{`{"available":true}`, "", true, 0, 0},
		{`{"available":true,"access_scope":"weird"}`, "", true, 0, 0},
		// 不在名单 / 关了 / 启动中
		{`{"available":false,"reason":"not_admin","message":"x"}`, "", false, 0, 0},
		{`{"available":false,"reason":"disabled"}`, "", true, 0, 0},
		{`{"available":false,"reason":"starting","access_scope":"servers"}`, "servers", true, 0, 0},
		{`{}`, "", false, 0, 0},
		// 预留的 servers：缺名称或喵窝地址的丢掉
		{`{"available":true,"servers":[{"name":"东京","mesh_ip":"100.64.0.21","server_id":3},{"name":"","mesh_ip":"100.64.0.22"},{"name":"x"},"bad",null]}`, "", true, 0, 1},
		{`{"available":true,"servers":null}`, "", true, 0, 0},
	}
	for _, c := range cases {
		out := normalizeMeshStatus(meshJSON(t, c.in))
		scope, _ := out["access_scope"].(string)
		if scope != c.scope {
			t.Errorf("%s: scope = %q, want %q", c.in, scope, c.scope)
		}
		if in, _ := out["in_list"].(bool); in != c.inList {
			t.Errorf("%s: in_list = %v, want %v", c.in, in, c.inList)
		}
		if n, _ := out["device_limit"].(int); n != c.limit {
			t.Errorf("%s: device_limit = %v, want %d", c.in, out["device_limit"], c.limit)
		}
		servers, _ := out["servers"].([]any)
		if len(servers) != c.nServers {
			t.Errorf("%s: servers = %v, want %d", c.in, out["servers"], c.nServers)
		}
		if c.nServers == 0 {
			if _, ok := out["servers"]; ok {
				t.Errorf("%s: 没有可用的服务器时不该输出 servers", c.in)
			}
		}
	}
	out := normalizeMeshStatus(meshJSON(t, `{"available":true,"servers":[{"name":" 东京 ","mesh_ip":"100.64.0.21","server_id":3}]}`))
	s := out["servers"].([]any)[0].(map[string]any)
	if s["name"] != "东京" || s["mesh_ip"] != "100.64.0.21" || s["server_id"] != float64(3) {
		t.Errorf("servers[0] = %v", s)
	}
	// 其余字段原样保留
	out = normalizeMeshStatus(meshJSON(t, `{"available":true,"control_url":"https://p","joined_admin":"admin","access_scope":"full"}`))
	if out["control_url"] != "https://p" || out["joined_admin"] != "admin" {
		t.Errorf("字段丢了：%v", out)
	}
}

func TestMeshDevicesShared(t *testing.T) {
	out := normalizeMeshDevices(meshJSON(t, `{"devices":[{"id":1,"name":"me","ipv4":"100.64.0.2","routes":null,"pending_routes":null}],"sites":null}`))
	devs := out["devices"].([]any)
	if len(devs) != 1 {
		t.Fatalf("devices = %v", devs)
	}
	d := devs[0].(map[string]any)
	if r, ok := d["routes"].([]any); !ok || len(r) != 0 {
		t.Errorf("null routes 应当是空列表：%v", d["routes"])
	}
	if r, ok := d["pending_routes"].([]any); !ok || len(r) != 0 {
		t.Errorf("null pending_routes 应当是空列表：%v", d["pending_routes"])
	}
	if _, ok := d["kind"]; ok {
		t.Errorf("自己的设备不标 kind：%v", d)
	}
	if s, ok := out["sites"].([]any); !ok || len(s) != 0 {
		t.Errorf("sites = %v", out["sites"])
	}
	// 缺 shared_devices = 空列表
	if s, ok := out["shared_devices"].([]any); !ok || len(s) != 0 {
		t.Errorf("shared_devices = %v", out["shared_devices"])
	}

	// sites 范围：站点路由器只有网段
	out = normalizeMeshDevices(meshJSON(t, `{"devices":[],"sites":[],"shared_devices":[
		{"id":7,"name":"router","ipv4":"","dns_name":"","username":"admin","routes":["192.168.1.0/24"],"pending_routes":null},
		{"id":8,"name":"phone","ipv4":"100.64.0.9","dns_name":"phone.mesh","username":"admin","routes":null},
		{"id":9,"name":"empty","ipv4":"","dns_name":"","routes":null},
		"bad"]}`))
	shared := out["shared_devices"].([]any)
	if len(shared) != 2 {
		t.Fatalf("shared = %v", shared)
	}
	site := shared[0].(map[string]any)
	if site["kind"] != "site" || site["username"] != "admin" || len(site["routes"].([]any)) != 1 {
		t.Errorf("site = %v", site)
	}
	dev := shared[1].(map[string]any)
	if dev["kind"] != "device" || len(dev["routes"].([]any)) != 0 {
		t.Errorf("device = %v", dev)
	}
	// 服务未就绪时的 error 原样带出
	out = normalizeMeshDevices(meshJSON(t, `{"devices":[],"sites":[{"id":1,"original":"192.168.1.0/24"}],"error":"喵窝正在启动"}`))
	if out["error"] != "喵窝正在启动" || len(out["sites"].([]any)) != 1 {
		t.Errorf("out = %v", out)
	}
}

func TestMeshErrorText(t *testing.T) {
	disabled := func() map[string]any { return map[string]any{"reason": "disabled"} }
	full := func() map[string]any { return map[string]any{"available": true, "device_limit": float64(5)} }
	cases := []struct {
		code   int
		msg    string
		status func() map[string]any
		want   string
	}{
		{401, "unauthorized", nil, "登录已失效，请重新登录主控账户"},
		{403, "forbidden", nil, "这个账号不能用喵窝了（可能已被移出喵窝名单）"},
		{409, "conflict", disabled, "主控已关闭喵窝"},
		{409, "conflict", full, "设备数已达上限（5 台）"},
		{409, "conflict", nil, "设备数已达上限"},
		{429, "", nil, "主控忙，请稍后再试"},
		{503, "", nil, "主控忙，请稍后再试"},
		{502, "headscale: dial", nil, "主控暂时连不上组网服务，请稍后再试（本机的喵窝身份不受影响）"},
		{400, "名称不合法", nil, "名称不合法"},
		{404, "", nil, "主控回 HTTP 404"},
	}
	for _, c := range cases {
		if got := meshErrorText(c.code, c.msg, c.status); got != c.want {
			t.Errorf("%d %q: %q, want %q", c.code, c.msg, got, c.want)
		}
	}
	var he interface{ HTTPStatus() int } = &meshError{status: 409, msg: "x"}
	if he.HTTPStatus() != 409 {
		t.Error("HTTPStatus")
	}
}
