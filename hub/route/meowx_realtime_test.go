package route

import (
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/panelrt"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

// 跑法：go test -tags with_gvisor ./hub/route/
func TestMeowxRealtimeRoutes(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	defer panelrt.Stop()
	rt, entries := meowxRealtimeRouter(), meowxEntriesRouter()
	do := func(h http.Handler, method, body string) (int, string) {
		req := httptest.NewRequest(method, "/", strings.NewReader(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		data, _ := io.ReadAll(w.Result().Body)
		return w.Code, string(data)
	}

	if code, body := do(rt, "PUT", `{"base":"ftp://x","token":"t"}`); code != http.StatusBadRequest || !strings.Contains(body, "message") {
		t.Fatalf("bad base: %d %s", code, body)
	}
	if code, body := do(rt, "PUT", `{not json`); code != http.StatusBadRequest {
		t.Fatalf("bad json: %d %s", code, body)
	}
	// 连不上的主控也能配上（后台退避重连），状态里不带凭证
	code, body := do(rt, "PUT", `{"channels":[{"base":"http://127.0.0.1:1","rt":"secret-rt"}],"hook":{"exec":["/etc/init.d/meowx","subscription_changed"]}}`)
	if code != http.StatusOK || strings.Contains(body, "secret-rt") {
		t.Fatalf("put: %d %s", code, body)
	}
	var st panelrt.StatusInfo
	if err := json.Unmarshal([]byte(body), &st); err != nil || len(st.Channels) != 1 || st.Channels[0].Auth != "rt" ||
		st.Hook == nil || len(st.Hook.Exec) != 2 {
		t.Fatalf("status = %s", body)
	}
	if code, body := do(rt, "GET", ""); code != http.StatusOK || !strings.Contains(body, `"base":"http://127.0.0.1:1"`) {
		t.Fatalf("get: %d %s", code, body)
	}
	if code, _ := do(rt, "DELETE", ""); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if code, body := do(rt, "GET", ""); code != http.StatusOK || !strings.Contains(body, `"channels":[]`) {
		t.Fatalf("get after delete: %d %s", code, body)
	}
	if code, body := do(entries, "GET", ""); code != http.StatusOK || !strings.Contains(body, `"entries":[]`) {
		t.Fatalf("entries: %d %s", code, body)
	}
	if code, body := do(entries, "DELETE", ""); code != http.StatusOK || !strings.Contains(body, `"cleared":0`) {
		t.Fatalf("clear entries: %d %s", code, body)
	}
}
