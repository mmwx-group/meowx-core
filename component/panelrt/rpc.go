package panelrt

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/panelsecure"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/ntp"
)

// 连主控一律直连：经内核的拨号器（绑物理网卡 / routing-mark / 安卓 protect，与内核自己的出站一致），不进 TUN、不经节点；
// 域名按直连的解析器解析，绝不碰 net.DefaultResolver（独立运行时它被换成了「调用即崩」的桩，见 main.go）。
// 证书按内核的根证书池校验（含内置的 CA 列表：路由器上常常没有系统证书）。
var dialPanel = func(ctx context.Context, network, addr string) (net.Conn, error) {
	return dialer.DialContext(ctx, network, addr, dialer.WithResolver(resolver.DirectHostResolver))
}

func dialPanelTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	conn, err := dialPanel(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, panelTLSConfig(host))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func panelTLSConfig(host string) *tls.Config {
	return &tls.Config{ServerName: host, RootCAs: ca.GetCertPool(), Time: ntp.Now, NextProtos: []string{"http/1.1"}}
}

var httpClient = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialPanel(ctx, network, addr)
		},
		DialTLSContext:      dialPanelTLS,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     30 * time.Second,
		MaxIdleConnsPerHost: 2,
	},
}

// 主控公钥缓存：每次连 WS / 发 RPC 都先验一遍证书没必要；1 小时内复用，解不开应答时作废重取。
const masterKeyTTL = time.Hour

type cachedKey struct {
	key *ecdh.PublicKey
	at  time.Time
}

var (
	keyMu    sync.Mutex
	keyCache = map[string]cachedKey{}
)

func masterKey(base string) (*ecdh.PublicKey, error) {
	keyMu.Lock()
	if c, ok := keyCache[base]; ok && time.Since(c.at) < masterKeyTTL {
		keyMu.Unlock()
		return c.key, nil
	}
	keyMu.Unlock()
	key, err := panelsecure.FetchMasterKey(httpClient, base)
	if err != nil {
		return nil, err
	}
	keyMu.Lock()
	keyCache[base] = cachedKey{key: key, at: time.Now()}
	keyMu.Unlock()
	return key, nil
}

func forgetMasterKey(base string) {
	keyMu.Lock()
	delete(keyCache, base)
	keyMu.Unlock()
}

// authFields 鉴权字段：已登录用 token（会话或用户 API token），没登录用订阅应答里拿到的只读凭证 rt。
func (c Channel) authFields(m map[string]any) {
	if c.Token != "" {
		m["token"] = c.Token
	} else if c.RT != "" {
		m["rt"] = c.RT
	}
}

func newNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// errNotFound 主控没有这个接口（旧主控）：安静地忽略。
var errNotFound = errors.New("主控没有这个接口")

// rpcGet 经加密 RPC 发一次 GET（主控把 path 映射到 /api + path），回解开的应答正文。HTTP 404 回 errNotFound，
// 其它非 2xx 回带状态码的错误（正文里有 error 就带上）。
func rpcGet(ctx context.Context, ch Channel, path string) ([]byte, error) {
	key, err := masterKey(ch.Base)
	if err != nil {
		return nil, err
	}
	inner := map[string]any{"path": path, "method": "GET", "ts": time.Now().Unix(), "nonce": newNonce()}
	ch.authFields(inner)
	plain, err := json.Marshal(inner)
	if err != nil {
		return nil, err
	}
	envelope, respKey, err := panelsecure.SealRPC(key, plain)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ch.Base+"/api/secure/rpc", bytes.NewReader(envelope))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("连不上主控：%s", describeErr(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, errNotFound
	}
	out, err := panelsecure.OpenRPC(respKey, body)
	if err != nil {
		forgetMasterKey(ch.Base)
		return nil, fmt.Errorf("主控应答无法解密（HTTP %d）", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var obj struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(out, &obj)
		if obj.Error != "" {
			return nil, fmt.Errorf("HTTP %d：%s", resp.StatusCode, obj.Error)
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return out, nil
}

// describeErr 只留原因：url.Error 会把完整地址印出来（地址本身不带凭证，但别让日志变长）。
func describeErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err.Error()
	}
	return err.Error()
}
