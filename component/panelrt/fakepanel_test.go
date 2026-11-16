package panelrt

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/panelsecure"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"golang.org/x/crypto/chacha20poly1305"
)

// fakePanel 测试用的假主控：照主控 internal/handler/app_secure.go 实现 /api/secure/cert、/api/secure/rpc 与加密 WS
// （首帧临时公钥 → 加密鉴权帧 → 鉴权不过直接关、不发任何帧 → 之后推加密帧、收客户端的保活与回执）。
type fakePanel struct {
	t      *testing.T
	srv    *httptest.Server
	base   string
	master *ecdh.PrivateKey

	mu          sync.Mutex
	tokens      map[string]bool // 认的 token / rt
	wsDisabled  bool            // WS 端点回 503（模拟连不上实时通道）
	entryState  any             // 拉取接口的应答；nil = 404（旧主控）
	subRevs     any
	onConnect   func(c *fakeWS) // 鉴权通过后推什么
	conns       []*fakeWS
	auths       []map[string]any
	uplink      []map[string]any // 客户端上行（ping / entry_ack）
	rpcAuths    []map[string]any
	connections int
}

func newFakePanel(t *testing.T) *fakePanel {
	t.Helper()
	licPub, licPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	master, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := panelsecure.LicenseKey
	panelsecure.LicenseKey = base64.StdEncoding.EncodeToString(licPub)
	p := &fakePanel{t: t, master: master, tokens: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/secure/cert", func(w http.ResponseWriter, r *http.Request) {
		pub := base64.StdEncoding.EncodeToString(master.PublicKey().Bytes())
		exp := time.Now().Add(time.Hour).Unix()
		sig := ed25519.Sign(licPriv, panelsecure.CertMessage(pub, "127.0.0.1", exp))
		_ = json.NewEncoder(w).Encode(panelsecure.Cert{MasterPub: pub, Domain: "127.0.0.1", ExpireUnix: exp, Sig: base64.StdEncoding.EncodeToString(sig)})
	})
	mux.HandleFunc("/api/secure/rpc", p.serveRPC)
	mux.HandleFunc("/api/secure/ws", p.serveWS)
	p.srv = httptest.NewServer(mux)
	p.base = p.srv.URL
	t.Cleanup(func() {
		p.srv.CloseClientConnections()
		p.srv.Close()
		panelsecure.LicenseKey = oldKey
	})
	return p
}

func (p *fakePanel) derive(ePub []byte, infoC2S, infoS2C string) (cipher.AEAD, cipher.AEAD, error) {
	pub, err := ecdh.X25519().NewPublicKey(ePub)
	if err != nil {
		return nil, nil, err
	}
	shared, err := p.master.ECDH(pub)
	if err != nil {
		return nil, nil, err
	}
	salt := append(append([]byte{}, ePub...), p.master.PublicKey().Bytes()...)
	c2s, _ := chacha20poly1305.New(panelsecure.HKDF(shared, salt, infoC2S))
	s2c, _ := chacha20poly1305.New(panelsecure.HKDF(shared, salt, infoS2C))
	return c2s, s2c, nil
}

func (p *fakePanel) serveRPC(w http.ResponseWriter, r *http.Request) {
	buf := make([]byte, 1<<16)
	n, _ := readFull(r, buf)
	env := buf[:n]
	if len(env) < 32+12+16 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	c2s, s2c, err := p.derive(env[:32], panelsecure.InfoRPCClientToServer, panelsecure.InfoRPCServerToClient)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	plain, err := c2s.Open(nil, env[32:44], env[44:], nil)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var inner map[string]any
	_ = json.Unmarshal(plain, &inner)
	p.mu.Lock()
	p.rpcAuths = append(p.rpcAuths, inner)
	ok := p.tokens[str(inner["token"])] || p.tokens[str(inner["rt"])]
	var resp any
	switch inner["path"] {
	case "/user/forward/entry-state":
		resp = p.entryState
	case "/user/subscription-revs":
		resp = p.subRevs
	}
	p.mu.Unlock()
	status := http.StatusOK
	switch {
	case resp == nil:
		status, resp = http.StatusNotFound, map[string]any{"error": "not found"}
	case !ok:
		status, resp = http.StatusUnauthorized, map[string]any{"error": "unauthorized"}
	}
	body, _ := json.Marshal(resp)
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	w.WriteHeader(status)
	_, _ = w.Write(s2c.Seal(nonce, nonce, body, nil))
}

func readFull(r *http.Request, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := r.Body.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// fakeWS 一条已鉴权的假连接。
type fakeWS struct {
	conn     net.Conn
	s2c      cipher.AEAD
	c2s      cipher.AEAD
	mu       sync.Mutex
	sendN    uint64
	recvHigh uint64
}

func ctrNonce(counter uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

func (c *fakeWS) send(v any) error {
	body, _ := json.Marshal(v)
	c.mu.Lock()
	defer c.mu.Unlock()
	header := make([]byte, 8)
	binary.BigEndian.PutUint64(header, c.sendN)
	frame := c.s2c.Seal(header, ctrNonce(c.sendN), body, nil)
	c.sendN++
	return wsutil.WriteServerMessage(c.conn, ws.OpBinary, frame)
}

func (c *fakeWS) open(frame []byte) ([]byte, error) {
	if len(frame) < 24 {
		return nil, errors.New("short")
	}
	counter := binary.BigEndian.Uint64(frame[:8])
	if counter+1 <= c.recvHigh {
		return nil, errors.New("replay")
	}
	plain, err := c.c2s.Open(nil, ctrNonce(counter), frame[8:], nil)
	if err != nil {
		return nil, err
	}
	c.recvHigh = counter + 1
	return plain, nil
}

func (c *fakeWS) close() { _ = c.conn.Close() }

func (p *fakePanel) serveWS(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	disabled := p.wsDisabled
	p.mu.Unlock()
	if disabled {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	conn, _, _, err := ws.UpgradeHTTP(r, w)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	ePub, _, err := wsutil.ReadClientData(conn)
	if err != nil || len(ePub) != 32 {
		return
	}
	c2s, s2c, err := p.derive(ePub, panelsecure.InfoWSClientToServer, panelsecure.InfoWSServerToClient)
	if err != nil {
		return
	}
	c := &fakeWS{conn: conn, c2s: c2s, s2c: s2c}
	frame, _, err := wsutil.ReadClientData(conn)
	if err != nil {
		return
	}
	plain, err := c.open(frame)
	if err != nil {
		return
	}
	var auth map[string]any
	_ = json.Unmarshal(plain, &auth)
	p.mu.Lock()
	p.auths = append(p.auths, auth)
	ok := p.tokens[str(auth["token"])] || p.tokens[str(auth["rt"])]
	if !ok {
		p.mu.Unlock()
		return // 同主控：鉴权不过直接关，不发任何帧
	}
	p.connections++
	p.conns = append(p.conns, c)
	onConnect := p.onConnect
	p.mu.Unlock()
	if onConnect != nil {
		go onConnect(c)
	}
	_ = conn.SetReadDeadline(time.Time{})
	for {
		frame, _, err := wsutil.ReadClientData(conn)
		if err != nil {
			return
		}
		plain, err := c.open(frame)
		if err != nil {
			return
		}
		var m map[string]any
		_ = json.Unmarshal(plain, &m)
		p.mu.Lock()
		p.uplink = append(p.uplink, m)
		p.mu.Unlock()
	}
}

func (p *fakePanel) snapshot() (auths, uplink, rpcAuths []map[string]any, connections int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]map[string]any(nil), p.auths...), append([]map[string]any(nil), p.uplink...),
		append([]map[string]any(nil), p.rpcAuths...), p.connections
}

// waitFor 轮询直到 cond 成立（至多 d）。
func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
