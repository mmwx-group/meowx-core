package panelrt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/entryoverride"
	"github.com/metacubex/mihomo/component/panelsecure"
	"github.com/metacubex/mihomo/log"
)

// channel 一条实时通道：一个主控 + 一份凭证（token 或 rt）。一个协程连 WS、断了按退避重连（照 MeowX RealtimeClient），
// 另一个协程在 WS 连不上期间经加密 RPC 拉入口与订阅状态。
type channel struct {
	cfg   Channel
	id    string
	scope string

	ctx      context.Context
	cancel   context.CancelFunc
	kickCh   chan struct{}
	pullKick chan struct{}
	done     chan struct{}

	mu          sync.Mutex
	state       string
	conn        *wsConn
	attempts    int
	lastAttempt time.Time
	connectedAt time.Time
	nextRetryAt time.Time
	lastEvent   string
	lastEventAt time.Time
	lastError   string
	lastErrorAt time.Time
	lastPullAt  time.Time
	authFailed  bool
}

const (
	stateConnecting = "connecting"
	stateConnected  = "connected"
	stateBackoff    = "backoff"
	stateStopped    = "stopped"
)

func newChannel(cfg Channel) *channel {
	ctx, cancel := context.WithCancel(context.Background())
	return &channel{cfg: cfg, id: cfg.id(), scope: cfg.scope(), ctx: ctx, cancel: cancel,
		kickCh: make(chan struct{}, 1), pullKick: make(chan struct{}, 1), done: make(chan struct{}), state: stateConnecting}
}

func (c *channel) start() {
	go c.run()
	go c.pullLoop()
}

func (c *channel) stop() {
	c.cancel()
	c.mu.Lock()
	c.state = stateStopped
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		conn.close()
	}
}

// kick 换网了：正在退避就提前重连（与上次尝试至少隔 15s）；连不上期间顺带拉一次状态。连着的不动。
func (c *channel) kick() {
	c.mu.Lock()
	connected := c.state == stateConnected
	c.mu.Unlock()
	if connected {
		return
	}
	select {
	case c.kickCh <- struct{}{}:
	default:
	}
	select {
	case c.pullKick <- struct{}{}:
	default:
	}
}

func (c *channel) noteEvent(kind string) {
	c.mu.Lock()
	c.lastEvent, c.lastEventAt = kind, time.Now()
	c.mu.Unlock()
}

func (c *channel) noteError(err error) {
	c.mu.Lock()
	c.lastError, c.lastErrorAt = err.Error(), time.Now()
	c.mu.Unlock()
}

func (c *channel) host() string { return hostOf(c.cfg.Base) }

func (c *channel) run() {
	defer close(c.done)
	policy := newReconnectPolicy()
	kicked := false
	for c.ctx.Err() == nil {
		if kicked {
			kicked = false
			c.mu.Lock()
			last := c.lastAttempt
			c.mu.Unlock()
			d := resumeDelay(time.Since(last), !last.IsZero())
			c.setBackoff(d)
			if !c.sleep(d, nil) {
				return
			}
		}
		c.mu.Lock()
		c.attempts++
		c.lastAttempt = time.Now()
		c.state = stateConnecting
		c.nextRetryAt = time.Time{}
		c.mu.Unlock()

		handshook, lived, err := c.connectOnce()
		if c.ctx.Err() != nil {
			return
		}
		wasAuthFailed := policy.authFailed
		delay := policy.connectionEnded(handshook, lived)
		c.mu.Lock()
		c.authFailed = policy.authFailed
		c.connectedAt = time.Time{}
		c.mu.Unlock()
		switch {
		case policy.authFailed && !wasAuthFailed:
			err = fmt.Errorf("连续 %d 次在鉴权后被主控关闭，疑似凭证失效，改为每 %d 分钟重试一次", timing.authFailureStrikes, int(timing.authFailureBackoff/time.Minute))
			log.Warnln("[MeowX] 实时通道 %s：%s", c.host(), err)
		case handshook:
			if err == nil {
				err = errors.New("连接已断开")
			}
			log.Infoln("[MeowX] 实时通道 %s：连接断开（存活 %s：%s），%s 后重连", c.host(), roundDuration(lived), err, delay)
		case err != nil:
			log.Infoln("[MeowX] 实时通道 %s：连接失败（%s），%s 后重试", c.host(), err, delay)
		}
		if err != nil {
			c.noteError(err)
		}
		c.setBackoff(delay)
		if !c.sleep(delay, &kicked) {
			return
		}
	}
}

func (c *channel) setBackoff(d time.Duration) {
	c.mu.Lock()
	if c.state != stateStopped {
		c.state = stateBackoff
		c.nextRetryAt = time.Now().Add(d)
	}
	c.mu.Unlock()
}

// sleep 等 d；kicked 不为空时可被叫醒（置 *kicked）。停掉回 false。
func (c *channel) sleep(d time.Duration, kicked *bool) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	var kick chan struct{}
	if kicked != nil {
		kick = c.kickCh
	}
	select {
	case <-c.ctx.Done():
		return false
	case <-t.C:
		return true
	case <-kick:
		*kicked = true
		return true
	}
}

// connectOnce 连一次：取证书验签 → WS 握手 → 首帧临时公钥 → 加密鉴权帧 → 收消息直到断开。
// handshook = WS 升级成功、两帧都发出去了；lived = 从那时到断开的时长（鉴权失败时主控会立刻关）。
func (c *channel) connectOnce() (handshook bool, lived time.Duration, err error) {
	key, err := masterKey(c.cfg.Base)
	if err != nil {
		return false, 0, err
	}
	sess, err := panelsecure.NewSession(key)
	if err != nil {
		return false, 0, err
	}
	dialCtx, cancel := context.WithTimeout(c.ctx, timing.handshakeTimeout)
	conn, err := dialWS(dialCtx, c.cfg.Base)
	cancel()
	if err != nil {
		return false, 0, fmt.Errorf("连不上主控：%s", describeErr(err))
	}
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		conn.close()
		return false, 0, c.ctx.Err()
	}
	c.conn = conn
	c.mu.Unlock()
	defer func() {
		conn.close()
		c.mu.Lock()
		c.conn = nil
		c.mu.Unlock()
	}()

	if err := conn.writeBinary(sess.ClientHello()); err != nil {
		return false, 0, err
	}
	auth := map[string]any{"ts": time.Now().Unix(), "nonce": newNonce(), "caps": []string{"entry_v2", "sub_v2", "ack"}}
	c.cfg.authFields(auth)
	plain, _ := json.Marshal(auth)
	if err := conn.writeBinary(sess.Seal(plain)); err != nil {
		return false, 0, err
	}
	opened := time.Now()
	c.mu.Lock()
	c.state, c.connectedAt = stateConnected, opened
	c.mu.Unlock()

	stopPing := make(chan struct{})
	defer close(stopPing)
	go c.keepalive(conn, sess, opened, stopPing)

	for {
		frame, err := conn.readMessage()
		if err != nil {
			return true, time.Since(opened), err
		}
		body, err := sess.Open(frame)
		if err != nil {
			continue // 解不开（不该发生）：丢掉这一帧，计数器没动
		}
		var m message
		if json.Unmarshal(body, &m) != nil {
			continue
		}
		for _, a := range c.handleMessage(&m, "", time.Now()) {
			ackBody, _ := json.Marshal(map[string]any{"type": "entry_ack", "chainId": a.ChainID, "rev": a.Rev})
			_ = conn.writeBinary(sess.Seal(ackBody))
		}
	}
}

// keepalive 每 60s 一个加密的 {"type":"ping"}（主控读超时 70s）；发不出去 = 链路已死，关掉连接让读循环结束。
// 连接活过鉴权判定窗口再记一行「已连接」（鉴权失败时主控秒关，不刷屏）。
func (c *channel) keepalive(conn *wsConn, sess *panelsecure.Session, opened time.Time, stop chan struct{}) {
	announce := time.NewTimer(timing.authFailureWindow)
	defer announce.Stop()
	ticker := time.NewTicker(timing.pingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-announce.C:
			log.Infoln("[MeowX] 实时通道 %s：已连接", c.host())
		case <-ticker.C:
			if err := conn.writeBinary(sess.Seal([]byte(`{"type":"ping"}`))); err != nil {
				conn.close()
				return
			}
		}
	}
}

// pullLoop 拉取接口（规格 §5）：通道启动时拉一次；WS 连不上期间每 5 分钟、换网时各拉一次。
func (c *channel) pullLoop() {
	c.pull()
	t := time.NewTimer(timing.pullInterval)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.pullKick:
			c.mu.Lock()
			due := c.state != stateConnected && time.Since(c.lastPullAt) >= timing.kickMinInterval
			c.mu.Unlock()
			if due {
				c.pull()
			}
		case <-t.C:
			c.mu.Lock()
			connected := c.state == stateConnected
			c.mu.Unlock()
			if !connected {
				c.pull()
			}
			t.Reset(timing.pullInterval)
		}
	}
}

// pull 经加密 RPC 拉入口状态与订阅 rev。旧主控没有这两个接口（404）时安静地跳过。
func (c *channel) pull() {
	start := time.Now()
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()
	if body, err := rpcGet(ctx, c.cfg, "/user/forward/entry-state"); err == nil {
		var st struct {
			Ready   *bool           `json:"ready"`
			Entries []snapshotEntry `json:"entries"`
		}
		if json.Unmarshal(body, &st) == nil && (st.Ready != nil || st.Entries != nil) {
			c.noteEvent("entry_state")
			c.applySnapshot(st.Ready != nil && *st.Ready, st.Entries, entryoverride.OriginPull, start)
		}
	} else if !errors.Is(err, errNotFound) && c.ctx.Err() == nil {
		log.Debugln("[MeowX] 实时通道 %s：拉入口状态失败（%s）", c.host(), err)
	}
	if body, err := rpcGet(ctx, c.cfg, "/user/subscription-revs"); err == nil {
		var st struct {
			Subs []rawSubRev `json:"subs"`
		}
		if json.Unmarshal(body, &st) == nil && st.Subs != nil {
			c.noteEvent("subscription_revs")
			c.applySubSnapshot(st.Subs)
		}
	} else if !errors.Is(err, errNotFound) && c.ctx.Err() == nil {
		log.Debugln("[MeowX] 实时通道 %s：拉订阅 rev 失败（%s）", c.host(), err)
	}
	c.mu.Lock()
	c.lastPullAt = time.Now()
	c.mu.Unlock()
}

func roundDuration(d time.Duration) time.Duration {
	if d < time.Minute {
		return d.Round(100 * time.Millisecond)
	}
	return d.Truncate(time.Second)
}
