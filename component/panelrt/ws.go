package panelrt

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

// wsConn 实时通道用的最小 WS 客户端（gobwas/ws）：二进制帧收发，主控的 ping 回 pong。
// 写只有一把锁、一帧一次 Write，保活协程、回执与 pong 不会交错写坏帧。
type wsConn struct {
	conn net.Conn
	rd   *wsutil.Reader
	mu   sync.Mutex
}

const wsMaxFrame = 1 << 20 // 同主控 appWSMaxFrame

// wsURL 主控地址（http / https）→ /api/secure/ws 的 ws / wss 地址。
func wsURL(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", errors.New("主控地址必须是 http / https")
	}
	u.Path = "/api/secure/ws"
	u.RawQuery = ""
	return u.String(), nil
}

func dialWS(ctx context.Context, base string) (*wsConn, error) {
	target, err := wsURL(base)
	if err != nil {
		return nil, err
	}
	d := ws.Dialer{
		Timeout: timing.handshakeTimeout,
		NetDial: dialPanel,
		TLSClient: func(conn net.Conn, hostname string) net.Conn {
			return tls.Client(conn, panelTLSConfig(hostname))
		},
		Header: ws.HandshakeHeaderHTTP{"User-Agent": []string{"MeowX"}},
	}
	conn, br, _, err := d.Dial(ctx, target)
	if err != nil {
		return nil, err
	}
	var src io.Reader = conn
	if br != nil {
		src = br // 握手应答后面可能已经读进来一截帧
	}
	c := &wsConn{conn: conn}
	c.rd = &wsutil.Reader{Source: src, State: ws.StateClientSide, MaxFrameSize: wsMaxFrame, OnIntermediate: c.control}
	return c, nil
}

func (c *wsConn) writeFrame(f ws.Frame) error {
	f = ws.MaskFrameInPlace(f)
	bts, err := ws.CompileFrame(f)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = c.conn.Write(bts)
	return err
}

// writeBinary 发一个二进制帧（p 会被就地加掩码，调用方别再用它）。
func (c *wsConn) writeBinary(p []byte) error {
	return c.writeFrame(ws.NewBinaryFrame(p))
}

// control 处理控制帧：ping 回 pong，close 结束读。
func (c *wsConn) control(h ws.Header, r io.Reader) error {
	switch h.OpCode {
	case ws.OpPing:
		payload, err := io.ReadAll(io.LimitReader(r, 125))
		if err != nil {
			return err
		}
		return c.writeFrame(ws.NewPongFrame(payload))
	case ws.OpPong:
		_, err := io.Copy(io.Discard, r)
		return err
	case ws.OpClose:
		_, _ = io.Copy(io.Discard, r)
		_ = c.writeFrame(ws.NewCloseFrame(ws.NewCloseFrameBody(ws.StatusNormalClosure, "")))
		return io.EOF
	}
	return nil
}

// readMessage 读下一条数据消息（二进制或文本），期间的控制帧就地处理。每收到一帧都把读超时往后推。
func (c *wsConn) readMessage() ([]byte, error) {
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(timing.readTimeout))
		hdr, err := c.rd.NextFrame()
		if err != nil {
			return nil, err
		}
		if hdr.OpCode.IsControl() {
			if err := c.control(hdr, c.rd); err != nil {
				return nil, err
			}
			continue
		}
		if hdr.OpCode&(ws.OpBinary|ws.OpText) == 0 {
			if err := c.rd.Discard(); err != nil {
				return nil, err
			}
			continue
		}
		return io.ReadAll(io.LimitReader(c.rd, wsMaxFrame))
	}
}

func (c *wsConn) close() {
	_ = c.conn.Close()
}
