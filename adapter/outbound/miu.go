package outbound

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/once"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/miu"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/tls"
)

type Miu struct {
	*Base
	client    *miu.Client
	option    *MiuOption
	tlsConfig *vmess.TLSConfig
}

type MiuOption struct {
	BasicOption
	Name                     string         `proxy:"name"`
	Server                   string         `proxy:"server"`
	Port                     int            `proxy:"port"`
	PSK                      string         `proxy:"psk"`
	PaddingScheme            []string       `proxy:"padding-scheme,omitempty"` // 显式初始方案（按行）；空=按 PSK 派生
	ALPN                     []string       `proxy:"alpn,omitempty"`
	SNI                      string         `proxy:"sni,omitempty"`
	ServerName               string         `proxy:"servername,omitempty"`
	ECHOpts                  ECHOptions     `proxy:"ech-opts,omitempty"`
	RealityOpts              RealityOptions `proxy:"reality-opts,omitempty"`
	ClientFingerprint        string         `proxy:"client-fingerprint,omitempty"`
	SkipCertVerify           bool           `proxy:"skip-cert-verify,omitempty"`
	NameCertVerify           string         `proxy:"name-cert-verify,omitempty"`
	Fingerprint              string         `proxy:"fingerprint,omitempty"`
	Certificate              string         `proxy:"certificate,omitempty"`
	PrivateKey               string         `proxy:"private-key,omitempty"`
	UDP                      bool           `proxy:"udp,omitempty"`
	Vision                   bool           `proxy:"vision,omitempty"`      // 兼容字段，Miu 第二版不用
	RecvWindow               int            `proxy:"recv-window,omitempty"` // 兼容字段，Miu 第二版不用
	ClientMetadata           string         `proxy:"client-metadata,omitempty"`
	IdleSessionCheckInterval int            `proxy:"idle-session-check-interval,omitempty"` // 兼容字段
	IdleSessionTimeout       int            `proxy:"idle-session-timeout,omitempty"`
	MinIdleSession           int            `proxy:"min-idle-session,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (m *Miu) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	// 目标原样发给服务端：域名在服务端解析。
	c, err := m.client.DialContext(ctx, "tcp", metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	return NewConn(c, m), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (m *Miu) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := m.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	// 一条 UoT 流，独占一条通道，首个数据包写出时开。
	pc, err := m.client.ListenPacket()
	if err != nil {
		return nil, err
	}
	return NewPacketConn(pc, m), nil
}

// SupportUOT implements C.ProxyAdapter
func (m *Miu) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (m *Miu) ProxyInfo() C.ProxyInfo {
	info := m.Base.ProxyInfo()
	info.DialerProxy = m.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter
func (m *Miu) Close() error {
	return m.client.Close()
}

// dialLane 开一条通道的外层连接：经代理拨号器 TCP，再 TLS / uTLS / REALITY。TLS 连接原样返回、不加任何包装，
// miu 库要伸进去取裸段。
func (m *Miu) dialLane(ctx context.Context) (net.Conn, error) {
	conn, err := m.dialer.DialContext(ctx, "tcp", m.addr)
	if err != nil {
		return nil, err
	}
	tlsConn, err := vmess.StreamTLSConn(ctx, conn, m.tlsConfig)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// miuRawUsable 一次性自检：裸段在 vmess.StreamTLSConn 这里能返回的两种 TLS 连接上都能用——metacubex/tls 的
// *tls.Conn 和 metacubex/utls 的 *utls.UConn（REALITY 握手也产出后者）。
var miuRawUsable = once.OnceValue(func() bool {
	err := miu.SelfTest(func(conn net.Conn, cfg *stdtls.Config) net.Conn {
		return tls.Client(conn, &tls.Config{ServerName: cfg.ServerName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	})
	if err == nil {
		err = miu.SelfTest(func(conn net.Conn, cfg *stdtls.Config) net.Conn {
			chrome, _ := tlsC.GetFingerprint("chrome")
			return tlsC.UClient(conn, &tlsC.Config{ServerName: cfg.ServerName, InsecureSkipVerify: true, MinVersion: tlsC.VersionTLS13}, chrome)
		})
	}
	if err != nil {
		log.Warnln("Miu: raw segments are not usable with this build, continuing without them: %v", err)
		return false
	}
	return true
})

func NewMiu(option MiuOption) (*Miu, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &Miu{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Miu,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())

	echConfig, err := option.ECHOpts.Parse()
	if err != nil {
		return nil, err
	}
	realityConfig, err := option.RealityOpts.Parse()
	if err != nil {
		return nil, err
	}
	if realityConfig != nil && option.ClientFingerprint == "" {
		return nil, errors.New("REALITY is based on uTLS, please set a client-fingerprint")
	}
	sni := option.SNI
	if sni == "" {
		sni = option.ServerName
	}
	if sni == "" {
		sni = option.Server
	}
	outbound.tlsConfig = &vmess.TLSConfig{
		Host:              sni,
		SkipCertVerify:    option.SkipCertVerify,
		NameCertVerify:    option.NameCertVerify,
		NextProtos:        option.ALPN,
		FingerPrint:       option.Fingerprint,
		Certificate:       option.Certificate,
		PrivateKey:        option.PrivateKey,
		ClientFingerprint: option.ClientFingerprint,
		ECH:               echConfig,
		Reality:           realityConfig,
	}

	outbound.client, err = miu.NewClient(miu.ClientConfig{
		PSK:           option.PSK,
		Dial:          outbound.dialLane,
		LaneIdle:      time.Duration(option.IdleSessionTimeout) * time.Second,
		MinIdle:       option.MinIdleSession,
		DisableRaw:    !miuRawUsable(),
		PaddingScheme: strings.Join(option.PaddingScheme, "\n"),
	})
	if err != nil {
		return nil, err
	}
	return outbound, nil
}
