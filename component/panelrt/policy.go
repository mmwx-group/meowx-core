package panelrt

import (
	"math/rand"
	"time"
)

// 节奏（照 MeowX RealtimeClient，单测里调小）：
//   - 重连退避 5s 起倍增、封顶 5 分钟；一条连接活过 60s 算稳定，退避归零（主控空闲窗 70s，活过 60s 说明鉴权与链路都正常）。
//   - 鉴权失败长这样：WS 握手成功、鉴权帧发出后主控立刻关（token 不认就直接 return，不发任何帧）。存活 < 2s 且**连续** 3 次
//     才算（单次可能只是主控正好重启），之后每 30 分钟试一次（主控滚动重启、每用户连接数满了这些几分钟就会自愈；
//     token 真失效时外壳重新登录会换配置）。只有一次稳定连接能清掉这个状态。
//   - 换网叫醒：与上一次尝试至少隔 15s，再加 1–3s 抖动（同一网络下很多台一起恢复时别一起砸向主控）。
//   - 加密保活帧 60s 一次（主控读超时 70s）；主控每 30s 发一次 WS ping，150s 什么都没收到就当链路已死。
//   - 实时通道连不上期间每 5 分钟经加密 RPC 拉一次入口与订阅状态。
type timingConfig struct {
	initialBackoff     time.Duration
	maxBackoff         time.Duration
	stableAfter        time.Duration
	authFailureWindow  time.Duration
	authFailureStrikes int
	authFailureBackoff time.Duration
	kickMinInterval    time.Duration
	resumeJitterMin    time.Duration
	resumeJitterMax    time.Duration
	pingInterval       time.Duration
	readTimeout        time.Duration
	handshakeTimeout   time.Duration
	pullInterval       time.Duration
	subJitterMax       time.Duration // 订阅变更通知前随机等 0–10s
	subMinInterval     time.Duration // 同一份订阅 30s 内至多通知一次
}

var timing = timingConfig{
	initialBackoff:     5 * time.Second,
	maxBackoff:         300 * time.Second,
	stableAfter:        60 * time.Second,
	authFailureWindow:  2 * time.Second,
	authFailureStrikes: 3,
	authFailureBackoff: 30 * time.Minute,
	kickMinInterval:    15 * time.Second,
	resumeJitterMin:    time.Second,
	resumeJitterMax:    3 * time.Second,
	pingInterval:       60 * time.Second,
	readTimeout:        150 * time.Second,
	handshakeTimeout:   15 * time.Second,
	pullInterval:       5 * time.Minute,
	subJitterMax:       10 * time.Second,
	subMinInterval:     30 * time.Second,
}

// reconnectPolicy 重连节奏（纯值类型，同 MeowX ReconnectPolicy）。
type reconnectPolicy struct {
	backoff    time.Duration
	shortLived int  // 连续「握手成功却秒关」的次数
	authFailed bool // 疑似鉴权失败
}

func newReconnectPolicy() reconnectPolicy {
	return reconnectPolicy{backoff: timing.initialBackoff}
}

// connectionEnded 一次连接结束，回下次重连前等多久。handshook = WS 升级成功且两帧都发出去了；lived = 从那时到断开的时长。
// 只有握手成功的连接参与鉴权判定：连不上（网络问题）走普通退避，且打断「连续」计数。
func (p *reconnectPolicy) connectionEnded(handshook bool, lived time.Duration) time.Duration {
	if handshook && lived >= timing.stableAfter {
		p.backoff = timing.initialBackoff
		p.shortLived = 0
		p.authFailed = false
		return p.backoff
	}
	if handshook && lived < timing.authFailureWindow {
		p.shortLived++
		if p.authFailed || p.shortLived >= timing.authFailureStrikes {
			p.authFailed = true
			p.shortLived = 0
			return timing.authFailureBackoff
		}
	} else {
		p.shortLived = 0
	}
	delay := p.backoff
	p.backoff *= 2
	if p.backoff > timing.maxBackoff {
		p.backoff = timing.maxBackoff
	}
	return delay
}

// resumeDelay 被叫醒后到真正重连要等多久：正常是 1–3s 抖动；距上次尝试不足 kickMinInterval 时补足到它。
func resumeDelay(sinceLastAttempt time.Duration, haveLast bool) time.Duration {
	jitter := timing.resumeJitterMin
	if span := timing.resumeJitterMax - timing.resumeJitterMin; span > 0 {
		jitter += time.Duration(rand.Int63n(int64(span)))
	}
	if !haveLast {
		return jitter
	}
	if rest := timing.kickMinInterval - sinceLastAttempt; rest > jitter {
		return rest
	}
	return jitter
}

func randomJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(max) + 1))
}
