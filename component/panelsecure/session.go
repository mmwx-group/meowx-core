package panelsecure

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// Session 实时通道的会话加密（同客户端 SecureSession）。并发安全。
type Session struct {
	hello            []byte
	aeadC2S, aeadS2C cipher.AEAD

	mu        sync.Mutex
	sendCount uint64
	recvCount uint64 // 下一帧的计数至少要这么大
}

// NewSession 新开一条会话：一把新的临时密钥，计数归零。
func NewSession(masterPub *ecdh.PublicKey) (*Session, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(masterPub)
	if err != nil {
		return nil, err
	}
	ePub := eph.PublicKey().Bytes()
	salt := append(append([]byte{}, ePub...), masterPub.Bytes()...)
	s := &Session{hello: ePub}
	if s.aeadC2S, err = chacha20poly1305.New(HKDF(shared, salt, InfoWSClientToServer)); err != nil {
		return nil, err
	}
	if s.aeadS2C, err = chacha20poly1305.New(HKDF(shared, salt, InfoWSServerToClient)); err != nil {
		return nil, err
	}
	return s, nil
}

// ClientHello 开连后先发给主控的首帧（临时公钥，32 字节）。
func (s *Session) ClientHello() []byte { return append([]byte(nil), s.hello...) }

func counterNonce(counter uint64) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// Seal 封一帧发出：计数(8, 大端) ‖ 密文 ‖ tag。
func (s *Session) Seal(plain []byte) []byte {
	s.mu.Lock()
	counter := s.sendCount
	s.sendCount++
	s.mu.Unlock()
	header := make([]byte, 8, 8+len(plain)+s.aeadC2S.Overhead())
	binary.BigEndian.PutUint64(header, counter)
	return s.aeadC2S.Seal(header, counterNonce(counter), plain, nil)
}

// ErrReplay 收到的帧计数没有递增。
var ErrReplay = errors.New("帧计数没有递增")

// Open 解开收到的一帧，要求计数严格递增。
func (s *Session) Open(frame []byte) ([]byte, error) {
	if len(frame) < 8+s.aeadS2C.Overhead() {
		return nil, ErrUndecryptable
	}
	counter := binary.BigEndian.Uint64(frame[:8])
	s.mu.Lock()
	defer s.mu.Unlock()
	if counter < s.recvCount {
		return nil, ErrReplay
	}
	plain, err := s.aeadS2C.Open(nil, counterNonce(counter), frame[8:], nil)
	if err != nil {
		return nil, ErrUndecryptable
	}
	s.recvCount = counter + 1
	return plain, nil
}
