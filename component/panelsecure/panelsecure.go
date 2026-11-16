// Package panelsecure 客户端 ↔ 主控的端到端加密（与 iOS / Android 客户端、主控 internal/appsecure 同一套，逐字节一致）。
//
// 信任模型：许可证服务用 Ed25519 给每台主控的 X25519 公钥签一张绑定域名的证书（GET /api/secure/cert，明文），
// 客户端内置许可证公钥验签、核对域名与有效期，得到可信的主控公钥。
//
//   - 加密 RPC（POST /api/secure/rpc）：每请求一把临时 X25519 密钥 → HKDF-SHA256（salt = 临时公钥 ‖ 主控公钥，
//     IKM = 原始共享密钥）派生收发两把 key → ChaCha20-Poly1305。请求信封 = 临时公钥(32) ‖ nonce(12) ‖ 密文+tag，
//     应答 = nonce(12) ‖ 密文+tag。
//   - 实时通道（WS /api/secure/ws）：首帧发临时公钥(32)，同样派生出两把会话 key；之后每帧 = 计数(8, 大端) ‖ 密文+tag，
//     nonce = 4 个零字节 ‖ 计数，两个方向各自从 0 递增，收到的计数必须严格递增（防重放），见 session.go。
package panelsecure

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// LicenseKey 许可证服务的 Ed25519 验签公钥（base64，与客户端内置的同一把）。只有单测会换掉它。
var LicenseKey = "/cKXW8AIOPE6ChoZtXjP8N+KkIYvKLvnpLyaLPrpTQM="

// HKDF info 串：四个方向各一把独立 key。
const (
	InfoRPCClientToServer = "mmx-secure-rpc-c2s-v1"
	InfoRPCServerToClient = "mmx-secure-rpc-s2c-v1"
	InfoWSClientToServer  = "mmx-secure-ws-c2s-v1"
	InfoWSServerToClient  = "mmx-secure-ws-s2c-v1"
)

// HKDF 派生一把 32 字节的 key（HKDF-SHA256）。
func HKDF(secret, salt []byte, info string) []byte {
	key := make([]byte, 32)
	_, _ = io.ReadFull(hkdf.New(sha256.New, secret, salt, []byte(info)), key)
	return key
}

// Cert 主控证书（/api/secure/cert 的 JSON，字段名是已固定的契约）。
type Cert struct {
	MasterPub  string `json:"masterPub"`
	Domain     string `json:"domain"`
	ExpireUnix int64  `json:"expireUnix"`
	Sig        string `json:"sig"`
}

// CertMessage 被签名的确切字节。
func CertMessage(masterPub, domain string, expireUnix int64) []byte {
	return []byte(fmt.Sprintf("mmx-cert-v1\n%s\n%s\n%d", masterPub, domain, expireUnix))
}

// Verify 验签 + 核对域名与有效期（同客户端 MasterCert.verified），成功回主控公钥。
func (c Cert) Verify(host string) (*ecdh.PublicKey, error) {
	licenseKey, _ := base64.StdEncoding.DecodeString(LicenseKey)
	sig, _ := base64.StdEncoding.DecodeString(c.Sig)
	if c.ExpireUnix <= time.Now().Unix() || !strings.EqualFold(c.Domain, host) || len(licenseKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(ed25519.PublicKey(licenseKey), CertMessage(c.MasterPub, c.Domain, c.ExpireUnix), sig) {
		return nil, errors.New("主控证书验签失败（域名 / 有效期不符，或不是正版主控）")
	}
	raw, err := base64.StdEncoding.DecodeString(c.MasterPub)
	if err != nil {
		return nil, errors.New("主控公钥无效")
	}
	return ecdh.X25519().NewPublicKey(raw)
}

// FetchMasterKey 取主控证书并验签，回可信的主控公钥。base = 主控地址（scheme://host[:port]）。
func FetchMasterKey(client *http.Client, base string) (*ecdh.PublicKey, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	resp, err := client.Get(base + "/api/secure/cert")
	if err != nil {
		return nil, fmt.Errorf("连不上主控（%s）：%v", u.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("主控证书端点返回 HTTP %d", resp.StatusCode)
	}
	var cert Cert
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&cert); err != nil {
		return nil, errors.New("主控证书格式无法解析")
	}
	return cert.Verify(u.Hostname())
}

// SealRPC 封一次加密 RPC 请求：回信封与解应答用的 key。
func SealRPC(masterPub *ecdh.PublicKey, plain []byte) (envelope, responseKey []byte, err error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	shared, err := eph.ECDH(masterPub)
	if err != nil {
		return nil, nil, err
	}
	ePub := eph.PublicKey().Bytes()
	salt := append(append([]byte{}, ePub...), masterPub.Bytes()...)
	keyC2S := HKDF(shared, salt, InfoRPCClientToServer)
	keyS2C := HKDF(shared, salt, InfoRPCServerToClient)
	aead, err := chacha20poly1305.New(keyC2S)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, _ = rand.Read(nonce)
	envelope = append(append(append([]byte{}, ePub...), nonce...), aead.Seal(nil, nonce, plain, nil)...)
	return envelope, keyS2C, nil
}

// ErrUndecryptable 应答 / 帧解不开（不是这台主控、或者被中间人改过）。
var ErrUndecryptable = errors.New("主控应答无法解密")

// OpenRPC 解开主控的应答（nonce(12) ‖ 密文+tag）。
func OpenRPC(responseKey, body []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(responseKey)
	if err != nil {
		return nil, err
	}
	if len(body) < chacha20poly1305.NonceSize+aead.Overhead() {
		return nil, ErrUndecryptable
	}
	out, err := aead.Open(nil, body[:chacha20poly1305.NonceSize], body[chacha20poly1305.NonceSize:], nil)
	if err != nil {
		return nil, ErrUndecryptable
	}
	return out, nil
}
