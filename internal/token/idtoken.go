package token

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/heliantheon/aegis/config"
)

// IDTokenClaims 是面向登录客户端的 OIDC 身份声明，与 PASETO 访问令牌分离。
type IDTokenClaims struct {
	jwt.RegisteredClaims
	Nonce       string `json:"nonce,omitempty"`
	Nickname    string `json:"nickname,omitempty"`
	Picture     string `json:"picture,omitempty"`
	Email       string `json:"email,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
}

type idTokenSigner struct {
	privateKey *rsa.PrivateKey
	kid        string
	keys       []map[string]string
}

func newIDTokenSigner(privateKey *rsa.PrivateKey, publicKeys []*rsa.PublicKey) *idTokenSigner {
	signer := &idTokenSigner{privateKey: privateKey}
	seen := make(map[string]bool, len(publicKeys))
	for _, publicKey := range publicKeys {
		jwk := oidcPublicKey(publicKey)
		if seen[jwk["kid"]] {
			continue
		}
		seen[jwk["kid"]] = true
		signer.keys = append(signer.keys, jwk)
	}
	signer.kid = oidcPublicKey(&privateKey.PublicKey)["kid"]
	return signer
}

func oidcPublicKey(publicKey *rsa.PublicKey) map[string]string {
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())
	// RFC 7638：成员按字典序排列后计算 JWK thumbprint。
	thumbprint := sha256.Sum256([]byte(`{"e":"` + e + `","kty":"RSA","n":"` + n + `"}`))
	return map[string]string{
		"kty": "RSA", "use": "sig", "alg": "RS256",
		"kid": base64.RawURLEncoding.EncodeToString(thumbprint[:]), "n": n, "e": e,
	}
}

func (s *Service) oidcSigningKey() (*idTokenSigner, error) {
	s.oidcOnce.Do(func() {
		privateKey, publicKeys, err := config.GetOIDCSigningKeys()
		if err != nil {
			s.oidcErr = err
			return
		}
		s.oidcSigner = newIDTokenSigner(privateKey, publicKeys)
	})
	return s.oidcSigner, s.oidcErr
}

// OIDCKeySet 返回当前签名公钥及尚未退役的轮换公钥，永不暴露私钥。
func (s *Service) OIDCKeySet() (map[string]any, error) {
	signer, err := s.oidcSigningKey()
	if err != nil {
		return nil, err
	}
	return map[string]any{"keys": signer.keys}, nil
}

// IssueIDToken 使用独立 RSA 密钥签发 RS256 JWT，不进入 PASETO 签发链路。
func (s *Service) IssueIDToken(ctx context.Context, claims IDTokenClaims) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if claims.Subject == "" || len(claims.Subject) > 255 || len(claims.Audience) != 1 || claims.Audience[0] == "" {
		return "", fmt.Errorf("OIDC ID Token 必须有用户 subject 和唯一 client audience")
	}
	if claims.IssuedAt == nil || claims.ExpiresAt == nil || !claims.ExpiresAt.After(claims.IssuedAt.Time) {
		return "", fmt.Errorf("OIDC ID Token 时间声明无效")
	}
	claims.Issuer = s.issuer
	signer, err := s.oidcSigningKey()
	if err != nil {
		return "", fmt.Errorf("加载 OIDC 签名密钥失败: %w", err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = signer.kid
	encoded, err := token.SignedString(signer.privateKey)
	if err != nil {
		return "", fmt.Errorf("签发 OIDC ID Token 失败: %w", err)
	}
	return encoded, nil
}

// NewIDTokenClaims 构建具有标准时间语义的 OIDC 身份声明。
func NewIDTokenClaims(subject, clientID string, lifetime time.Duration) IDTokenClaims {
	now := time.Now()
	return IDTokenClaims{RegisteredClaims: jwt.RegisteredClaims{
		Subject: subject, Audience: jwt.ClaimStrings{clientID},
		IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(lifetime)),
	}}
}
