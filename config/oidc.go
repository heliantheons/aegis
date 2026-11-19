package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// GetOIDCDefaultAudience 返回未指定资源的 OIDC 请求使用的服务。
func GetOIDCDefaultAudience() string {
	if audience := Cfg().GetString("oidc.default-audience"); audience != "" {
		return audience
	}
	return GetIrisAudience()
}

// GetOIDCSigningKeys 加载独立于 PASETO 的 RSA 签名密钥与轮换公钥。
// 密钥在进程启动时配置；轮换时保留旧公钥直到其 ID Token 全部过期。
func GetOIDCSigningKeys() (*rsa.PrivateKey, []*rsa.PublicKey, error) {
	block, rest := pem.Decode([]byte(Cfg().GetString("oidc.signing-key")))
	if block == nil || strings.TrimSpace(string(rest)) != "" {
		return nil, nil, fmt.Errorf("oidc.signing-key 必须包含一个 RSA 私钥 PEM")
	}
	privateKey, err := parseOIDCPrivateKey(block)
	if err != nil {
		return nil, nil, err
	}
	if privateKey.N.BitLen() < 2048 {
		return nil, nil, fmt.Errorf("oidc.signing-key 至少需要 2048 位 RSA 密钥")
	}
	if err := privateKey.Validate(); err != nil {
		return nil, nil, fmt.Errorf("校验 OIDC RSA 私钥失败: %w", err)
	}
	privateKey.Precompute()

	publicKeys := []*rsa.PublicKey{&privateKey.PublicKey}
	for _, encoded := range Cfg().GetStringSlice("oidc.verification-keys") {
		block, rest := pem.Decode([]byte(encoded))
		if block == nil || block.Type != "PUBLIC KEY" || strings.TrimSpace(string(rest)) != "" {
			return nil, nil, fmt.Errorf("oidc.verification-keys 必须是 PKIX 公钥 PEM 列表")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("解析 OIDC 轮换公钥失败: %w", err)
		}
		publicKey, ok := parsed.(*rsa.PublicKey)
		if !ok || publicKey.N.BitLen() < 2048 {
			return nil, nil, fmt.Errorf("OIDC 轮换公钥必须是至少 2048 位 RSA 密钥")
		}
		publicKeys = append(publicKeys, publicKey)
	}
	return privateKey, publicKeys, nil
}

func parseOIDCPrivateKey(block *pem.Block) (*rsa.PrivateKey, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析 OIDC RSA 私钥失败: %w", err)
		}
		return privateKey, nil
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析 OIDC 私钥失败: %w", err)
		}
		if privateKey, ok := parsed.(*rsa.PrivateKey); ok {
			return privateKey, nil
		}
	}
	return nil, fmt.Errorf("oidc.signing-key 必须是 PKCS#1 或 PKCS#8 RSA 私钥")
}
