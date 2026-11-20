package token

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	pkgservice "github.com/heliantheon/aegis-go/service"
	"github.com/heliantheon/aegis-go/utilities/key"
	tokendef "github.com/heliantheon/aegis-go/utilities/token"
)

func TestOIDCIDTokenAndPublishedJWK(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{issuer: "https://issuer.example/api"}
	service.oidcOnce.Do(func() {
		service.oidcSigner = newIDTokenSigner(privateKey, []*rsa.PublicKey{&privateKey.PublicKey})
	})
	authenticatedAt := time.Now().Add(-time.Minute).Truncate(time.Second)
	claims := NewIDTokenClaims("user-123", "client-123", authenticatedAt, time.Hour)
	claims.Nonce = "request-nonce"
	claims.Nickname = "Example"
	claims.Picture = "https://example.com/avatar.png"
	encoded, err := service.IssueIDToken(context.Background(), claims)
	if err != nil {
		t.Fatal(err)
	}
	keySet, err := service.OIDCKeySet()
	if err != nil {
		t.Fatal(err)
	}
	publicKeys, ok := keySet["keys"].([]map[string]string)
	if !ok || len(publicKeys) == 0 {
		t.Fatalf("JWKS contains no RSA public keys: %v", keySet)
	}
	jwk := publicKeys[0]
	n, err := base64.RawURLEncoding.DecodeString(jwk["n"])
	if err != nil {
		t.Fatal(err)
	}
	e, err := base64.RawURLEncoding.DecodeString(jwk["e"])
	if err != nil {
		t.Fatal(err)
	}
	if new(big.Int).SetBytes(e).Int64() != 65537 {
		t.Fatalf("unexpected RSA exponent: %x", e)
	}
	publicKey := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537}
	verified := &IDTokenClaims{}
	_, err = jwt.ParseWithClaims(encoded, verified, func(token *jwt.Token) (any, error) {
		if token.Header["kid"] != jwk["kid"] || jwk["alg"] != "RS256" || jwk["kty"] != "RSA" {
			t.Fatalf("JWT header and published JWK disagree: header=%v, jwk=%v", token.Header, jwk)
		}
		return publicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(service.issuer), jwt.WithAudience("client-123"), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil {
		t.Fatalf("standard JWT verification using published JWK failed: %v", err)
	}
	if verified.Subject != "user-123" || verified.Nonce != claims.Nonce || verified.Nickname != claims.Nickname || verified.AuthTime == nil || !verified.AuthTime.Equal(authenticatedAt) {
		t.Fatalf("verified identity = %+v", verified)
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(encoded, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, claim := range []string{"iat", "exp", "auth_time"} {
		if _, ok := decoded[claim].(float64); !ok {
			t.Fatalf("claim %s is not NumericDate: %v", claim, decoded[claim])
		}
	}
	for _, claim := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, ok := jwk[claim]; ok {
			t.Fatalf("JWKS disclosed private parameter %s", claim)
		}
	}
}

func TestOIDCKeyRotationKeepsPreviousPublicKey(t *testing.T) {
	t.Parallel()
	previous, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	current, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer := newIDTokenSigner(current, []*rsa.PublicKey{&current.PublicKey, &previous.PublicKey, &current.PublicKey})
	previousToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{Subject: "user-123", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))})
	previousToken.Header["kid"] = oidcPublicKey(&previous.PublicKey)["kid"]
	encoded, err := previousToken.SignedString(previous)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwt.Parse(encoded, func(token *jwt.Token) (any, error) {
		for _, jwk := range signer.keys {
			if token.Header["kid"] == jwk["kid"] {
				n, decodeErr := base64.RawURLEncoding.DecodeString(jwk["n"])
				if decodeErr != nil {
					return nil, decodeErr
				}
				return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537}, nil
			}
		}
		return nil, jwt.ErrTokenUnverifiable
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("previous token cannot verify against rotated JWKS: %v", err)
	}
	if signer.kid != oidcPublicKey(&current.PublicKey)["kid"] {
		t.Fatal("new signer does not select current key")
	}
}

func TestAccessTokenStillUsesExistingPASETOContract(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	provider := func(material []byte) key.Provider {
		return key.SingleOf(func(context.Context, string) ([]byte, error) { return material, nil })
	}
	service := &Service{
		domainSignProvider: provider(privateKey), serviceKeyProvider: provider(secret),
		domainSigners: make(map[string]*Signer), serviceEncryptors: make(map[string]*Encryptor),
	}
	access := NewClaimsBuilder().Issuer("https://issuer.example/api").ClientID("app").Audience("resource").ExpiresIn(time.Hour).
		Build(NewUserAccessTokenBuilder().OpenID("user-123").Nickname("Example").Scope("openid profile"))
	encoded, err := service.Issue(context.Background(), access)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "v4.public.") {
		t.Fatalf("access token changed format: %q", encoded)
	}
	decoded, err := pkgservice.NewDecryptor("resource", provider(secret), provider(publicKey)).Interpret(context.Background(), encoded)
	if err != nil {
		t.Fatalf("existing Go SDK cannot verify/decrypt access token: %v", err)
	}
	identity, ok := decoded.(*tokendef.UserAccessToken)
	if !ok || identity.OpenID() != "user-123" || identity.Nickname() != "Example" || !strings.HasPrefix(identity.Subject(), "v4.local.") {
		t.Fatalf("existing encrypted identity contract changed: %+v", decoded)
	}
}
