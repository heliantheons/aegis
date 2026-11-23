package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"

	"github.com/heliantheon/aegis-go/utilities/key"
	pkgtoken "github.com/heliantheon/aegis-go/utilities/token"
	"github.com/heliantheon/aegis/auth"
	hermesv1 "github.com/heliantheon/aegis/internal/rpc/hermes/v1"
	internaltoken "github.com/heliantheon/aegis/internal/token"
	"github.com/heliantheon/aegis/profile"
	"github.com/heliantheon/aegis/rpc/hermes"
)

type profileUserRegistry struct {
	grpc.ClientConnInterface
	lookups []string
}

func (r *profileUserRegistry) Invoke(_ context.Context, method string, request, reply any, _ ...grpc.CallOption) error {
	if method != hermesv1.UserService_GetDecryptedUser_FullMethodName {
		return fmt.Errorf("unexpected RPC %s", method)
	}
	req, ok := request.(*hermesv1.OpenIDRequest)
	if !ok {
		return fmt.Errorf("unexpected request %T", request)
	}
	user, ok := reply.(*hermesv1.DecryptedUser)
	if !ok {
		return fmt.Errorf("unexpected response %T", reply)
	}
	r.lookups = append(r.lookups, req.Openid)
	nickname, email := "Current nickname", "current@example.com"
	user.User = &hermesv1.User{Openid: req.Openid, Nickname: &nickname, Email: &email, EmailVerified: true}
	user.Phone = "+123456789"
	return nil
}

func TestProfileUsesIrisTokenAndCurrentUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pubkeys" || r.URL.Query().Get("client_id") != "atlas" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		if err := json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"public_key": base64.StdEncoding.EncodeToString(publicKey)}}}); err != nil {
			t.Error(err)
		}
	}))
	defer keys.Close()
	seed := make([]byte, 48)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	if err := configureProfileTokenManager(keys.URL, "iris", seed); err != nil {
		t.Fatal(err)
	}
	registry := &profileUserRegistry{}
	profileHandler := profile.NewHandler(hermes.New(registry), nil)
	handler := auth.NewHandler(nil, nil, nil, nil, nil, nil, profileHandler, nil)
	router := gin.New()
	if err := registerAccountRoutes(router.Group("/api"), handler, "iris"); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, token string
		status      int
	}{
		{"Iris token without OIDC scopes", signedProfileToken(t, privateKey, seed, "iris", time.Hour), http.StatusOK},
		{"other resource", signedProfileToken(t, privateKey, seed, "hermes", time.Hour), http.StatusUnauthorized},
		{"expired Iris token", signedProfileToken(t, privateKey, seed, "iris", -time.Second), http.StatusUnauthorized},
		{"missing token", "", http.StatusUnauthorized},
		{"malformed token", "invalid", http.StatusUnauthorized},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := len(registry.lookups)
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/profile?openid=other-user", nil)
			if tt.token != "" {
				request.Header.Set("Authorization", "Bearer "+tt.token)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != tt.status || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("profile response = %d %v %s", response.Code, response.Header(), response.Body.String())
			}
			if tt.status != http.StatusOK {
				if len(registry.lookups) != before {
					t.Fatal("rejected token reached user lookup")
				}
				return
			}
			var got profile.ProfileResponse
			if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.OpenID != "user-123" || got.Nickname == nil || *got.Nickname != "Current nickname" || got.Email == nil || *got.Email != "current@example.com" || !got.EmailVerified || got.Phone != "+123456789" {
				t.Fatalf("current profile = %+v", got)
			}
			if len(registry.lookups) != before+1 || registry.lookups[before] != "user-123" {
				t.Fatalf("profile user lookups = %v", registry.lookups)
			}
		})
	}
}

func signedProfileToken(t *testing.T, privateKey ed25519.PrivateKey, seed []byte, audience string, lifetime time.Duration) string {
	t.Helper()
	provider := func(material []byte) key.Provider {
		return key.SingleOf(func(context.Context, string) ([]byte, error) { return material, nil })
	}
	built := pkgtoken.NewClaimsBuilder().Issuer("https://aegis.example/api").ClientID("atlas").Audience(audience).ExpiresIn(lifetime).
		Build(pkgtoken.NewUserAccessTokenBuilder().OpenID("user-123").Nickname("Old token nickname"))
	uat, ok := built.(*pkgtoken.UserAccessToken)
	if !ok {
		t.Fatalf("built token = %T", built)
	}
	payload, err := uat.MarshalIdentity()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := internaltoken.NewEncryptor(key.EncryptKeyProvider(provider(seed)), audience).Encrypt(t.Context(), payload)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := pkgtoken.Build(uat)
	if err != nil {
		t.Fatal(err)
	}
	wire.SetSubject(encrypted)
	signed, err := internaltoken.NewSigner(provider(privateKey), "atlas").Sign(t.Context(), wire)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
