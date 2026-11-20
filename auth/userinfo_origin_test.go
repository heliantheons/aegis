package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"

	"github.com/heliantheon/aegis-go/utilities/key"
	"github.com/heliantheon/aegis/config"
	"github.com/heliantheon/aegis/internal/cache"
	hermesv1 "github.com/heliantheon/aegis/internal/rpc/hermes/v1"
	internaltoken "github.com/heliantheon/aegis/internal/token"
	"github.com/heliantheon/aegis/middleware"
	"github.com/heliantheon/aegis/rpc/hermes"
)

type userInfoClientRegistry struct {
	authorizationRegistry
	origins map[string][]string
}

func (r *userInfoClientRegistry) Invoke(ctx context.Context, method string, request, reply any, options ...grpc.CallOption) error {
	if method != hermesv1.ProvisionService_GetApplication_FullMethodName {
		return r.authorizationRegistry.Invoke(ctx, method, request, reply, options...)
	}
	req, ok := request.(*hermesv1.GetApplicationRequest)
	if !ok {
		return errors.New("unexpected application request type")
	}
	origins, ok := r.origins[req.AppId]
	if !ok {
		return errors.New("application not registered")
	}
	application, ok := reply.(*hermesv1.Application)
	if !ok {
		return errors.New("unexpected application response type")
	}
	application.AppId = req.AppId
	application.AllowedOrigins = origins
	return nil
}

func TestUserInfoOriginUsesVerifiedTokenClient(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service, encoded := signedUserInfoAccessToken(t)
	const allowed = "https://atlas.example"
	const other = "https://other.example"
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, tt := range []struct {
			name, origin, query string
			origins             []string
			status              int
			allowOrigin         string
		}{
			{"registered origin", allowed, "", []string{allowed}, http.StatusOK, allowed},
			{"other client origin", other, "", []string{allowed}, http.StatusForbidden, ""},
			{"forged client query", other, "?client_id=other", []string{allowed}, http.StatusForbidden, ""},
			{"login UI is not a client origin", config.GetEndpoint(), "", []string{allowed}, http.StatusForbidden, ""},
			{"empty application policy", allowed, "", nil, http.StatusForbidden, ""},
			{"no browser origin", "", "", nil, http.StatusOK, ""},
		} {
			t.Run(method+"/"+tt.name, func(t *testing.T) {
				handler := &Handler{tokenSvc: service}
				if tt.origin != "" {
					registry := &userInfoClientRegistry{origins: map[string][]string{"atlas": tt.origins, "other": {other}}}
					manager := cache.NewManager(hermes.New(registry), nil)
					t.Cleanup(manager.Close)
					handler.cache = manager
				}
				router := gin.New()
				router.Handle(method, "/userinfo", middleware.NoStore, handler.UserInfo)
				request := httptest.NewRequestWithContext(t.Context(), method, "/userinfo"+tt.query, nil)
				request.Header.Set("Authorization", "Bearer "+encoded)
				request.Header.Set("Origin", tt.origin)
				recorder := httptest.NewRecorder()
				router.ServeHTTP(recorder, request)
				assertUserInfoOriginResponse(t, recorder, tt.status, tt.allowOrigin)
			})
		}
	}
}

func assertUserInfoOriginResponse(t *testing.T, recorder *httptest.ResponseRecorder, status int, allowOrigin string) {
	t.Helper()
	if recorder.Code != status || recorder.Header().Get("Access-Control-Allow-Origin") != allowOrigin {
		t.Fatalf("response = %d, headers %v, body %s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	if recorder.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("UserInfo enabled ambient browser credentials")
	}
	if recorder.Code != http.StatusOK {
		return
	}
	var claims map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &claims); err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "user-123" {
		t.Fatalf("UserInfo subject = %v", claims["sub"])
	}
}

func signedUserInfoAccessToken(t *testing.T) (*internaltoken.Service, string) {
	t.Helper()
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
	service := internaltoken.NewService(nil, provider(privateKey), provider(publicKey), provider(secret), provider(publicKey))
	access := internaltoken.NewClaimsBuilder().Issuer(config.GetIssuer()).ClientID("atlas").Audience(config.GetOIDCDefaultAudience()).ExpiresIn(time.Hour).
		Build(internaltoken.NewUserAccessTokenBuilder().OpenID("user-123").Nickname("Example").Scope("openid profile"))
	encoded, err := service.Issue(t.Context(), access)
	if err != nil {
		t.Fatal(err)
	}
	return service, encoded
}
