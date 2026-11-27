package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"

	"github.com/heliantheon/aegis/config"
	"github.com/heliantheon/aegis/internal/authorize"
	"github.com/heliantheon/aegis/internal/cache"
	"github.com/heliantheon/aegis/internal/provision"
	hermesv1 "github.com/heliantheon/aegis/internal/rpc/hermes/v1"
	"github.com/heliantheon/aegis/rpc/hermes"
	pkgredis "github.com/heliantheon/common/redis"
)

// Exercise the real cache/Hermes read-through without a network dependency.
type originHermesConn struct {
	grpc.ClientConnInterface
}

func (s *originHermesConn) Invoke(_ context.Context, method string, args, reply any, _ ...grpc.CallOption) error {
	switch {
	case strings.HasSuffix(method, "/GetApplication"):
		request, ok := args.(*hermesv1.GetApplicationRequest)
		if !ok {
			return fmt.Errorf("unexpected application request %T", args)
		}
		id := request.AppId
		app, ok := reply.(*hermesv1.Application)
		if !ok {
			return fmt.Errorf("unexpected application response %T", reply)
		}
		app.AppId = id
		switch id {
		case "app-a":
			app.AllowedOrigins = []string{"https://a.example"}
		case "app-b", "confidential-b":
			app.AllowedOrigins = []string{"https://b.example"}
		case "empty":
		default:
			return fmt.Errorf("unknown application %q", id)
		}
		return nil
	case strings.HasSuffix(method, "/GetKeys"):
		request, ok := args.(*hermesv1.GetKeysRequest)
		if !ok {
			return fmt.Errorf("unexpected key request %T", args)
		}
		keys, ok := reply.(*hermesv1.KeySet)
		if !ok {
			return fmt.Errorf("unexpected key response %T", reply)
		}
		if request.OwnerId == "confidential-b" {
			keys.Keys = [][]byte{bytes.Repeat([]byte{0x42}, 48)}
		}
		return nil
	default:
		return fmt.Errorf("unexpected RPC %s", method)
	}
}

type originRedis struct {
	pkgredis.Client
	values   map[string]string
	consumed int
	writes   int
	reads    int
}

func (s *originRedis) Get(_ context.Context, key string) (string, error) {
	s.reads++
	if value, ok := s.values[key]; ok {
		return value, nil
	}
	return "", pkgredis.ErrNil
}

func (s *originRedis) Set(_ context.Context, key string, value any, _ time.Duration) error {
	s.writes++
	text, ok := value.(string)
	if !ok {
		return fmt.Errorf("unexpected Redis value %T", value)
	}
	s.values[key] = text
	return nil
}

func (s *originRedis) Eval(_ context.Context, _ string, _ []string, _ ...any) (any, error) {
	s.consumed++
	return nil, pkgredis.ErrNil
}

func originFixture(t *testing.T) (*Handler, *originRedis, *originHermesConn) {
	t.Helper()
	redis := &originRedis{values: make(map[string]string)}
	conn := &originHermesConn{}
	client := hermes.New(conn)
	manager := cache.NewManager(client, redis)
	t.Cleanup(manager.Close)
	return &Handler{
		provisionSvc: provision.NewService(manager),
		authorizeSvc: authorize.NewService(manager, client, nil, nil, nil, time.Minute),
	}, redis, conn
}

func originTestConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[aegis]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
}

func TestTokenOriginUsesAuthenticatedBodyClient(t *testing.T) {
	gin.SetMode(gin.TestMode)
	originTestConfig(t)
	for _, format := range []string{"form", "json"} {
		for _, tc := range []struct {
			name     string
			client   string
			origin   string
			status   int
			consumed int
			allow    string
		}{
			{"forged query cannot select policy", "app-b", "https://a.example", http.StatusForbidden, 0, ""},
			{"matching policy reaches grant exchange", "app-b", "https://b.example", http.StatusBadRequest, 1, "https://b.example"},
			{"empty origins fail closed", "empty", "https://a.example", http.StatusForbidden, 0, ""},
			{"no origin retains grant exchange", "empty", "", http.StatusBadRequest, 1, ""},
		} {
			t.Run(format+"/"+tc.name, func(t *testing.T) {
				handler, redis, _ := originFixture(t)
				body, contentType := originTokenBody(t, format, tc.client)
				recorder := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(recorder)
				c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/token?client_id=app-a", strings.NewReader(body))
				c.Request.Header.Set("Content-Type", contentType)
				c.Request.Header.Set("Origin", tc.origin)
				handler.Token(c)
				assertProtocolOrigin(t, recorder, tc.status, tc.allow, tc.origin)
				if redis.consumed != tc.consumed {
					t.Fatalf("authorization codes consumed = %d, want %d", redis.consumed, tc.consumed)
				}
			})
		}
	}
}

func originTokenBody(t *testing.T, format, client string) (string, string) {
	t.Helper()
	if format == "form" {
		return url.Values{"client_id": {client}, "grant_type": {"authorization_code"}, "code": {"unconsumed"}}.Encode(), "application/x-www-form-urlencoded"
	}
	body, err := json.Marshal(map[string]string{"client_id": client, "grant_type": "authorization_code", "code": "unconsumed"})
	if err != nil {
		t.Fatal(err)
	}
	return string(body), "application/json"
}

func assertProtocolOrigin(t *testing.T, recorder *httptest.ResponseRecorder, status int, allow, origin string) {
	t.Helper()
	if recorder.Code != status || recorder.Header().Get("Access-Control-Allow-Origin") != allow {
		t.Fatalf("status=%d allow=%q body=%s; want status=%d allow=%q", recorder.Code, recorder.Header().Get("Access-Control-Allow-Origin"), recorder.Body, status, allow)
	}
	if recorder.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("client protocol response allows credentials")
	}
	if origin != "" && !strings.Contains(recorder.Header().Get("Vary"), "Origin") {
		t.Fatal("origin response does not vary on Origin")
	}
}

func TestRevokeOriginUsesStoredTokenOwner(t *testing.T) {
	gin.SetMode(gin.TestMode)
	originTestConfig(t)
	for _, tc := range []struct {
		name    string
		owner   string
		client  string
		origin  string
		status  int
		revoked bool
		allow   string
	}{
		{"forged client cannot grant origin", "app-b", "app-a", "https://a.example", http.StatusBadRequest, false, ""},
		{"owner policy rejects other origin", "app-b", "", "https://a.example", http.StatusForbidden, false, ""},
		{"owner policy allows revocation with cookies", "app-b", "app-b", "https://b.example", http.StatusOK, true, "https://b.example"},
		{"empty origins fail closed", "empty", "", "https://a.example", http.StatusForbidden, false, ""},
		{"unknown client fails closed", "missing", "", "https://a.example", http.StatusForbidden, false, ""},
		{"unknown token retains RFC7009 response", "", "app-a", "https://a.example", http.StatusOK, false, ""},
		{"no origin preserves revocation semantics", "app-b", "app-a", "", http.StatusOK, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, redis, _ := originFixture(t)
			key := config.GetCacheKeyPrefix("refresh_token") + "refresh"
			if tc.owner != "" {
				encoded, err := json.Marshal(cache.RefreshToken{Token: "refresh", ClientID: tc.owner, ExpiresAt: time.Now().Add(time.Hour)})
				if err != nil {
					t.Fatal(err)
				}
				redis.values[key] = string(encoded)
			}
			recorder := httptest.NewRecorder()
			router := gin.New()
			router.POST("/api/revoke", handler.Revoke)
			body := url.Values{"token": {"refresh"}, "client_id": {tc.client}}.Encode()
			request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/revoke?client_id=app-a", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("Origin", tc.origin)
			request.AddCookie(&http.Cookie{Name: "sso", Value: "present", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
			router.ServeHTTP(recorder, request)
			if recorder.Code != tc.status {
				t.Fatalf("status=%d body=%s, want %d", recorder.Code, recorder.Body, tc.status)
			}
			if got := redis.writes > 0; got != tc.revoked {
				t.Fatalf("revoked=%v, want %v", got, tc.revoked)
			}
			if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != tc.allow {
				t.Fatalf("allow origin=%q, want %q", got, tc.allow)
			}
			if recorder.Header().Get("Access-Control-Allow-Credentials") != "" {
				t.Fatal("revocation response allows credentials")
			}
		})
	}
}

func TestRefreshOriginRejectedBeforeTokenLookup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	originTestConfig(t)
	handler, redis, _ := originFixture(t)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	body := url.Values{"client_id": {"app-b"}, "grant_type": {"refresh_token"}, "refresh_token": {"untouched"}}.Encode()
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/token?client_id=app-a", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.Request.Header.Set("Origin", "https://a.example")
	handler.Token(c)
	if recorder.Code != http.StatusForbidden || redis.reads != 0 || redis.writes != 0 {
		t.Fatalf("status=%d reads=%d writes=%d, want rejection before refresh token lookup", recorder.Code, redis.reads, redis.writes)
	}
}

func TestTokenOriginUsesBasicAuthenticatedClient(t *testing.T) {
	gin.SetMode(gin.TestMode)
	originTestConfig(t)
	for _, format := range []string{"form", "json"} {
		for _, origin := range []string{"https://a.example", "https://b.example"} {
			t.Run(format+"/"+origin, func(t *testing.T) {
				handler, redis, _ := originFixture(t)
				body := "grant_type=authorization_code&code=unconsumed"
				contentType := "application/x-www-form-urlencoded"
				if format == "json" {
					body = `{"grant_type":"authorization_code","code":"unconsumed"}`
					contentType = "application/json"
				}
				recorder := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(recorder)
				c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/token?client_id=app-a", strings.NewReader(body))
				c.Request.Header.Set("Content-Type", contentType)
				c.Request.Header.Set("Origin", origin)
				c.Request.SetBasicAuth("confidential-b", "5TSHOjfPvWkRKtg_IBoVtw0dq-8YKt6rVjUFxdo3J1k")
				handler.Token(c)
				wantStatus, wantConsumed, wantAllow := http.StatusForbidden, 0, ""
				if origin == "https://b.example" {
					wantStatus, wantConsumed, wantAllow = http.StatusBadRequest, 1, origin
				}
				if recorder.Code != wantStatus || redis.consumed != wantConsumed || recorder.Header().Get("Access-Control-Allow-Origin") != wantAllow {
					t.Fatalf("status=%d consumed=%d allow=%q body=%s", recorder.Code, redis.consumed, recorder.Header().Get("Access-Control-Allow-Origin"), recorder.Body)
				}
			})
		}
	}
}
