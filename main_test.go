package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/heliantheon/aegis-go/guard"
	"github.com/heliantheon/aegis/auth"
	"github.com/heliantheon/aegis/middleware"
)

func TestConfigureProfileTokenManagerUsesIrisServiceSeed(t *testing.T) {
	if err := configureProfileTokenManager("https://aegis.example.com/api", "iris", bytes.Repeat([]byte{1}, 48)); err != nil {
		t.Fatalf("configureProfileTokenManager() error = %v", err)
	}
	if guard.GetTokenManager() == nil {
		t.Fatal("configureProfileTokenManager() did not configure the guard token manager")
	}
}

func TestConfigureProfileTokenManagerRejectsSigningSeed(t *testing.T) {
	if err := configureProfileTokenManager("https://aegis.example.com/api", "iris", bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("configureProfileTokenManager() error = nil, want invalid service seed error")
	}
}

func TestAuthRouteResponseTraits(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const origin = "https://client.example"
	router := gin.New()
	cookieCORS := middleware.CORS(middleware.CORSOptions{
		ResolveOrigin:    middleware.AllowedOrigins([]string{origin}),
		AllowCredentials: true,
	})
	registerAuthRoutes(router.Group("/api"), &auth.Handler{}, cookieCORS, middleware.ProtectCookieRequests(origin))
	for _, tt := range []struct {
		method, path                     string
		status                           int
		allowOrigin                      string
		credentials, noStore, noReferrer bool
	}{
		{http.MethodPost, "/api/token", http.StatusBadRequest, "*", false, true, false},
		{http.MethodPost, "/api/revoke", http.StatusBadRequest, "*", false, true, false},
		{http.MethodGet, "/api/pubkeys", http.StatusBadRequest, "*", false, false, false},
		{http.MethodPost, "/api/authorize", http.StatusBadRequest, origin, true, true, true},
		{http.MethodGet, "/api/idps/unsupported/callback", http.StatusBadRequest, "", false, true, true},
		{http.MethodOptions, "/api/pubkeys", http.StatusNoContent, "*", false, false, false},
		{http.MethodOptions, "/api/token", http.StatusNoContent, "*", false, false, false},
		{http.MethodOptions, "/api/authorize", http.StatusNoContent, origin, true, false, false},
		{http.MethodPost, "/api/check", http.StatusUnauthorized, "", false, true, false},
	} {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequestWithContext(context.Background(), tt.method, tt.path, strings.NewReader("{"))
			request.Header.Set("Origin", origin)
			request.Header.Set("Content-Type", "application/json")
			if tt.method == http.MethodOptions {
				request.Header.Set("Access-Control-Request-Method", http.MethodPost)
			}
			router.ServeHTTP(recorder, request)
			if recorder.Code != tt.status || recorder.Header().Get("Access-Control-Allow-Origin") != tt.allowOrigin {
				t.Fatalf("response = %d, headers %v", recorder.Code, recorder.Header())
			}
			if (recorder.Header().Get("Access-Control-Allow-Credentials") == "true") != tt.credentials {
				t.Fatalf("credential policy = %v", recorder.Header())
			}
			if (recorder.Header().Get("Cache-Control") == "no-store") != tt.noStore || (recorder.Header().Get("Pragma") == "no-cache") != tt.noStore {
				t.Fatalf("cache policy = %v", recorder.Header())
			}
			if (recorder.Header().Get("Referrer-Policy") == "no-referrer") != tt.noReferrer {
				t.Fatalf("referrer policy = %v", recorder.Header())
			}
			if tt.allowOrigin != "" && !strings.Contains(recorder.Header().Get("Access-Control-Expose-Headers"), "WWW-Authenticate") {
				t.Fatalf("bearer error challenge is not readable: %v", recorder.Header())
			}
		})
	}
}

func TestCookieRouteRequestProtection(t *testing.T) {
	const trusted = "https://login.example"
	router := gin.New()
	registerAuthRoutes(router.Group("/api"), &auth.Handler{}, middleware.CORS(middleware.CORSOptions{
		ResolveOrigin:    middleware.AllowedOrigins([]string{trusted}),
		AllowCredentials: true,
	}), middleware.ProtectCookieRequests(trusted))
	for _, path := range []string{"/authorize", "/login", "/idps", "/binding", "/challenge", "/challenge/test", "/logout"} {
		for _, source := range []string{"missing", "untrusted", "cross-site"} {
			t.Run(path+"/"+source, func(t *testing.T) {
				request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api"+path, strings.NewReader("{"))
				request.Header.Set("Content-Type", "application/json")
				switch source {
				case "untrusted":
					request.Header.Set("Origin", "https://evil.example")
				case "cross-site":
					request.Header.Set("Origin", trusted)
					request.Header.Set("Sec-Fetch-Site", "cross-site")
				}
				recorder := httptest.NewRecorder()
				router.ServeHTTP(recorder, request)
				if recorder.Code != http.StatusForbidden {
					t.Fatalf("response = %d, body %s; want cookie protection before body binding", recorder.Code, recorder.Body.String())
				}
			})
		}
	}
	for _, path := range []string{"/authorize", "/login", "/idps", "/binding"} {
		for _, source := range []string{"origin", "fetch metadata", "referer"} {
			t.Run(path+"/trusted "+source, func(t *testing.T) {
				request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api"+path, strings.NewReader("{"))
				request.Header.Set("Content-Type", "application/json")
				switch source {
				case "origin":
					request.Header.Set("Origin", trusted)
				case "fetch metadata":
					request.Header.Set("Sec-Fetch-Site", "same-origin")
				case "referer":
					request.Header.Set("Referer", trusted+"/login")
				}
				recorder := httptest.NewRecorder()
				router.ServeHTTP(recorder, request)
				if recorder.Code != http.StatusBadRequest {
					t.Fatalf("response = %d, body %s; want handler binding error", recorder.Code, recorder.Body.String())
				}
			})
		}
	}
}

func TestPublicOAuthRoutesDoNotRequireCookieSourceEvidence(t *testing.T) {
	const trusted = "https://login.example"
	router := gin.New()
	registerAuthRoutes(router.Group("/api"), &auth.Handler{}, middleware.CORS(middleware.CORSOptions{
		ResolveOrigin: middleware.AllowedOrigins([]string{trusted}),
	}), middleware.ProtectCookieRequests(trusted))
	for _, tt := range []struct {
		path   string
		status int
	}{
		{"/token", http.StatusBadRequest},
		{"/revoke", http.StatusBadRequest},
	} {
		for _, origin := range []string{"", "https://other.example"} {
			t.Run(tt.path+"/"+origin, func(t *testing.T) {
				request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api"+tt.path, strings.NewReader("{"))
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Origin", origin)
				request.Header.Set("Sec-Fetch-Site", "cross-site")
				recorder := httptest.NewRecorder()
				router.ServeHTTP(recorder, request)
				if recorder.Code != tt.status {
					t.Fatalf("response = %d, body %s; want %d", recorder.Code, recorder.Body.String(), tt.status)
				}
			})
		}
	}
}
