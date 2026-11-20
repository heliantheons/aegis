package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCORSOriginAndCredentialCombinations(t *testing.T) {
	for _, tt := range []struct {
		name        string
		resolve     OriginResolver
		credentials bool
		origin      string
		allowOrigin string
		vary        bool
	}{
		{"any origin without cookies", AnyOrigin, false, "https://client.example", "*", false},
		{"wildcard with cookies rejected", AnyOrigin, true, "https://client.example", "", true},
		{"allowed origin with cookies", AllowedOrigins([]string{"https://client.example"}), true, "https://client.example", "https://client.example", true},
		{"rejected origin varies cached response", AllowedOrigins([]string{"https://client.example"}), true, "https://other.example", "", true},
		{"same origin request", AnyOrigin, false, "", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(func(c *gin.Context) { c.Writer.Header().Add("Vary", "Accept-Encoding"); c.Next() })
			router.GET("/data", CORS(CORSOptions{ResolveOrigin: tt.resolve, AllowCredentials: tt.credentials}), func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"value": "response"}) })
			recorder := httptest.NewRecorder()
			request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/data", nil)
			request.Header.Set("Origin", tt.origin)
			router.ServeHTTP(recorder, request)
			wantStatus := http.StatusOK
			if tt.origin != "" && tt.allowOrigin == "" {
				wantStatus = http.StatusForbidden
			}
			if recorder.Code != wantStatus || recorder.Header().Get("Access-Control-Allow-Origin") != tt.allowOrigin {
				t.Fatalf("response = %d, headers %v", recorder.Code, recorder.Header())
			}
			wantCredentials := ""
			if tt.credentials && tt.allowOrigin != "" {
				wantCredentials = "true"
			}
			if got := recorder.Header().Get("Access-Control-Allow-Credentials"); got != wantCredentials {
				t.Fatalf("credentials = %q, want %q", got, wantCredentials)
			}
			vary := strings.Join(recorder.Header().Values("Vary"), ",")
			if !strings.Contains(vary, "Accept-Encoding") || strings.Contains(vary, "Origin") != tt.vary {
				t.Fatalf("cache variation = %q", vary)
			}
		})
	}
}

func TestCORSPreflightDoesNotExposePrivateResponsePolicy(t *testing.T) {
	router := gin.New()
	options := CORSOptions{ResolveOrigin: AnyOrigin, AllowMethods: []string{"GET", "POST", "OPTIONS"}}
	group := router.Group("", Preflight(options), CORS(options), NoStore)
	group.OPTIONS("/resource", func(c *gin.Context) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "preflight reached resource"})
	})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/resource", nil)
	request.Header.Set("Origin", "https://client.example")
	request.Header.Set("Access-Control-Request-Method", "POST")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || recorder.Body.Len() != 0 || recorder.Header().Get("Cache-Control") != "" || recorder.Header().Get("Access-Control-Max-Age") != "86400" {
		t.Fatalf("preflight = %d, headers %v, body %s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	if recorder.Header().Get("Access-Control-Allow-Methods") != "GET, POST, OPTIONS" {
		t.Fatalf("allowed methods = %q", recorder.Header().Get("Access-Control-Allow-Methods"))
	}
}

func TestPreflightOnlyInterceptsTruePreflights(t *testing.T) {
	for _, tt := range []struct {
		name, origin, requestedMethod string
		status                        int
		reached                       bool
	}{
		{"ordinary options", "", "", http.StatusAccepted, true},
		{"options with origin", "https://client.example", "", http.StatusAccepted, true},
		{"options with requested method", "", "POST", http.StatusAccepted, true},
		{"trusted preflight", "https://client.example", "POST", http.StatusNoContent, false},
		{"untrusted preflight", "https://other.example", "POST", http.StatusForbidden, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reached := false
			router := gin.New()
			router.OPTIONS("/resource", Preflight(CORSOptions{ResolveOrigin: AllowedOrigins([]string{"https://client.example"})}), func(c *gin.Context) {
				reached = true
				c.Status(http.StatusAccepted)
			})
			request := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/resource", nil)
			request.Header.Set("Origin", tt.origin)
			request.Header.Set("Access-Control-Request-Method", tt.requestedMethod)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if recorder.Code != tt.status || reached != tt.reached {
				t.Fatalf("response = %d, reached = %v; want %d, %v", recorder.Code, reached, tt.status, tt.reached)
			}
			if tt.status == http.StatusForbidden && recorder.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("denied preflight exposes an allowed origin")
			}
		})
	}
}

type unreadCORSBody struct {
	t *testing.T
}

func (b unreadCORSBody) Read([]byte) (int, error) {
	b.t.Fatal("CORS read the request body")
	return 0, nil
}

func (unreadCORSBody) Close() error { return nil }

func TestCORSNeverReadsRequestBody(t *testing.T) {
	for _, origin := range []string{"https://client.example", "https://other.example"} {
		t.Run(origin, func(t *testing.T) {
			router := gin.New()
			router.POST("/resource", CORS(CORSOptions{ResolveOrigin: AllowedOrigins([]string{"https://client.example"}), AllowCredentials: true}), func(c *gin.Context) {
				if _, ok := c.Request.Body.(unreadCORSBody); !ok {
					t.Fatal("CORS replaced the request body")
				}
				c.Status(http.StatusAccepted)
			})
			request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/resource", nil)
			request.Body = unreadCORSBody{t: t}
			request.Header.Set("Origin", origin)
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			wantStatus := http.StatusAccepted
			if origin != "https://client.example" {
				wantStatus = http.StatusForbidden
			}
			if recorder.Code != wantStatus || !strings.Contains(strings.Join(recorder.Header().Values("Vary"), ","), "Origin") {
				t.Fatalf("response = %d, headers %v", recorder.Code, recorder.Header())
			}
			wantOrigin := origin
			if origin != "https://client.example" {
				wantOrigin = ""
			}
			if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != wantOrigin {
				t.Fatalf("allowed origin = %q, want %q", got, wantOrigin)
			}
		})
	}
}

func TestProtectCookieRequestsSourceEvidence(t *testing.T) {
	const trusted = "https://login.example"
	for _, tt := range []struct {
		name, method, origin, fetchSite, referer string
		allowed                                  bool
	}{
		{"safe get", http.MethodGet, "https://evil.example", "cross-site", "", true},
		{"safe head", http.MethodHead, "null", "cross-site", "", true},
		{"safe options", http.MethodOptions, "", "", "", true},
		{"trusted origin", http.MethodPost, trusted, "", "", true},
		{"same origin metadata", http.MethodPost, "", "same-origin", "", true},
		{"trusted referer", http.MethodPost, "", "", trusted + "/login?return_to=%2F", true},
		{"missing evidence", http.MethodPost, "", "", "", false},
		{"same site insufficient", http.MethodPost, "", "same-site", "", false},
		{"null origin", http.MethodPost, "null", "same-origin", trusted, false},
		{"malformed origin", http.MethodPost, "://invalid", "same-origin", trusted, false},
		{"untrusted origin", http.MethodPost, "https://evil.example", "same-origin", trusted, false},
		{"origin with path", http.MethodPost, trusted + "/path", "", "", false},
		{"trusted cross site", http.MethodPost, trusted, "cross-site", trusted, true},
		{"rogue same site", http.MethodPost, "https://evil.example", "same-site", trusted, false},
		{"untrusted referer", http.MethodPost, "", "", "https://evil.example/login", false},
		{"referer prefix trick", http.MethodPost, "", "", trusted + ".evil.example/login", false},
		{"unsafe put", http.MethodPut, "", "", "", false},
		{"unsafe delete", http.MethodDelete, "", "", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reached := false
			router := gin.New()
			router.Handle(tt.method, "/session", ProtectCookieRequests([]string{trusted}), func(c *gin.Context) {
				reached = true
				c.Status(http.StatusAccepted)
			})
			request := httptest.NewRequestWithContext(context.Background(), tt.method, "/session", nil)
			request.Body = unreadCORSBody{t: t}
			request.Header.Set("Origin", tt.origin)
			request.Header.Set("Sec-Fetch-Site", tt.fetchSite)
			request.Header.Set("Referer", tt.referer)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			wantStatus := http.StatusForbidden
			if tt.allowed {
				wantStatus = http.StatusAccepted
			}
			if recorder.Code != wantStatus || reached != tt.allowed {
				t.Fatalf("response = %d, reached = %v; want %d, %v", recorder.Code, reached, wantStatus, tt.allowed)
			}
		})
	}
}

func TestPreflightLeavesActualResponsesUntouched(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodOptions} {
		router := gin.New()
		router.Handle(method, "/token", Preflight(CORSOptions{ResolveOrigin: AnyOrigin}), func(c *gin.Context) {
			c.Status(http.StatusBadRequest)
		})
		request := httptest.NewRequestWithContext(t.Context(), method, "/token", nil)
		request.Body = unreadCORSBody{t: t}
		request.Header.Set("Origin", "https://app.example")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("ordinary request intercepted: %d", response.Code)
		}
		for key := range response.Header() {
			if strings.HasPrefix(key, "Access-Control-") {
				t.Fatalf("actual response inherited preflight policy: %v", response.Header())
			}
		}
	}
}

func TestAllowOriginChecksVerifiedClientPolicyBeforeBusiness(t *testing.T) {
	for _, tt := range []struct {
		name, origin string
		origins      []string
		allowed      bool
	}{
		{"nonbrowser", "", nil, true},
		{"registered", "https://app.example", []string{"https://app.example"}, true},
		{"unregistered", "https://rogue.example", []string{"https://app.example"}, false},
		{"empty policy", "https://app.example", nil, false},
		{"null", "null", []string{"null"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reached := false
			router := gin.New()
			router.POST("/token", func(c *gin.Context) {
				if !AllowOrigin(c, tt.origins) {
					return
				}
				reached = true
				c.Status(http.StatusAccepted)
			})
			request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", nil)
			request.Body = unreadCORSBody{t: t}
			request.Header.Set("Origin", tt.origin)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			want := http.StatusForbidden
			if tt.allowed {
				want = http.StatusAccepted
			}
			if reached != tt.allowed || response.Code != want {
				t.Fatalf("response = %d, business reached = %v", response.Code, reached)
			}
			if tt.origin != "" && !strings.Contains(strings.Join(response.Header().Values("Vary"), ","), "Origin") {
				t.Fatal("origin-dependent response missing Vary")
			}
			wantOrigin := ""
			if tt.allowed {
				wantOrigin = tt.origin
			}
			if response.Header().Get("Access-Control-Allow-Origin") != wantOrigin || response.Header().Get("Access-Control-Allow-Credentials") != "" {
				t.Fatalf("actual policy = %v", response.Header())
			}
			if wantOrigin != "" && (!strings.Contains(response.Header().Get("Access-Control-Expose-Headers"), "Location") || !strings.Contains(response.Header().Get("Access-Control-Expose-Headers"), "WWW-Authenticate")) {
				t.Fatal("client cannot read redirect or challenge headers")
			}
		})
	}
}

func TestCookieTrustRejectsWildcardAndNull(t *testing.T) {
	for _, origin := range []string{"https://app.example", "null"} {
		router := gin.New()
		router.POST("/session", ProtectCookieRequests([]string{"*", "null"}), func(c *gin.Context) { c.Status(http.StatusAccepted) })
		request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/session", nil)
		request.Header.Set("Origin", origin)
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("invalid credential trust accepted: %d", response.Code)
		}
	}
}
