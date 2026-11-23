package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"

	"github.com/heliantheon/aegis/config"
	"github.com/heliantheon/aegis/internal/cache"
	hermesv1 "github.com/heliantheon/aegis/internal/rpc/hermes/v1"
	"github.com/heliantheon/aegis/internal/types"
	"github.com/heliantheon/aegis/models"
	"github.com/heliantheon/aegis/rpc/hermes"
	pkgredis "github.com/heliantheon/common/redis"
)

func standardAuthorizationQuery() url.Values {
	return url.Values{
		"client_id":             {"atlas"},
		"redirect_uri":          {"https://atlas.example/callback?tenant=one"},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {"state + / ?"},
		"nonce":                 {"nonce"},
		"code_challenge":        {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		"code_challenge_method": {"S256"},
	}
}

func authorizeQueryContext(query url.Values) *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/authorize?"+query.Encode(), nil)
	return c
}

func TestBindAuthorizeParameters(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tt := range []struct {
		name    string
		change  func(url.Values)
		maxAge  uint64
		wantErr bool
	}{
		{name: "standard request"},
		{name: "space delimited parameters", change: func(q url.Values) {
			q.Set("scope", "  openid\tprofile\nemail ")
			q.Set("prompt", " login \tconsent ")
		}},
		{name: "multi audience extension", change: func(q url.Values) {
			q.Set("audiences", `{"iris":{"scope":"openid profile"},"hermes":{"scope":"read"}}`)
		}},
		{name: "explicit zero max age", change: func(q url.Values) { q.Set("max_age", "0") }},
		{name: "positive max age", change: func(q url.Values) { q.Set("max_age", "3600") }, maxAge: 3600},
		{name: "missing client", change: func(q url.Values) { q.Del("client_id") }, wantErr: true},
		{name: "empty client", change: func(q url.Values) { q.Set("client_id", "") }, wantErr: true},
		{name: "missing redirect", change: func(q url.Values) { q.Del("redirect_uri") }, wantErr: true},
		{name: "empty redirect", change: func(q url.Values) { q.Set("redirect_uri", "") }, wantErr: true},
		{name: "missing response type", change: func(q url.Values) { q.Del("response_type") }, wantErr: true},
		{name: "empty response type", change: func(q url.Values) { q.Set("response_type", "") }, wantErr: true},
		{name: "repeated state", change: func(q url.Values) { q.Add("state", "attacker") }, wantErr: true},
		{name: "repeated redirect", change: func(q url.Values) { q.Add("redirect_uri", "https://evil.example") }, wantErr: true},
		{name: "repeated extension", change: func(q url.Values) {
			q.Add("resource", "one")
			q.Add("resource", "two")
		}, wantErr: true},
		{name: "negative max age", change: func(q url.Values) { q.Set("max_age", "-1") }, wantErr: true},
		{name: "fractional max age", change: func(q url.Values) { q.Set("max_age", "0.1") }, wantErr: true},
		{name: "empty max age", change: func(q url.Values) { q.Set("max_age", "") }, wantErr: true},
		{name: "padded max age", change: func(q url.Values) { q.Set("max_age", " 1 ") }, wantErr: true},
		{name: "whitespace max age", change: func(q url.Values) { q.Set("max_age", " ") }, wantErr: true},
		{name: "positive sign max age", change: func(q url.Values) { q.Set("max_age", "+1") }, wantErr: true},
		{name: "overflow max age", change: func(q url.Values) { q.Set("max_age", "18446744073709551616") }, wantErr: true},
		{name: "invalid audience object", change: func(q url.Values) { q.Set("audiences", `[]`) }, wantErr: true},
		{name: "empty audience object", change: func(q url.Values) { q.Set("audiences", `{}`) }, wantErr: true},
		{name: "null audience object", change: func(q url.Values) { q.Set("audiences", `null`) }, wantErr: true},
	} {
		for _, source := range []string{"query", "form"} {
			t.Run(tt.name+"/"+source, func(t *testing.T) {
				q := standardAuthorizationQuery()
				q.Set("prompt", "login consent")
				q.Set("login_hint", "user@example.com")
				if tt.change != nil {
					tt.change(q)
				}
				var req types.AuthRequest
				var err error
				if source == "query" {
					err = bindAuthorizeQuery(authorizeQueryContext(q), &req)
				} else {
					c, _ := gin.CreateTestContext(httptest.NewRecorder())
					c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/authorize?client_id=attacker&redirect_uri=https://evil.example", strings.NewReader(q.Encode()))
					c.Request.Header.Set("Content-Type", gin.MIMEPOSTForm)
					err = bindAuthorizeBody(c, &req)
				}
				if (err != nil) != tt.wantErr {
					t.Fatalf("authorization binding error = %v, wantErr %v", err, tt.wantErr)
				}
				if err != nil {
					return
				}
				want := types.AuthorizeRequestBase{
					ResponseType:        "code",
					ClientID:            "atlas",
					RedirectURI:         "https://atlas.example/callback?tenant=one",
					CodeChallenge:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					CodeChallengeMethod: "S256",
					State:               "state + / ?",
					Scope:               []string{"openid", "profile", "email"},
					Prompt:              []string{"login", "consent"},
					Nonce:               "nonce",
					LoginHint:           "user@example.com",
				}
				if q.Has("max_age") {
					want.MaxAge = &tt.maxAge
				}
				if !reflect.DeepEqual(req.AuthorizeRequestBase, want) {
					t.Fatalf("bound standard request = %+v, want %+v", req.AuthorizeRequestBase, want)
				}
				if audience := req.Audiences["iris"]; q.Has("audiences") && (audience == nil || audience.Scope != "openid profile") {
					t.Fatalf("audiences = %+v", req.Audiences)
				}
			})
		}
	}
}

func TestAuthorizationDecodersIsolateSourcesAndIgnoreMethod(t *testing.T) {
	gin.SetMode(gin.TestMode)
	query := standardAuthorizationQuery()
	query.Set("audience", "iris")
	query.Set("prompt", "login consent")
	query.Set("login_hint", "user@example.com")
	query.Set("max_age", "0")
	query.Set("resource", "https://api.example/resource?tenant=one&name=a+b")
	query.Set("custom_parameter", "custom + / ?")
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequestWithContext(context.Background(), method, "/api/authorize?"+query.Encode(), strings.NewReader("invalid body"))
		var req types.AuthRequest
		err := bindAuthorizeQuery(c, &req)
		if err != nil || req.ClientID != "atlas" {
			t.Fatalf("%s query decoder = %+v, error = %v", method, req, err)
		}
		wantParams := map[string]any{
			"resource":         query.Get("resource"),
			"custom_parameter": "custom + / ?",
		}
		if !reflect.DeepEqual(req.Params, wantParams) || req.MaxAge == nil || *req.MaxAge != 0 {
			t.Fatalf("query parameters = %+v, max_age = %v", req.Params, req.MaxAge)
		}
		flowJSON, err := json.Marshal(types.AuthFlow{Request: &req})
		if err != nil {
			t.Fatal(err)
		}
		var flow types.AuthFlow
		if err := json.Unmarshal(flowJSON, &flow); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(flow.Request, &req) {
			t.Fatalf("stored request = %+v, want %+v", flow.Request, req)
		}
		encoded, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		for _, body := range []struct {
			contentType string
			value       string
		}{{gin.MIMEJSON, string(encoded)}, {gin.MIMEPOSTForm, query.Encode()}} {
			c.Request = httptest.NewRequestWithContext(context.Background(), method, "/api/authorize?client_id=attacker&redirect_uri=https://evil.example", strings.NewReader(body.value))
			c.Request.Header.Set("Content-Type", body.contentType)
			var bound types.AuthRequest
			err = bindAuthorizeBody(c, &bound)
			if err != nil || !reflect.DeepEqual(bound, req) {
				t.Fatalf("%s %s body decoder = %+v, error = %v", method, body.contentType, bound, err)
			}
		}
	}
}

func TestValidateStandardAuthorizationParameters(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tt := range []struct {
		name    string
		change  func(*types.AuthRequest)
		wantErr bool
	}{
		{name: "code with S256"},
		{name: "login and consent", change: func(r *types.AuthRequest) { r.Prompt = []string{"login", "consent"} }},
		{name: "silent only", change: func(r *types.AuthRequest) { r.Prompt = []string{"none"} }},
		{name: "hybrid response", change: func(r *types.AuthRequest) { r.ResponseType = "code id_token" }, wantErr: true},
		{name: "implicit response", change: func(r *types.AuthRequest) { r.ResponseType = "token" }, wantErr: true},
		{name: "empty response", change: func(r *types.AuthRequest) { r.ResponseType = "" }, wantErr: true},
		{name: "plain challenge", change: func(r *types.AuthRequest) { r.CodeChallengeMethod = "plain" }, wantErr: true},
		{name: "short challenge", change: func(r *types.AuthRequest) { r.CodeChallenge = "abc" }, wantErr: true},
		{name: "none and login", change: func(r *types.AuthRequest) { r.Prompt = []string{"none", "login"} }, wantErr: true},
		{name: "none and consent", change: func(r *types.AuthRequest) { r.Prompt = []string{"none", "consent"} }, wantErr: true},
		{name: "unknown prompt", change: func(r *types.AuthRequest) { r.Prompt = []string{"select_account"} }, wantErr: true},
		{name: "duplicate prompt", change: func(r *types.AuthRequest) { r.Prompt = []string{"login", "login"} }, wantErr: true},
		{name: "null audience", change: func(r *types.AuthRequest) {
			r.Audience = ""
			r.Audiences = map[string]*types.RequestAudienceScope{"iris": nil}
		}, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var req types.AuthRequest
			if err := bindAuthorizeQuery(authorizeQueryContext(standardAuthorizationQuery()), &req); err != nil {
				t.Fatal(err)
			}
			req.Audience = "iris"
			if tt.change != nil {
				tt.change(&req)
			}
			if err := validateAuthorizeRequest(&req); (err != nil) != tt.wantErr {
				t.Fatalf("validateAuthorizeRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthorizationRedirectMustMatchRegistrationExactly(t *testing.T) {
	t.Parallel()
	registered := `["https://client.example/callback?tenant=one"]`
	app := &models.Application{AllowedRedirectURIs: &registered}
	for _, tt := range []struct {
		uri  string
		want bool
	}{
		{"https://client.example/callback?tenant=one", true},
		{"https://client.example/callback/?tenant=one", false},
		{"https://CLIENT.example/callback?tenant=one", false},
		{"https://client.example/callback?tenant=one#fragment", false},
		{"https://client.example/callback?tenant=two", false},
		{"https://client.example.evil/callback?tenant=one", false},
	} {
		if got := validAuthorizationRedirect(app, tt.uri); got != tt.want {
			t.Errorf("validAuthorizationRedirect(%q) = %v, want %v", tt.uri, got, tt.want)
		}
	}
}

type authorizationRegistry struct {
	grpc.ClientConnInterface
	lookups int
	reject  bool
}

func (r *authorizationRegistry) Invoke(_ context.Context, method string, _ any, reply any, _ ...grpc.CallOption) error {
	switch method {
	case hermesv1.ProvisionService_GetApplication_FullMethodName:
		r.lookups++
		if r.reject {
			return errors.New("application not registered")
		}
		application, ok := reply.(*hermesv1.Application)
		if !ok {
			return errors.New("unexpected application response type")
		}
		application.AppId = "atlas"
		application.AllowedRedirectUris = []string{standardAuthorizationQuery().Get("redirect_uri")}
		return nil
	case hermesv1.KeyService_GetKeys_FullMethodName:
		return nil
	default:
		return errors.New("unexpected authorization registry request: " + method)
	}
}

func authorizationHandler(t *testing.T, registry *authorizationRegistry) *Handler {
	t.Helper()
	manager := cache.NewManager(hermes.New(registry), nil)
	t.Cleanup(manager.Close)
	return &Handler{cache: manager}
}

func TestAuthorizeIsolatesGetAndPostParameterSources(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := authorizationHandler(t, &authorizationRegistry{})
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		query := standardAuthorizationQuery()
		query.Set("response_type", "token")
		body := `{"ignored":`
		if method == http.MethodPost {
			var req types.AuthRequest
			if err := bindAuthorizeQuery(authorizeQueryContext(query), &req); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			body = string(encoded)
			query.Set("redirect_uri", "https://evil.example/callback")
		}
		request := httptest.NewRequestWithContext(context.Background(), method, "/api/authorize?"+query.Encode(), strings.NewReader(body))
		request.Header.Set("Content-Type", gin.MIMEJSON)
		recorder := httptest.NewRecorder()
		router := gin.New()
		router.Handle(method, "/api/authorize", h.Authorize)
		router.ServeHTTP(recorder, request)
		if method == http.MethodPost {
			if recorder.Code != http.StatusBadRequest || recorder.Header().Get("Location") != "" || !strings.Contains(recorder.Body.String(), `"error":"unsupported_response_type"`) {
				t.Fatalf("POST action error = %d %q %s", recorder.Code, recorder.Header().Get("Location"), recorder.Body.String())
			}
			continue
		}
		u, err := url.Parse(recorder.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if recorder.Code != http.StatusSeeOther || u.Host != "atlas.example" || u.Query().Get("tenant") != "one" || u.Query().Get("state") != query.Get("state") || u.Query().Get("error") != "unsupported_response_type" {
			t.Fatalf("method=%s response = %d %s", method, recorder.Code, u)
		}
	}
}

func TestAuthorizationErrorsRespectBindingAndRedirectBoundaries(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tt := range []struct {
		name      string
		change    func(url.Values)
		reject    bool
		malformed bool
		redirect  bool
		lookup    bool
	}{
		{name: "registered redirect", redirect: true, lookup: true},
		{name: "unregistered redirect", change: func(q url.Values) { q.Set("redirect_uri", "https://evil.example/callback") }, lookup: true},
		{name: "unknown client", reject: true, lookup: true},
		{name: "duplicate client", change: func(q url.Values) { q.Add("client_id", "other") }},
		{name: "duplicate redirect", change: func(q url.Values) { q.Add("redirect_uri", "https://evil.example/callback") }},
		{name: "duplicate state", change: func(q url.Values) { q.Add("state", "duplicate") }},
		{name: "missing client", change: func(q url.Values) { q.Del("client_id") }},
		{name: "empty client", change: func(q url.Values) { q.Set("client_id", "") }},
		{name: "missing redirect", change: func(q url.Values) { q.Del("redirect_uri") }},
		{name: "empty redirect", change: func(q url.Values) { q.Set("redirect_uri", "") }},
		{name: "missing response type", change: func(q url.Values) { q.Del("response_type") }},
		{name: "empty response type", change: func(q url.Values) { q.Set("response_type", "") }},
		{name: "invalid max age", change: func(q url.Values) { q.Set("max_age", "abc") }},
		{name: "malformed query", malformed: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			registry := &authorizationRegistry{reject: tt.reject}
			h := authorizationHandler(t, registry)
			query := standardAuthorizationQuery()
			query.Set("response_type", "token")
			if tt.change != nil {
				tt.change(query)
			}
			rawQuery := query.Encode()
			if tt.malformed {
				rawQuery += "&invalid=%zz"
			}
			recorder := httptest.NewRecorder()
			router := gin.New()
			router.GET("/api/authorize", h.Authorize)
			router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/authorize?"+rawQuery, nil))
			if (registry.lookups > 0) != tt.lookup {
				t.Fatalf("registry lookups = %d, want lookup %v", registry.lookups, tt.lookup)
			}
			if !tt.redirect {
				if recorder.Code < 400 || recorder.Header().Get("Location") != "" {
					t.Fatalf("unvalidated error = %d %q", recorder.Code, recorder.Header().Get("Location"))
				}
				if !tt.lookup && recorder.Code != http.StatusBadRequest {
					t.Fatalf("binding error status = %d, want 400", recorder.Code)
				}
				return
			}
			u, err := url.Parse(recorder.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if recorder.Code != http.StatusSeeOther || u.Host != "atlas.example" || u.Query().Get("error") != "unsupported_response_type" || u.Query().Get("state") != query.Get("state") {
				t.Fatalf("validated error = %d %s", recorder.Code, u)
			}
		})
	}
}

func TestAuthorizationBodyBindingErrorsRejectUnregisteredRedirects(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tt := range []struct {
		contentType string
		body        string
		lookups     int
	}{
		{gin.MIMEJSON, `{"client_id":"atlas","redirect_uri":"https://evil.example/callback","response_type":`, 0},
		{gin.MIMEPOSTForm, "client_id=atlas&redirect_uri=https%3A%2F%2Fevil.example%2Fcallback&max_age=-1", 0},
	} {
		registry := &authorizationRegistry{}
		h := authorizationHandler(t, registry)
		request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/authorize?"+standardAuthorizationQuery().Encode(), strings.NewReader(tt.body))
		request.Header.Set("Content-Type", tt.contentType)
		recorder := httptest.NewRecorder()
		router := gin.New()
		router.POST("/api/authorize", h.Authorize)
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest || recorder.Header().Get("Location") != "" || registry.lookups != tt.lookups {
			t.Fatalf("%s body error = %d %q, registry lookups = %d, want %d", tt.contentType, recorder.Code, recorder.Header().Get("Location"), registry.lookups, tt.lookups)
		}
	}
}

func TestAuthorizationBindingErrorsStopBeforeRegistry(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		registry := &authorizationRegistry{}
		h := authorizationHandler(t, registry)
		query := standardAuthorizationQuery()
		query.Set("max_age", "invalid")
		target := "/api/authorize?" + query.Encode()
		body := "ignored body"
		if method == http.MethodPost {
			target = "/api/authorize?client_id=attacker&redirect_uri=https://evil.example"
			body = query.Encode()
		}
		request := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
		request.Header.Set("Content-Type", gin.MIMEPOSTForm)
		recorder := httptest.NewRecorder()
		router := gin.New()
		router.Handle(method, "/api/authorize", h.Authorize)
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest || recorder.Header().Get("Location") != "" || registry.lookups != 0 || !strings.Contains(recorder.Body.String(), `"error":"invalid_request"`) {
			t.Fatalf("%s binding error = %d %q %s, registry lookups = %d", method, recorder.Code, recorder.Header().Get("Location"), recorder.Body.String(), registry.lookups)
		}
	}
}

func TestAuthorizationNavigationPreservesPostAction(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tt := range []struct {
		method string
		status int
	}{
		{http.MethodGet, http.StatusSeeOther},
		{http.MethodPost, http.StatusMultipleChoices},
	} {
		recorder := httptest.NewRecorder()
		router := gin.New()
		router.Handle(tt.method, "/api/authorize", func(c *gin.Context) {
			forwardNext(c, &types.AuthFlow{State: types.FlowStateInitialized}, authorizationRedirect)
		})
		router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), tt.method, "/api/authorize", nil))
		if recorder.Code != tt.status || recorder.Header().Get("Location") != config.GetEndpointLogin() {
			t.Fatalf("%s navigation = %d %q", tt.method, recorder.Code, recorder.Header().Get("Location"))
		}
	}
}

func TestDiscoveryMetadata(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/discovery", (&Handler{}).Discovery)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/discovery", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("discovery status = %d", recorder.Code)
	}
	var metadata map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	issuer := config.GetIssuer()
	if metadata["issuer"] != issuer || metadata["authorization_endpoint"] != issuer+"/authorize" || metadata["jwks_uri"] != issuer+"/jwks" || metadata["userinfo_endpoint"] != issuer+"/profile" {
		t.Fatalf("discovery metadata = %v", metadata)
	}
}

type ssoAuthTimeRedis struct {
	pkgredis.Client
	hashes map[string]map[string]string
	ttls   map[string]time.Duration
}

func (r *ssoAuthTimeRedis) HGetAll(_ context.Context, key string) (map[string]string, error) {
	result := make(map[string]string)
	for domain, value := range r.hashes[key] {
		result[domain] = value
	}
	return result, nil
}

func (r *ssoAuthTimeRedis) HSet(_ context.Context, key string, values ...any) error {
	fields, ok := values[0].(map[string]string)
	if !ok {
		return errors.New("unexpected SSO metadata value")
	}
	r.hashes[key] = fields
	return nil
}

func (r *ssoAuthTimeRedis) Expire(_ context.Context, key string, ttl time.Duration) error {
	r.ttls[key] = ttl
	return nil
}

func TestSSORenewalPreservesOriginalDomainAuthenticationTimes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	original := map[string]string{"platform": "1700000000", "consumer": "1700000010"}
	redis := &ssoAuthTimeRedis{hashes: map[string]map[string]string{ssoAuthTimeKey("old"): original}, ttls: make(map[string]time.Duration)}
	manager := cache.NewManager(nil, redis)
	defer manager.Close()
	h := &Handler{cache: manager}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/authorize", nil)
	c.Request.AddCookie(&http.Cookie{Name: config.GetSSOCookieName(), Value: "old", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	h.copySSOAuthTimes(c, context.Background(), "renewed", "", time.Time{})
	if got := redis.hashes[ssoAuthTimeKey("renewed")]; !reflect.DeepEqual(got, original) {
		t.Fatalf("renewal auth times = %v, want %v", got, original)
	}
	if redis.ttls[ssoAuthTimeKey("renewed")] != config.GetSSOTTL() {
		t.Fatal("renewal metadata TTL does not follow the SSO lifetime")
	}
	h.copySSOAuthTimes(c, context.Background(), "reauthenticated", "platform", time.Unix(1700000099, 0))
	want := map[string]string{"platform": "1700000099", "consumer": "1700000010"}
	if got := redis.hashes[ssoAuthTimeKey("reauthenticated")]; !reflect.DeepEqual(got, want) {
		t.Fatalf("reauthentication auth times = %v, want %v", got, want)
	}
}

func TestAuthorizationCodeRedirectPreservesRegisteredQueryAndState(t *testing.T) {
	t.Parallel()
	location := buildAuthCodeRedirectURL("https://client.example/callback?tenant=one", &cache.AuthorizationCode{Code: "code + / ?", State: "state + / ?"})
	u, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("tenant") != "one" || u.Query().Get("code") != "code + / ?" || u.Query().Get("state") != "state + / ?" {
		t.Fatalf("callback query = %v", u.Query())
	}
}
