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

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"

	"github.com/heliantheon/aegis/config"
	"github.com/heliantheon/aegis/internal/cache"
	"github.com/heliantheon/aegis/internal/provision"
	hermesv1 "github.com/heliantheon/aegis/internal/rpc/hermes/v1"
	"github.com/heliantheon/aegis/internal/types"
	"github.com/heliantheon/aegis/models"
	"github.com/heliantheon/aegis/rpc/hermes"
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
		wantErr bool
	}{
		{name: "standard request"},
		{name: "space delimited parameters", change: func(q url.Values) {
			q.Set("scope", "  openid\tprofile\nemail ")
			q.Set("prompt", " login ")
		}},
		{name: "multi audience extension", change: func(q url.Values) {
			q.Set("audiences", `{"iris":{"scope":"openid profile"},"hermes":{"scope":"read"}}`)
		}},
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
		{name: "invalid audience object", change: func(q url.Values) { q.Set("audiences", `[]`) }, wantErr: true},
		{name: "empty audience object", change: func(q url.Values) { q.Set("audiences", `{}`) }, wantErr: true},
		{name: "null audience object", change: func(q url.Values) { q.Set("audiences", `null`) }, wantErr: true},
	} {
		for _, source := range []string{"query", "form"} {
			t.Run(tt.name+"/"+source, func(t *testing.T) {
				q := standardAuthorizationQuery()
				q.Set("prompt", "login")
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
					Prompt:              []string{"login"},
					Nonce:               "nonce",
					LoginHint:           "user@example.com",
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
	query.Set("prompt", "login")
	query.Set("login_hint", "user@example.com")
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
		if !reflect.DeepEqual(req.Params, wantParams) {
			t.Fatalf("query parameters = %+v", req.Params)
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
		{name: "login prompt", change: func(r *types.AuthRequest) { r.Prompt = []string{"login"} }},
		{name: "silent prompt rejected", change: func(r *types.AuthRequest) { r.Prompt = []string{"none"} }, wantErr: true},
		{name: "consent prompt rejected", change: func(r *types.AuthRequest) { r.Prompt = []string{"consent"} }, wantErr: true},
		{name: "hybrid response", change: func(r *types.AuthRequest) { r.ResponseType = "code id_token" }, wantErr: true},
		{name: "implicit response", change: func(r *types.AuthRequest) { r.ResponseType = "token" }, wantErr: true},
		{name: "empty response", change: func(r *types.AuthRequest) { r.ResponseType = "" }, wantErr: true},
		{name: "plain challenge", change: func(r *types.AuthRequest) { r.CodeChallengeMethod = "plain" }, wantErr: true},
		{name: "short challenge", change: func(r *types.AuthRequest) { r.CodeChallenge = "abc" }, wantErr: true},
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
	case hermesv1.ResourceService_GetApplicationServiceRelations_FullMethodName:
		return nil
	case hermesv1.ProvisionService_GetService_FullMethodName:
		service, ok := reply.(*hermesv1.Service)
		if !ok {
			return errors.New("unexpected service response type")
		}
		service.ServiceId = "iris"
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
	return &Handler{provisionSvc: provision.NewService(manager)}
}

func TestAuthorizeIsolatesGetAndPostParameterSources(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := authorizationHandler(t, &authorizationRegistry{})
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		query := standardAuthorizationQuery()
		query.Set("audience", "iris")
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
			if recorder.Code != http.StatusForbidden || recorder.Header().Get("Location") != "" || !strings.Contains(recorder.Body.String(), `"error":"access_denied"`) {
				t.Fatalf("POST action error = %d %q %s", recorder.Code, recorder.Header().Get("Location"), recorder.Body.String())
			}
			continue
		}
		u, err := url.Parse(recorder.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if recorder.Code != http.StatusSeeOther || u.Host != "atlas.example" || u.Query().Get("tenant") != "one" || u.Query().Get("state") != query.Get("state") || u.Query().Get("error") != "access_denied" {
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
		{name: "invalid audiences", change: func(q url.Values) { q.Set("audiences", "[]") }},
		{name: "unsupported response type", change: func(q url.Values) { q.Set("response_type", "token") }},
		{name: "invalid code challenge", change: func(q url.Values) { q.Set("code_challenge", "bad") }},
		{name: "unsupported prompt", change: func(q url.Values) { q.Set("prompt", "none") }},
		{name: "fragment redirect", change: func(q url.Values) { q.Set("redirect_uri", "https://atlas.example/callback#frag") }},
		{name: "malformed query", malformed: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			registry := &authorizationRegistry{reject: tt.reject}
			h := authorizationHandler(t, registry)
			query := standardAuthorizationQuery()
			query.Set("audience", "iris")
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
			if recorder.Code != http.StatusSeeOther || u.Host != "atlas.example" || u.Query().Get("error") != "access_denied" || u.Query().Get("state") != query.Get("state") {
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
		{gin.MIMEPOSTForm, "client_id=atlas&redirect_uri=https%3A%2F%2Fevil.example%2Fcallback&audiences=[]", 0},
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
		query.Set("audiences", "[]")
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
