package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"

	"github.com/heliantheon/aegis-go/utilities/key"
	pkgtoken "github.com/heliantheon/aegis-go/utilities/token"
	"github.com/heliantheon/aegis/config"
	"github.com/heliantheon/aegis/internal/authenticate"
	"github.com/heliantheon/aegis/internal/authenticator"
	"github.com/heliantheon/aegis/internal/authenticator/idp/google"
	"github.com/heliantheon/aegis/internal/authorize"
	"github.com/heliantheon/aegis/internal/cache"
	hermesv1 "github.com/heliantheon/aegis/internal/rpc/hermes/v1"
	"github.com/heliantheon/aegis/internal/token"
	"github.com/heliantheon/aegis/internal/types"
	"github.com/heliantheon/aegis/internal/user"
	"github.com/heliantheon/aegis/models"
	"github.com/heliantheon/aegis/rpc/hermes"
)

// This adapter models Redis storage only; consent decisions, serialization,
// token signing/verification, flow persistence, and code issuance stay real.
type consentRedis struct {
	ssoAuthTimeRedis
	values   map[string]string
	sets     map[string]map[string]bool
	readErr  error
	grantErr error
	grants   int
}

func newConsentRedis() *consentRedis {
	return &consentRedis{
		ssoAuthTimeRedis: ssoAuthTimeRedis{hashes: make(map[string]map[string]string), ttls: make(map[string]time.Duration)},
		values:           make(map[string]string), sets: make(map[string]map[string]bool),
	}
}

func (r *consentRedis) Get(_ context.Context, key string) (string, error) {
	value, ok := r.values[key]
	if !ok {
		return "", errors.New("missing key")
	}
	return value, nil
}

func (r *consentRedis) Set(_ context.Context, key string, value any, ttl time.Duration) error {
	text, ok := value.(string)
	if !ok {
		return errors.New("unexpected Redis string value")
	}
	r.values[key], r.ttls[key] = text, ttl
	return nil
}

func (r *consentRedis) HGet(_ context.Context, key, field string) (string, error) {
	return r.hashes[key][field], nil
}

func (r *consentRedis) SMembers(_ context.Context, key string) ([]string, error) {
	if r.readErr != nil {
		return nil, r.readErr
	}
	var members []string
	for member := range r.sets[key] {
		members = append(members, member)
	}
	return members, nil
}

func (r *consentRedis) Eval(_ context.Context, _ string, keys []string, args ...any) (any, error) {
	r.grants++
	if r.grantErr != nil {
		return nil, r.grantErr
	}
	if len(keys) != 1 || len(args) < 2 {
		return nil, errors.New("unexpected consent script arguments")
	}
	milliseconds, ok := args[0].(int64)
	if !ok {
		return nil, errors.New("unexpected consent expiration")
	}
	if r.sets[keys[0]] == nil {
		r.sets[keys[0]] = make(map[string]bool)
	}
	for _, arg := range args[1:] {
		member, ok := arg.(string)
		if !ok {
			return nil, errors.New("unexpected consent fact")
		}
		r.sets[keys[0]][member] = true
	}
	r.ttls[keys[0]] = time.Duration(milliseconds) * time.Millisecond
	return int64(1), nil
}

func consentTestFlow() *types.AuthFlow {
	flow := types.NewAuthFlow(&types.AuthRequest{
		AuthorizeRequestBase: types.AuthorizeRequestBase{ClientID: "atlas", RedirectURI: standardAuthorizationQuery().Get("redirect_uri"), Scope: []string{"openid", "profile"}},
		Audience:             "iris",
	}, time.Hour, time.Hour)
	flow.Application = &models.Application{AppID: "atlas", DomainID: "platform"}
	flow.User = &models.UserWithDecrypted{User: models.User{OpenID: "user-one"}}
	flow.State = types.FlowStateAuthenticated
	flow.Service = &models.Service{ServiceID: "iris"}
	flow.Connection = "google"
	flow.ConnectionMap = map[string]*types.ConnectionConfig{"google": {Type: types.ConnTypeIDP}}
	return flow
}

func TestConsentApprovalReuseAndIsolation(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*types.AuthFlow)
		want   bool
	}{
		{name: "same request"},
		{name: "subset", change: func(f *types.AuthFlow) { f.Request.Scope = []string{"openid"} }},
		{name: "expanded claim", change: func(f *types.AuthFlow) { f.Request.Scope = append(f.Request.Scope, "email") }, want: true},
		{name: "new single audience", change: func(f *types.AuthFlow) { f.Request.Audience = "other" }, want: true},
		{name: "new user", change: func(f *types.AuthFlow) { f.User.OpenID = "user-two" }, want: true},
		{name: "new application", change: func(f *types.AuthFlow) { f.Request.ClientID = "other"; f.Application.AppID = "other" }, want: true},
		{name: "new domain", change: func(f *types.AuthFlow) { f.Application.DomainID = "consumer" }, want: true},
		{name: "forced consent", change: func(f *types.AuthFlow) { f.Request.Prompt = []string{types.PromptConsent} }, want: true},
		{name: "approved current flow overrides forced consent", change: func(f *types.AuthFlow) { f.Request.Prompt = []string{types.PromptConsent}; f.ConsentGranted = true }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			redis := newConsentRedis()
			manager := cache.NewManager(nil, redis)
			defer manager.Close()
			if err := manager.GrantConsent(context.Background(), "platform", "user-one", "atlas", map[string][]string{"": {"openid", "profile"}, "iris": {"openid", "profile"}}, config.GetSSOTTL()); err != nil {
				t.Fatal(err)
			}
			flow := consentTestFlow()
			if tt.change != nil {
				tt.change(flow)
			}
			got, err := (&Handler{cache: manager}).requiresConsent(context.Background(), flow)
			if err != nil || got != tt.want {
				t.Fatalf("requiresConsent() = %v, %v; want %v, nil", got, err, tt.want)
			}
		})
	}
}

func TestConsentRequiresEveryResourceScope(t *testing.T) {
	for _, tt := range []struct {
		name      string
		audiences map[string]*types.RequestAudienceScope
		want      bool
	}{
		{"approved resource", map[string]*types.RequestAudienceScope{"iris": {Scope: "openid read write"}}, false},
		{"resource subset", map[string]*types.RequestAudienceScope{"iris": {Scope: "openid read"}}, false},
		{"expanded resource scope", map[string]*types.RequestAudienceScope{"iris": {Scope: "openid admin"}}, true},
		{"same scope new resource", map[string]*types.RequestAudienceScope{"other": {Scope: "openid read"}}, true},
		{"additional resource", map[string]*types.RequestAudienceScope{"iris": {Scope: "openid read"}, "other": {Scope: "read"}}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			manager := cache.NewManager(nil, newConsentRedis())
			defer manager.Close()
			if err := manager.GrantConsent(context.Background(), "platform", "user-one", "atlas", map[string][]string{"iris": {"openid", "read", "write"}}, time.Hour); err != nil {
				t.Fatal(err)
			}
			flow := consentTestFlow()
			flow.Request.Scope, flow.Request.Audience, flow.Request.Audiences = nil, "", tt.audiences
			got, err := (&Handler{cache: manager}).requiresConsent(context.Background(), flow)
			if err != nil || got != tt.want {
				t.Fatalf("requiresConsent() = %v, %v; want %v, nil", got, err, tt.want)
			}
		})
	}
}

func TestConsentMissingApprovalAndReadFailure(t *testing.T) {
	redis := newConsentRedis()
	manager := cache.NewManager(nil, redis)
	defer manager.Close()
	h := &Handler{cache: manager}
	flow := consentTestFlow()
	if required, err := h.requiresConsent(context.Background(), flow); err != nil || !required {
		t.Fatalf("missing approval = %v, %v", required, err)
	}
	redis.readErr = errors.New("Redis unavailable")
	if _, err := h.requiresConsent(context.Background(), flow); err == nil {
		t.Fatal("consent lookup failure accepted")
	}
	flow.ConsentGranted = true
	if required, err := h.requiresConsent(context.Background(), flow); err != nil || required {
		t.Fatalf("approved current flow = %v, %v", required, err)
	}
	flow.ConsentGranted = false
	flow.Request.Scope = []string{"read"}
	if required, err := h.requiresConsent(context.Background(), flow); err != nil || required {
		t.Fatalf("legacy OAuth request = %v, %v", required, err)
	}
}

type consentRegistry struct{ grpc.ClientConnInterface }

func (r *consentRegistry) Invoke(_ context.Context, method string, _ any, reply any, _ ...grpc.CallOption) error {
	switch method {
	case hermesv1.ProvisionService_GetApplication_FullMethodName:
		app, ok := reply.(*hermesv1.Application)
		if !ok {
			return errors.New("unexpected application response")
		}
		app.AppId, app.DomainId = "atlas", "platform"
		app.AllowedRedirectUris = []string{standardAuthorizationQuery().Get("redirect_uri")}
	case hermesv1.KeyService_GetKeys_FullMethodName:
	case hermesv1.ProvisionService_GetService_FullMethodName:
		service, ok := reply.(*hermesv1.Service)
		if !ok {
			return errors.New("unexpected service response")
		}
		service.ServiceId, service.DomainId = "iris", "platform"
	case hermesv1.ResourceService_GetApplicationServiceRelations_FullMethodName:
		relations, ok := reply.(*hermesv1.ApplicationServiceRelationList)
		if !ok {
			return errors.New("unexpected relation response")
		}
		relations.Relations = []*hermesv1.ApplicationServiceRelation{{AppId: "atlas", ServiceId: "iris"}}
	case hermesv1.ProvisionService_GetApplicationIDPConfigs_FullMethodName:
		configs, ok := reply.(*hermesv1.ApplicationIDPConfigList)
		if !ok {
			return errors.New("unexpected IDP config response")
		}
		configs.Configs = []*hermesv1.ApplicationIDPConfig{{AppId: "atlas", Type: "google"}}
	case hermesv1.UserService_GetDecryptedUser_FullMethodName:
		user, ok := reply.(*hermesv1.DecryptedUser)
		if !ok {
			return errors.New("unexpected user response")
		}
		user.User = &hermesv1.User{Openid: "user-one"}
	default:
		return errors.New("unexpected consent fixture RPC: " + method)
	}
	return nil
}

func consentHTTPHandler(t *testing.T) (*Handler, *consentRedis) {
	t.Helper()
	redis := newConsentRedis()
	client := hermes.New(&consentRegistry{})
	manager := cache.NewManager(client, redis)
	var previous []authenticator.Authenticator
	if registry := authenticator.GlobalRegistry(); registry != nil {
		previous = registry.All()
	}
	registry := authenticator.NewRegistry()
	for _, registered := range previous {
		registry.Register(registered)
	}
	registry.Register(authenticate.NewIDPAuthenticator(google.NewProvider(manager)))
	t.Cleanup(func() {
		restored := authenticator.NewRegistry()
		for _, registered := range previous {
			restored.Register(registered)
		}
	})
	t.Cleanup(manager.Close)
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	provider := func(material []byte) key.Provider {
		return key.SingleOf(func(context.Context, string) ([]byte, error) { return material, nil })
	}
	tokenSvc := token.NewService(manager, provider(privateKey), provider(privateKey[ed25519.SeedSize:]), provider(make([]byte, 32)), nil)
	userSvc := user.NewService(manager, client)
	return &Handler{
		cache: manager, tokenSvc: tokenSvc, userSvc: userSvc,
		authenticateSvc: authenticate.NewService(manager, nil),
		authorizeSvc:    authorize.NewService(manager, client, userSvc, tokenSvc, nil, time.Minute),
	}, redis
}

func TestAuthorizePromptAndSSOConsentDecisions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, tt := range []struct {
			name, prompt, wantError string
			sso, approved           bool
			maxAge                  string
			wantConsent             bool
			errorStatus             int
			readFailure             bool
		}{
			{name: "silent approved SSO", prompt: "none", sso: true, approved: true},
			{name: "silent unapproved SSO", prompt: "none", sso: true, wantError: "consent_required", errorStatus: http.StatusBadRequest},
			{name: "silent no SSO", prompt: "none", wantError: "login_required", errorStatus: http.StatusUnauthorized},
			{name: "forced consent with SSO", prompt: "consent", sso: true, approved: true, wantConsent: true},
			{name: "forced consent without SSO", prompt: "consent", approved: true},
			{name: "forced login with SSO", prompt: "login", sso: true, approved: true},
			{name: "consent lookup failure", prompt: "none", sso: true, approved: true, readFailure: true, wantError: "server_error", errorStatus: http.StatusInternalServerError},
			{name: "legacy SSO cannot satisfy max age", prompt: "none", sso: true, approved: true, maxAge: "60", wantError: "login_required", errorStatus: http.StatusUnauthorized},
		} {
			t.Run(method+"/"+tt.name, func(t *testing.T) {
				h, redis := consentHTTPHandler(t)
				if tt.approved {
					if err := h.cache.GrantConsent(context.Background(), "platform", "user-one", "atlas", map[string][]string{"": {"openid", "profile", "email"}, "iris": {"openid", "profile", "email"}}, config.GetSSOTTL()); err != nil {
						t.Fatal(err)
					}
				}
				if tt.readFailure {
					redis.readErr = errors.New("Redis read unavailable")
				}
				query := standardAuthorizationQuery()
				query.Set("prompt", tt.prompt)
				if tt.maxAge != "" {
					query.Set("max_age", tt.maxAge)
				}
				var body string
				if method == http.MethodPost {
					var req types.AuthRequest
					if _, err := bindAuthorizeQuery(authorizeQueryContext(query), &req); err != nil {
						t.Fatal(err)
					}
					encoded, err := json.Marshal(req)
					if err != nil {
						t.Fatal(err)
					}
					body = string(encoded)
				}
				request := httptest.NewRequestWithContext(context.Background(), method, "/api/authorize?"+query.Encode(), strings.NewReader(body))
				request.Header.Set("Content-Type", gin.MIMEJSON)
				if tt.sso {
					sso := pkgtoken.NewClaimsBuilder().Issuer(token.SSOIssuer).ClientID(token.SSOIssuer).Audience(token.SSOAudience).ExpiresIn(time.Hour).Build(token.NewSSOTokenBuilder().Identity("platform", "user-one"))
					encoded, err := h.tokenSvc.Issue(context.Background(), sso)
					if err != nil {
						t.Fatal(err)
					}
					request.AddCookie(&http.Cookie{Name: config.GetSSOCookieName(), Value: encoded, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
				}
				recorder := httptest.NewRecorder()
				router := gin.New()
				router.Handle(method, "/api/authorize", h.Authorize)
				router.ServeHTTP(recorder, request)
				location, err := url.Parse(recorder.Header().Get("Location"))
				if err != nil {
					t.Fatal(err)
				}
				if tt.wantError != "" {
					if method == http.MethodPost {
						if recorder.Code != tt.errorStatus || location.String() != "" || !strings.Contains(recorder.Body.String(), `"error":"`+tt.wantError+`"`) {
							t.Fatalf("response = %d %q %s", recorder.Code, location, recorder.Body.String())
						}
					} else if recorder.Code != http.StatusSeeOther || location.Host != "atlas.example" || location.Query().Get("error") != tt.wantError {
						t.Fatalf("response = %d %q %s", recorder.Code, location, recorder.Body.String())
					}
					return
				}
				wantStatus := http.StatusSeeOther
				if method == http.MethodPost {
					wantStatus = http.StatusMultipleChoices
				}
				if recorder.Code != wantStatus {
					t.Fatalf("response = %d %q %s", recorder.Code, location, recorder.Body.String())
				}
				if tt.wantConsent {
					want, err := url.Parse(config.GetEndpointConsent())
					if err != nil {
						t.Fatal(err)
					}
					if location.Path != want.Path {
						t.Fatalf("consent location = %q", location)
					}
				} else if tt.sso && tt.prompt != "login" {
					if location.Host != "atlas.example" || location.Query().Get("code") == "" || location.Query().Get("state") != query.Get("state") {
						t.Fatalf("code location = %q", location)
					}
				} else {
					want, err := url.Parse(config.GetEndpointLogin())
					if err != nil {
						t.Fatal(err)
					}
					if location.Path != want.Path {
						t.Fatalf("login location = %q", location)
					}
				}
				if tt.sso {
					for storageKey, value := range redis.values {
						if strings.HasPrefix(storageKey, config.GetCacheKeyPrefix("auth_flow")) {
							var flow types.AuthFlow
							if err := json.Unmarshal([]byte(value), &flow); err != nil {
								t.Fatal(err)
							}
							if !flow.AuthenticatedAt.IsZero() {
								t.Fatalf("legacy SSO invented auth_time: %v", flow.AuthenticatedAt)
							}
						}
					}
				}
			})
		}
	}
}

func TestConsentDecisionPersistsOnlyApprovalAndFailsClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tt := range []struct {
		name          string
		confirm, fail bool
	}{
		{"approved", true, false}, {"denied", false, false}, {"persistence failure", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, redis := consentHTTPHandler(t)
			flow := consentTestFlow()
			if err := h.authenticateSvc.SaveFlow(context.Background(), flow); err != nil {
				t.Fatal(err)
			}
			if tt.fail {
				redis.grantErr = errors.New("Redis write unavailable")
			}
			body := `{"confirm":false}`
			if tt.confirm {
				body = `{"confirm":true}`
			}
			request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/consent", strings.NewReader(body))
			request.Header.Set("Content-Type", gin.MIMEJSON)
			request.AddCookie(&http.Cookie{Name: AuthSessionCookie, Value: flow.ID, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
			recorder := httptest.NewRecorder()
			router := gin.New()
			router.POST("/api/consent", h.Consent)
			router.ServeHTTP(recorder, request)
			location, err := url.Parse(recorder.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if tt.fail {
				if recorder.Code != http.StatusInternalServerError || location.Query().Get("code") != "" {
					t.Fatalf("write failure response = %d %q", recorder.Code, location)
				}
			} else {
				if recorder.Code != http.StatusMultipleChoices {
					t.Fatalf("response = %d %s", recorder.Code, recorder.Body.String())
				}
				if tt.confirm && location.Query().Get("code") == "" {
					t.Fatalf("approval did not issue code: %q", location)
				}
				if !tt.confirm && location.Query().Get("error") != "access_denied" {
					t.Fatalf("denial location = %q", location)
				}
			}
			if !tt.confirm && redis.grants != 0 {
				t.Fatal("denial persisted approval")
			}
			approved, err := h.cache.GetConsent(context.Background(), "platform", "user-one", "atlas")
			if err != nil {
				t.Fatal(err)
			}
			if tt.confirm && !tt.fail {
				if len(approved[""]) != 2 || len(approved["iris"]) != 2 {
					t.Fatalf("persisted scope facts = %v", approved)
				}
				if required, err := h.requiresConsent(context.Background(), consentTestFlow()); err != nil || required {
					t.Fatalf("approved future flow = %v, %v", required, err)
				}
			} else if len(approved) != 0 {
				t.Fatalf("unexpected persisted approval: %v", approved)
			}
			if tt.fail {
				stored, err := h.authenticateSvc.GetFlow(context.Background(), flow.ID)
				if err != nil {
					t.Fatal(err)
				}
				if stored.ConsentGranted || stored.State == types.FlowStateCompleted {
					t.Fatal("failed persistence approved or completed flow")
				}
				for storageKey := range redis.values {
					if strings.HasPrefix(storageKey, config.GetCacheKeyPrefix("auth_code")) {
						t.Fatal("failed persistence issued an authorization code")
					}
				}
			}
		})
	}
}

func TestSSOAuthenticationAge(t *testing.T) {
	t.Parallel()
	now := time.Unix(1700000100, 0)
	zero, ten := uint64(0), uint64(10)
	for _, tt := range []struct {
		name            string
		authenticatedAt time.Time
		maxAge          *uint64
		want            bool
	}{
		{"legacy session without max age", time.Time{}, nil, true},
		{"legacy session with max age", time.Time{}, &ten, false},
		{"fresh session", now.Add(-time.Second), &ten, true},
		{"exact age", now.Add(-10 * time.Second), &ten, true},
		{"expired authentication", now.Add(-11 * time.Second), &ten, false},
		{"zero always reauthenticates", now, &zero, false},
		{"future authentication", now.Add(time.Second), nil, false},
		{"no maximum age", now.Add(-time.Hour), nil, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := ssoAuthenticationFresh(tt.authenticatedAt, tt.maxAge, now); got != tt.want {
				t.Fatalf("ssoAuthenticationFresh() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConsentRequiresExplicitDecision(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/consent", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", gin.MIMEJSON)
	router := gin.New()
	router.POST("/api/consent", (&Handler{}).Consent)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("consent without decision status = %d", recorder.Code)
	}
}
