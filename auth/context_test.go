package auth

import (
	"encoding/json"
	"testing"

	"github.com/heliantheon/aegis/internal/types"
	"github.com/heliantheon/aegis/models"
)

func TestBuildAuthContextUsesApplicationDescription(t *testing.T) {
	t.Parallel()

	applicationDescription := "Heliantheon 平台统一管理入口。"
	serviceDescription := "菜谱管理、收藏与推荐服务"
	response, ok := buildAuthContext(&types.AuthFlow{
		Application: &models.Application{
			DomainID:    "platform",
			AppID:       "atlas",
			Name:        "Atlas 管理控制台",
			Description: &applicationDescription,
		},
		Service: &models.Service{
			DomainID:    models.InheritedDomainID,
			ServiceID:   "zwei",
			Name:        "Zwei 菜谱服务",
			Description: &serviceDescription,
		},
	}).(SingleAudienceContext)
	if !ok {
		t.Fatalf("context type = %T, want SingleAudienceContext", response)
	}

	if response.Application == nil || response.Application.Description == nil {
		t.Fatal("application description is missing")
	}
	if got := *response.Application.Description; got != applicationDescription {
		t.Fatalf("application description = %q, want %q", got, applicationDescription)
	}
	if response.Service == nil || response.Service.DomainID != "platform" {
		t.Fatalf("service domain = %v, want platform", response.Service)
	}
}

func TestBuildAuthContextPreservesAudienceShape(t *testing.T) {
	t.Parallel()

	application := &models.Application{AppID: "atlas", Name: "Atlas"}
	logoURL := "https://assets.example.com/iris.svg"

	tests := []struct {
		name         string
		flow         *types.AuthFlow
		wantService  bool
		wantServices bool
	}{
		{
			name: "single audience",
			flow: &types.AuthFlow{
				Request:     &types.AuthRequest{Audience: "iris"},
				Application: application,
				Service:     &models.Service{ServiceID: "iris", Name: "Iris", LogoURL: &logoURL},
			},
			wantService: true,
		},
		{
			name: "multi audience",
			flow: &types.AuthFlow{
				Request: &types.AuthRequest{Audiences: map[string]*types.RequestAudienceScope{
					"iris":   {},
					"hermes": {},
				}},
				Application: application,
				Services: []models.Service{
					{ServiceID: "hermes", Name: "Hermes"},
					{ServiceID: "iris", Name: "Iris", LogoURL: &logoURL},
				},
			},
			wantServices: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			encoded, err := json.Marshal(buildAuthContext(test.flow))
			if err != nil {
				t.Fatalf("marshal context: %v", err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatalf("unmarshal context: %v", err)
			}
			_, hasService := fields["service"]
			_, hasServices := fields["services"]
			if hasService != test.wantService || hasServices != test.wantServices {
				t.Fatalf("context shape service=%t services=%t, want service=%t services=%t: %s",
					hasService, hasServices, test.wantService, test.wantServices, encoded)
			}
			if test.wantService && string(fields["service"]) == "null" {
				t.Fatalf("single audience service is null: %s", encoded)
			}
			if test.wantServices {
				var services []ServiceInfo
				if err := json.Unmarshal(fields["services"], &services); err != nil {
					t.Fatalf("unmarshal services: %v", err)
				}
				if len(services) != 2 || services[0].ServiceID != "hermes" || services[1].ServiceID != "iris" {
					t.Fatalf("services = %+v, want hermes then iris", services)
				}
				if services[1].LogoURL == nil || *services[1].LogoURL != logoURL {
					t.Fatalf("iris logo_url = %v, want %q", services[1].LogoURL, logoURL)
				}
			}
		})
	}
}

func TestCollectAudiencesSortsMultiAudienceIDs(t *testing.T) {
	t.Parallel()

	req := &types.AuthRequest{Audiences: map[string]*types.RequestAudienceScope{
		"zwei":   {},
		"hermes": {},
		"iris":   {},
	}}

	for range 20 {
		got, authErr := collectAudiences(req)
		if authErr != nil {
			t.Fatalf("collectAudiences() error = %v", authErr)
		}
		want := []string{"hermes", "iris", "zwei"}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("collectAudiences() = %v, want %v", got, want)
			}
		}
	}
}

func TestValidateAuthorizeRequestUsesAudienceDataShape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		req     types.AuthRequest
		wantErr bool
	}{
		{name: "single audience", req: types.AuthRequest{Audience: "iris"}},
		{
			name: "multi audience with one entry",
			req: types.AuthRequest{Audiences: map[string]*types.RequestAudienceScope{
				"iris": {},
			}},
		},
		{name: "missing audience data", req: types.AuthRequest{}, wantErr: true},
		{
			name: "conflicting audience data",
			req: types.AuthRequest{
				Audience: "iris",
				Audiences: map[string]*types.RequestAudienceScope{
					"hermes": {},
				},
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			gotErr := validateAuthorizeRequest(&test.req)
			if (gotErr != nil) != test.wantErr {
				t.Fatalf("validateAuthorizeRequest() error = %v, wantErr %t", gotErr, test.wantErr)
			}
		})
	}
}
