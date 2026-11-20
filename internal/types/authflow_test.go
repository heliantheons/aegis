package types

import (
	"testing"
	"time"

	"github.com/go-json-experiment/json"

	"github.com/heliantheon/aegis/models"
)

func TestAuthRequestEmbeddedBaseRoundTrip(t *testing.T) {
	t.Parallel()

	want := AuthRequest{
		AuthorizeRequestBase: AuthorizeRequestBase{
			ResponseType:        "code",
			ClientID:            "atlas",
			RedirectURI:         "https://atlas.example.com/callback",
			CodeChallenge:       "challenge",
			CodeChallengeMethod: "S256",
			State:               "state",
		},
		Audiences: map[string]*RequestAudienceScope{
			"hermes": {Scope: "openid"},
			"iris":   {Scope: "openid profile"},
		},
		Params: map[string]any{"tenant": "platform"},
	}

	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	var got AuthRequest
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}

	if got.ClientID != want.ClientID || got.RedirectURI != want.RedirectURI {
		t.Fatalf("embedded base = %+v, want %+v", got.AuthorizeRequestBase, want.AuthorizeRequestBase)
	}
	if len(got.Audiences) != 2 || got.Audiences["iris"].Scope != "openid profile" {
		t.Fatalf("audiences = %+v, want %+v", got.Audiences, want.Audiences)
	}
	if got.GetString("tenant") != "platform" {
		t.Fatalf("tenant = %q, want platform", got.GetString("tenant"))
	}
}

func TestAuthFlowRetainsAuthenticationTimeAcrossSerialization(t *testing.T) {
	t.Parallel()
	age := uint64(0)
	flow := NewAuthFlow(&AuthRequest{AuthorizeRequestBase: AuthorizeRequestBase{MaxAge: &age}}, time.Minute, time.Hour)
	flow.SetAuthenticated(&models.UserWithDecrypted{})
	original := flow.AuthenticatedAt
	if original.IsZero() {
		t.Fatal("successful authentication did not record auth_time")
	}
	flow.SetAuthenticated(&models.UserWithDecrypted{})
	flow.Renew(time.Minute)
	if !flow.AuthenticatedAt.Equal(original) {
		t.Fatal("flow update reset original authentication time")
	}
	encoded, err := json.Marshal(flow)
	if err != nil {
		t.Fatal(err)
	}
	var restored AuthFlow
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if !restored.AuthenticatedAt.Equal(original) || restored.Request.MaxAge == nil || *restored.Request.MaxAge != 0 {
		t.Fatalf("restored flow authentication metadata = %v, %v", restored.AuthenticatedAt, restored.Request.MaxAge)
	}
}
