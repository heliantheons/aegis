package types

import (
	"testing"

	"github.com/go-json-experiment/json"
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
