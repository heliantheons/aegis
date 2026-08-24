package authorize

import (
	"crypto/sha256"
	"testing"

	tokendef "github.com/heliantheon/aegis-go/utilities/token"
	autherrors "github.com/heliantheon/aegis/errors"
)

func TestClientSecretMatches(t *testing.T) {
	t.Parallel()

	oldVerifier := sha256.Sum256([]byte("old-secret"))
	currentVerifier := sha256.Sum256([]byte("current-secret"))
	verifiers := [][sha256.Size]byte{currentVerifier, oldVerifier}

	if !clientSecretMatches(verifiers, "current-secret") {
		t.Fatal("clientSecretMatches() rejected the current secret")
	}
	if !clientSecretMatches(verifiers, "old-secret") {
		t.Fatal("clientSecretMatches() rejected an unexpired rotated secret")
	}
	if clientSecretMatches(verifiers, "wrong-secret") {
		t.Fatal("clientSecretMatches() accepted an invalid secret")
	}
}

func TestResolveCATClientID(t *testing.T) {
	t.Parallel()

	build := func(issuer, clientID, audience string) *tokendef.ClientToken {
		t.Helper()
		built := tokendef.NewClaimsBuilder().
			Issuer(issuer).
			ClientID(clientID).
			Audience(audience).
			Build(tokendef.NewClientTokenBuilder())
		clientToken, ok := built.(*tokendef.ClientToken)
		if !ok {
			t.Fatalf("unexpected token type %T", built)
		}
		return clientToken
	}

	t.Run("accepts matching cat", func(t *testing.T) {
		clientID, err := resolveCATClientID("app", build("app", "app", "aegis"))
		if err != nil {
			t.Fatalf("resolveCATClientID() error = %v", err)
		}
		if clientID != "app" {
			t.Fatalf("client_id = %q, want app", clientID)
		}
	})

	t.Run("resolves omitted client id", func(t *testing.T) {
		clientID, err := resolveCATClientID("", build("app", "app", "aegis"))
		if err != nil {
			t.Fatalf("resolveCATClientID() error = %v", err)
		}
		if clientID != "app" {
			t.Fatalf("client_id = %q, want app", clientID)
		}
	})

	for name, testCase := range map[string]struct {
		requestedClientID string
		token             *tokendef.ClientToken
	}{
		"client id mismatch": {"other", build("app", "app", "aegis")},
		"issuer mismatch":    {"app", build("other", "app", "aegis")},
		"audience mismatch":  {"app", build("app", "app", "service")},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := resolveCATClientID(testCase.requestedClientID, testCase.token)
			if err == nil {
				t.Fatal("resolveCATClientID() accepted invalid CAT")
			}
			if got := autherrors.ToAuthError(err).Code; got != autherrors.CodeInvalidClient {
				t.Fatalf("error code = %q, want %q", got, autherrors.CodeInvalidClient)
			}
		})
	}
}
