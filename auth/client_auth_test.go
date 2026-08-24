package auth

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	autherrors "github.com/heliantheon/aegis/errors"
	"github.com/heliantheon/aegis/internal/authorize"
)

func tokenContext(form url.Values) *gin.Context {
	recorder := httptest.NewRecorder()
	ginContext, _ := gin.CreateTestContext(recorder)
	request := httptest.NewRequestWithContext(
		context.Background(),
		"POST",
		"/api/token",
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ginContext.Request = request
	return ginContext
}

func TestResolveTokenClientCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("none", func(t *testing.T) {
		context := tokenContext(url.Values{"client_id": {"public-app"}})
		clientID := "public-app"
		method, secret, err := resolveTokenClientCredentials(context, &clientID)
		if err != nil {
			t.Fatalf("resolveTokenClientCredentials() error = %v", err)
		}
		if method != authorize.ClientAuthMethodNone || secret != "" || clientID != "public-app" {
			t.Fatalf("unexpected credentials: method=%q secret=%q client_id=%q", method, secret, clientID)
		}
	})

	t.Run("client secret post", func(t *testing.T) {
		context := tokenContext(url.Values{
			"client_id":     {"grafana"},
			"client_secret": {"post-secret"},
		})
		clientID := "grafana"
		method, secret, err := resolveTokenClientCredentials(context, &clientID)
		if err != nil {
			t.Fatalf("resolveTokenClientCredentials() error = %v", err)
		}
		if method != authorize.ClientAuthMethodSecretPost || secret != "post-secret" {
			t.Fatalf("unexpected credentials: method=%q secret=%q", method, secret)
		}
	})

	t.Run("client secret basic decodes form encoding", func(t *testing.T) {
		context := tokenContext(nil)
		context.Request.SetBasicAuth(url.QueryEscape("grafana client"), url.QueryEscape("s+e/cret"))
		clientID := ""
		method, secret, err := resolveTokenClientCredentials(context, &clientID)
		if err != nil {
			t.Fatalf("resolveTokenClientCredentials() error = %v", err)
		}
		if method != authorize.ClientAuthMethodSecretBasic || secret != "s+e/cret" || clientID != "grafana client" {
			t.Fatalf("unexpected credentials: method=%q secret=%q client_id=%q", method, secret, clientID)
		}
	})

	t.Run("rejects multiple methods", func(t *testing.T) {
		context := tokenContext(url.Values{
			"client_id":     {"grafana"},
			"client_secret": {"post-secret"},
		})
		context.Request.SetBasicAuth("grafana", "basic-secret")
		clientID := "grafana"
		_, _, err := resolveTokenClientCredentials(context, &clientID)
		if err == nil {
			t.Fatal("resolveTokenClientCredentials() accepted multiple authentication methods")
		}
		if got := autherrors.ToAuthError(err).Code; got != autherrors.CodeInvalidRequest {
			t.Fatalf("error code = %q, want %q", got, autherrors.CodeInvalidRequest)
		}
	})

	t.Run("rejects mismatched basic client id", func(t *testing.T) {
		context := tokenContext(url.Values{"client_id": {"other"}})
		context.Request.SetBasicAuth("grafana", "secret")
		clientID := "other"
		_, _, err := resolveTokenClientCredentials(context, &clientID)
		if err == nil {
			t.Fatal("resolveTokenClientCredentials() accepted a mismatched client id")
		}
		if got := autherrors.ToAuthError(err).Code; got != autherrors.CodeInvalidClient {
			t.Fatalf("error code = %q, want %q", got, autherrors.CodeInvalidClient)
		}
	})
}
