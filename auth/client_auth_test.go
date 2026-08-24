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
		authentication, err := resolveTokenClientCredentials(context, &clientID)
		if err != nil {
			t.Fatalf("resolveTokenClientCredentials() error = %v", err)
		}
		if authentication.Method != authorize.ClientAuthMethodNone || authentication.Credential != "" || clientID != "public-app" {
			t.Fatalf("unexpected credentials: method=%q credential=%q client_id=%q", authentication.Method, authentication.Credential, clientID)
		}
	})

	t.Run("client secret post", func(t *testing.T) {
		context := tokenContext(url.Values{
			"client_id":     {"grafana"},
			"client_secret": {"post-secret"},
		})
		clientID := "grafana"
		authentication, err := resolveTokenClientCredentials(context, &clientID)
		if err != nil {
			t.Fatalf("resolveTokenClientCredentials() error = %v", err)
		}
		if authentication.Method != authorize.ClientAuthMethodSecretPost || authentication.Credential != "post-secret" {
			t.Fatalf("unexpected credentials: method=%q credential=%q", authentication.Method, authentication.Credential)
		}
	})

	t.Run("client secret basic decodes form encoding", func(t *testing.T) {
		context := tokenContext(nil)
		context.Request.SetBasicAuth(url.QueryEscape("grafana client"), url.QueryEscape("s+e/cret"))
		clientID := ""
		authentication, err := resolveTokenClientCredentials(context, &clientID)
		if err != nil {
			t.Fatalf("resolveTokenClientCredentials() error = %v", err)
		}
		if authentication.Method != authorize.ClientAuthMethodSecretBasic || authentication.Credential != "s+e/cret" || clientID != "grafana client" {
			t.Fatalf("unexpected credentials: method=%q credential=%q client_id=%q", authentication.Method, authentication.Credential, clientID)
		}
	})

	t.Run("cat", func(t *testing.T) {
		context := tokenContext(nil)
		context.Request.Header.Set("Authorization", "Bearer v4.public.cat")
		clientID := ""
		authentication, err := resolveTokenClientCredentials(context, &clientID)
		if err != nil {
			t.Fatalf("resolveTokenClientCredentials() error = %v", err)
		}
		if authentication.Method != authorize.ClientAuthMethodCAT || authentication.Credential != "v4.public.cat" || clientID != "" {
			t.Fatalf("unexpected credentials: method=%q credential=%q client_id=%q", authentication.Method, authentication.Credential, clientID)
		}
	})

	t.Run("rejects multiple methods", func(t *testing.T) {
		context := tokenContext(url.Values{
			"client_id":     {"grafana"},
			"client_secret": {"post-secret"},
		})
		context.Request.SetBasicAuth("grafana", "basic-secret")
		clientID := "grafana"
		_, err := resolveTokenClientCredentials(context, &clientID)
		if err == nil {
			t.Fatal("resolveTokenClientCredentials() accepted multiple authentication methods")
		}
		if got := autherrors.ToAuthError(err).Code; got != autherrors.CodeInvalidRequest {
			t.Fatalf("error code = %q, want %q", got, autherrors.CodeInvalidRequest)
		}
	})

	t.Run("rejects client secret and cat", func(t *testing.T) {
		context := tokenContext(url.Values{
			"client_id":     {"grafana"},
			"client_secret": {"post-secret"},
		})
		context.Request.Header.Set("Authorization", "Bearer v4.public.cat")
		clientID := "grafana"
		_, err := resolveTokenClientCredentials(context, &clientID)
		if err == nil {
			t.Fatal("resolveTokenClientCredentials() accepted client secret and CAT")
		}
		if got := autherrors.ToAuthError(err).Code; got != autherrors.CodeInvalidRequest {
			t.Fatalf("error code = %q, want %q", got, autherrors.CodeInvalidRequest)
		}
	})

	t.Run("rejects mismatched basic client id", func(t *testing.T) {
		context := tokenContext(url.Values{"client_id": {"other"}})
		context.Request.SetBasicAuth("grafana", "secret")
		clientID := "other"
		_, err := resolveTokenClientCredentials(context, &clientID)
		if err == nil {
			t.Fatal("resolveTokenClientCredentials() accepted a mismatched client id")
		}
		if got := autherrors.ToAuthError(err).Code; got != autherrors.CodeInvalidClient {
			t.Fatalf("error code = %q, want %q", got, autherrors.CodeInvalidClient)
		}
	})
}
