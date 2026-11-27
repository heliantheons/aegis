package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/heliantheon/aegis/config"
	autherrors "github.com/heliantheon/aegis/errors"
	"github.com/heliantheon/aegis/internal/types"
	"github.com/heliantheon/aegis/models"
)

func TestRespondAuthFlowHandlesPendingAndErrorOutcomes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &Handler{}

	t.Run("authorize initialized sets session cookie and redirects to login", func(t *testing.T) {
		flow := types.NewAuthFlow(&types.AuthRequest{
			AuthorizeRequestBase: types.AuthorizeRequestBase{
				ResponseType: "code",
				ClientID:     "client-1",
				RedirectURI:  "https://app.example/callback",
			},
		}, time.Minute, time.Hour)
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/authorize", nil)

		h.respondAuthorize(c, flow, nil)
		c.Writer.WriteHeaderNow()

		if recorder.Code != http.StatusMultipleChoices || recorder.Header().Get("Location") != config.GetEndpointLogin() {
			t.Fatalf("authorize response = %d %q", recorder.Code, recorder.Header().Get("Location"))
		}
		var sessionCookie *http.Cookie
		for _, cookie := range recorder.Result().Cookies() {
			if cookie.Name == AuthSessionCookie {
				sessionCookie = cookie
			}
		}
		if sessionCookie == nil || sessionCookie.Value != flow.ID {
			t.Fatalf("session cookie = %v, want %q", sessionCookie, flow.ID)
		}
	})

	t.Run("login prerequisite pauses flow and directs to required actions", func(t *testing.T) {
		flow := types.NewAuthFlow(&types.AuthRequest{}, time.Minute, time.Hour)
		flow.SetConnectionMap(map[string]*types.ConnectionConfig{
			"google":  {Type: types.ConnTypeIDP, Strategy: []string{"redirect"}, Require: []string{"captcha"}},
			"captcha": {Type: types.ConnTypeFactor},
		})
		flow.SetConnection("google")
		flow.SetExtra(types.ExtraKeyStrategy, "redirect")
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/login", nil)

		h.respondFlow(c, flow, nil, false)
		c.Writer.WriteHeaderNow()

		location, err := url.Parse(recorder.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if recorder.Code != http.StatusMultipleChoices || location.Query().Get("actions") != "captcha" {
			t.Fatalf("prerequisite response = %d %q", recorder.Code, location)
		}
	})

	t.Run("callback identified user redirects browser to binding", func(t *testing.T) {
		flow := types.NewAuthFlow(&types.AuthRequest{}, time.Minute, time.Hour)
		flow.User = &models.UserWithDecrypted{User: models.User{OpenID: "user-1"}}
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/idps/google/callback", nil)

		h.respondFlow(c, flow, nil, true)

		if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/binding" {
			t.Fatalf("callback identify response = %d %q", recorder.Code, recorder.Header().Get("Location"))
		}
	})

	t.Run("expired flow clears auth session cookie", func(t *testing.T) {
		flow := types.NewAuthFlow(&types.AuthRequest{}, time.Minute, time.Hour)
		expired := autherrors.NewFlowExpired("session expired")
		flow.Fail(expired)
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/login", nil)

		h.respondFlowError(c, flow, expired)
		c.Writer.WriteHeaderNow()

		if recorder.Code != expired.HTTPStatus {
			t.Fatalf("expired status = %d, want %d", recorder.Code, expired.HTTPStatus)
		}
		var cleared bool
		for _, cookie := range recorder.Result().Cookies() {
			if cookie.Name == AuthSessionCookie && cookie.Value == "" && cookie.MaxAge < 0 {
				cleared = true
			}
		}
		if !cleared {
			t.Fatal("expired flow did not clear auth session cookie")
		}
	})
}
