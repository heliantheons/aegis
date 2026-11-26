package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"github.com/heliantheon/aegis/config"
	autherrors "github.com/heliantheon/aegis/errors"
	"github.com/heliantheon/aegis/internal/types"
	"github.com/heliantheon/aegis/models"
)

// Discovery 返回标准 OpenID Provider 配置。
func (h *Handler) Discovery(c *gin.Context) {
	issuer := config.GetIssuer()
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              issuer + "/jwks",
		"userinfo_endpoint":                     issuer + "/profile",
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "phone", "offline_access"},
		"claims_supported":                      []string{"iss", "sub", "aud", "iat", "exp", "nonce", "nickname", "picture", "email", "phone_number"},
	})
}

// JWKS 仅返回独立 OIDC 签名密钥的公开部分。
func (h *Handler) JWKS(c *gin.Context) {
	keys, err := h.tokenSvc.OIDCKeySet()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	c.JSON(http.StatusOK, keys)
}

func validateAuthorizationPrompt(prompts []string) *autherrors.AuthError {
	for i, prompt := range prompts {
		if slices.Contains(prompts[:i], prompt) {
			return autherrors.NewInvalidRequest("prompt values must not repeat")
		}
		if prompt != types.PromptLogin {
			return autherrors.NewInvalidRequest("unsupported prompt")
		}
	}
	return nil
}

func bindAuthorizeQuery(c *gin.Context, req *types.AuthRequest) error {
	query, err := url.ParseQuery(c.Request.URL.RawQuery)
	if err != nil {
		return autherrors.NewInvalidRequest("invalid authorization query")
	}
	return bindAuthorizeParameters(query, req)
}

func bindAuthorizeBody(c *gin.Context, req *types.AuthRequest) error {
	var err error
	switch c.ContentType() {
	case gin.MIMEJSON:
		err = c.ShouldBindJSON(req)
	case gin.MIMEPOSTForm:
		var body []byte
		body, err = io.ReadAll(c.Request.Body)
		if err == nil {
			var form url.Values
			form, err = url.ParseQuery(string(body))
			if err == nil {
				err = bindAuthorizeParameters(form, req)
			}
		}
	default:
		return autherrors.NewInvalidRequest("authorization body must be JSON or form data")
	}
	if err != nil {
		return autherrors.NewInvalidRequest(err.Error())
	}
	return nil
}

func bindAuthorizeParameters(query url.Values, req *types.AuthRequest) error {
	for _, values := range query {
		if len(values) != 1 {
			return autherrors.NewInvalidRequest("authorization parameters must not repeat")
		}
	}
	if err := binding.MapFormWithTag(req, query, "form"); err != nil {
		return autherrors.NewInvalidRequest(err.Error())
	}
	if err := binding.Validator.ValidateStruct(req); err != nil {
		return autherrors.NewInvalidRequest(err.Error())
	}
	if query.Has("audiences") && len(req.Audiences) == 0 {
		return autherrors.NewInvalidRequest("audiences must be a nonempty JSON object")
	}
	for key, values := range query {
		req.Set(key, values[0])
	}
	return nil
}

func validS256Challenge(challenge string) bool {
	if len(challenge) != 43 {
		return false
	}
	var buffer [sha256.Size]byte
	decoded, err := base64.RawURLEncoding.Strict().Decode(buffer[:], []byte(challenge))
	return err == nil && decoded == sha256.Size
}

func validRedirectURISyntax(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.IsAbs() && u.Fragment == "" && u.User == nil
}

func validAuthorizationRedirect(app *models.Application, raw string) bool {
	return validRedirectURISyntax(raw) && slices.Contains(app.GetAllowedRedirectURIs(), raw)
}

func authorizationErrorURL(redirectURI, state, code, description string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	query := u.Query()
	query.Set("error", code)
	query.Set("error_description", description)
	if state != "" {
		query.Set("state", state)
	}
	u.RawQuery = query.Encode()
	return u.String()
}
