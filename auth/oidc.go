package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	pkgtoken "github.com/heliantheon/aegis-go/utilities/token"
	"github.com/heliantheon/aegis/config"
	autherrors "github.com/heliantheon/aegis/errors"
	"github.com/heliantheon/aegis/internal/types"
	"github.com/heliantheon/aegis/models"
	"github.com/heliantheon/common/logger"
)

// Discovery 返回标准 OpenID Provider 配置。
func (h *Handler) Discovery(c *gin.Context) {
	issuer := config.GetIssuer()
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              issuer + "/jwks",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "phone", "offline_access"},
		"claims_supported":                      []string{"iss", "sub", "aud", "iat", "exp", "auth_time", "nonce", "nickname", "picture", "email", "phone_number"},
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

// UserInfo 验证现有 UAT 并按 OIDC scope 返回标准用户声明。
func (h *Handler) UserInfo(c *gin.Context) {
	authorization := strings.Fields(c.GetHeader("Authorization"))
	if len(authorization) != 2 || !strings.EqualFold(authorization[0], "Bearer") {
		userInfoError(c, http.StatusUnauthorized, "invalid_token")
		return
	}
	verified, err := h.tokenSvc.Verify(c.Request.Context(), authorization[1])
	if err != nil {
		userInfoError(c, http.StatusUnauthorized, "invalid_token")
		return
	}
	uat := userInfoToken(verified, config.GetIssuer(), config.GetOIDCDefaultAudience())
	if uat == nil {
		userInfoError(c, http.StatusUnauthorized, "invalid_token")
		return
	}
	if !h.allowClientOrigin(c, uat.ClientID()) {
		return
	}
	claims, ok := userInfoClaims(uat)
	if !ok {
		userInfoError(c, http.StatusForbidden, "insufficient_scope")
		return
	}
	c.JSON(http.StatusOK, claims)
}

func userInfoToken(verified pkgtoken.Token, issuer, audience string) *pkgtoken.UserAccessToken {
	uat, ok := verified.(*pkgtoken.UserAccessToken)
	if !ok || uat == nil || uat.Issuer() != issuer || uat.Audience() != audience || uat.IsExpired() || uat.OpenID() == "" {
		return nil
	}
	return uat
}

func userInfoClaims(uat *pkgtoken.UserAccessToken) (gin.H, bool) {
	scopes := uat.Scopes()
	if _, ok := scopes["openid"]; !ok {
		return nil, false
	}
	claims := gin.H{"sub": uat.OpenID()}
	if _, ok := scopes["profile"]; ok {
		claims["nickname"] = uat.Nickname()
		claims["picture"] = uat.Picture()
	}
	if _, ok := scopes["email"]; ok {
		claims["email"] = uat.Email()
	}
	if _, ok := scopes["phone"]; ok {
		claims["phone_number"] = uat.Phone()
	}
	return claims, true
}

func userInfoError(c *gin.Context, status int, code string) {
	challenge := `Bearer error="` + code + `"`
	if code == "insufficient_scope" {
		challenge += `, scope="openid"`
	}
	c.Header("WWW-Authenticate", challenge)
	c.JSON(status, gin.H{"error": code})
}

func bindAuthorizeQuery(c *gin.Context, req *types.AuthRequest) (string, error) {
	authorizationURL := "/api/authorize?" + c.Request.URL.RawQuery
	query, err := url.ParseQuery(c.Request.URL.RawQuery)
	if err != nil {
		return authorizationURL, autherrors.NewInvalidRequest("invalid authorization query")
	}
	return authorizationURL, bindAuthorizeParameters(query, req)
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
	case gin.MIMEMultipartPOSTForm:
		err = c.ShouldBindWith(req, binding.FormMultipart)
	default:
		return autherrors.NewInvalidRequest("authorization body must be JSON or form data")
	}
	if err != nil {
		return autherrors.NewInvalidRequest(err.Error())
	}
	return nil
}

func bindAuthorizeParameters(query url.Values, req *types.AuthRequest) error {
	if len(query["client_id"]) != 1 || len(query["redirect_uri"]) != 1 {
		req.RedirectURI = ""
		return autherrors.NewInvalidRequest("client_id and redirect_uri must occur exactly once")
	}
	bindErr := binding.MapFormWithTag(req, query, "form")
	for _, values := range query {
		if len(values) != 1 {
			return autherrors.NewInvalidRequest("authorization parameters must not repeat")
		}
	}
	if mode := query.Get("response_mode"); mode != "" && mode != "query" {
		return autherrors.NewInvalidRequest("only query response_mode is supported")
	}
	if age, ok := query["max_age"]; ok && (age[0] == "" || age[0] != strings.TrimSpace(age[0])) {
		return autherrors.NewInvalidRequest("max_age must be a nonnegative integer")
	}
	if bindErr != nil {
		return autherrors.NewInvalidRequest(bindErr.Error())
	}
	if query.Has("audiences") && len(req.Audiences) == 0 {
		return autherrors.NewInvalidRequest("audiences must be a nonempty JSON object")
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

func validAuthorizationRedirect(app *models.Application, raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.IsAbs() && u.Fragment == "" && u.User == nil && slices.Contains(app.GetAllowedRedirectURIs(), raw)
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

// authorizationRedirect 保留 POST API 的指令响应，GET 则由浏览器跟随跳转。
func authorizationRedirect(c *gin.Context, location string) {
	if c.Request.Method == http.MethodGet {
		browserRedirect(c, location)
		return
	}
	actionRedirect(c, location)
}

// validated is supplied only after the application registry accepts redirect_uri.
func authorizationError(c *gin.Context, validated *types.AuthRequest, err error) {
	authErr := autherrors.ToAuthError(err)
	if validated != nil && validated.Prompt.Contains(types.PromptNone) && authErr.Code == autherrors.CodeIdentityRequired {
		authErr = autherrors.New(http.StatusBadRequest, "interaction_required", "additional identity verification is required")
	}
	if c.Request.Method != http.MethodGet || validated == nil {
		c.JSON(authErr.HTTPStatus, gin.H{
			"error":             authErr.Code,
			"error_description": authErr.Description,
		})
		return
	}
	browserRedirect(c, authorizationErrorURL(validated.RedirectURI, validated.State, authErr.Code, authErr.Description))
}

func withAuthorizationURL(target, authorizationURL string) string {
	if authorizationURL == "" {
		return target
	}
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	query := u.Query()
	query.Set("authorize_url", authorizationURL)
	u.RawQuery = query.Encode()
	return u.String()
}

func ssoAuthTimeKey(raw string) string {
	return fmt.Sprintf("aegis:oidc:sso-auth-time:%x", sha256.Sum256([]byte(raw)))
}

func (h *Handler) ssoAuthenticatedAt(c *gin.Context, ctx context.Context, domain string) time.Time {
	raw, err := getSSOCookie(c)
	if err != nil || raw == "" {
		return time.Time{}
	}
	value, err := h.cache.Redis().HGet(ctx, ssoAuthTimeKey(raw), domain)
	if err != nil {
		return time.Time{}
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds <= 0 {
		return time.Time{}
	}
	return time.Unix(seconds, 0)
}

// copySSOAuthTimes 续期仅延长元数据存活时间，不重置任何域的认证时间。
func (h *Handler) copySSOAuthTimes(c *gin.Context, ctx context.Context, newToken, domain string, authenticatedAt time.Time) {
	times := make(map[string]string)
	if oldToken, err := getSSOCookie(c); err == nil && oldToken != "" {
		if stored, err := h.cache.Redis().HGetAll(ctx, ssoAuthTimeKey(oldToken)); err == nil && stored != nil {
			times = stored
		}
	}
	if domain != "" && !authenticatedAt.IsZero() {
		times[domain] = strconv.FormatInt(authenticatedAt.Unix(), 10)
	}
	if len(times) == 0 {
		return
	}
	key := ssoAuthTimeKey(newToken)
	if err := h.cache.Redis().HSet(ctx, key, times); err != nil {
		logger.Warnf("[OIDC] 保存 SSO 认证时间失败: %v", err)
		return
	}
	if err := h.cache.Redis().Expire(ctx, key, config.GetSSOTTL()); err != nil {
		logger.Warnf("[OIDC] 设置 SSO 认证时间过期失败: %v", err)
	}
}
