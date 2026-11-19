package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
	req.ClientID = query.Get("client_id")
	req.RedirectURI = query.Get("redirect_uri")
	req.State = query.Get("state")
	if len(query["client_id"]) != 1 || len(query["redirect_uri"]) != 1 {
		req.RedirectURI = ""
		return autherrors.NewInvalidRequest("client_id and redirect_uri must occur exactly once")
	}
	for _, values := range query {
		if len(values) != 1 {
			return autherrors.NewInvalidRequest("authorization parameters must not repeat")
		}
	}
	if mode := query.Get("response_mode"); mode != "" && mode != "query" {
		return autherrors.NewInvalidRequest("only query response_mode is supported")
	}
	req.ResponseType = query.Get("response_type")
	req.CodeChallenge = query.Get("code_challenge")
	req.CodeChallengeMethod = query.Get("code_challenge_method")
	req.Scope = strings.Fields(query.Get("scope"))
	req.Prompt = strings.Fields(query.Get("prompt"))
	req.Nonce = query.Get("nonce")
	req.LoginHint = query.Get("login_hint")
	req.Audience = query.Get("audience")
	return bindAuthorizeExtensions(query, req)
}

func bindAuthorizeExtensions(query url.Values, req *types.AuthRequest) error {
	if values, ok := query["max_age"]; ok {
		age, err := strconv.ParseUint(values[0], 10, 64)
		if err != nil || values[0] == "" || strings.HasPrefix(values[0], "+") {
			return autherrors.NewInvalidRequest("max_age must be a nonnegative integer")
		}
		req.MaxAge = &age
	}
	if audiences, ok := query["audiences"]; ok {
		if err := json.Unmarshal([]byte(audiences[0]), &req.Audiences); err != nil || len(req.Audiences) == 0 {
			return autherrors.NewInvalidRequest("audiences must be a nonempty JSON object")
		}
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

type authorizationResponder struct {
	navigate       func(*gin.Context, string)
	fail           func(*gin.Context, *types.AuthRequest, error)
	redirectErrors bool
}

// validated is supplied only after the application registry accepts redirect_uri.
func browserAuthorizationError(c *gin.Context, validated *types.AuthRequest, err error) {
	if validated == nil {
		localAuthorizationError(c, nil, err)
		return
	}
	authErr := autherrors.ToAuthError(err)
	browserRedirect(c, authorizationErrorURL(validated.RedirectURI, validated.State, authErr.Code, authErr.Description))
}

func localAuthorizationError(c *gin.Context, _ *types.AuthRequest, err error) {
	authErr := autherrors.ToAuthError(err)
	c.JSON(authErr.HTTPStatus, gin.H{
		"error":             authErr.Code,
		"error_description": authErr.Description,
	})
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

func ssoAuthenticationFresh(authenticatedAt time.Time, maxAge *uint64, now time.Time) bool {
	if authenticatedAt.IsZero() || authenticatedAt.After(now) {
		return false
	}
	return maxAge == nil || (*maxAge != 0 && uint64(now.Unix()-authenticatedAt.Unix()) <= *maxAge)
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

// requiresConsent 没有持久化历史授权时，OIDC scope 必须由当前用户明确同意。
func requiresConsent(flow *types.AuthFlow) bool {
	if flow.ConsentGranted {
		return false
	}
	if flow.Request.Prompt.Contains(types.PromptConsent) || flow.Request.Scope.Contains("openid") {
		return true
	}
	for _, audience := range flow.Request.Audiences {
		if audience != nil {
			for scope := range strings.FieldsSeq(audience.Scope) {
				if scope == "openid" {
					return true
				}
			}
		}
	}
	return false
}

func (h *Handler) requestConsent(c *gin.Context, ctx context.Context, flow *types.AuthFlow, navigate func(*gin.Context, string)) bool {
	if !requiresConsent(flow) {
		return false
	}
	h.issueSSOCookie(c, ctx, flow)
	setAuthSessionCookie(c, flow.ID)
	navigate(c, withAuthorizationURL(config.GetEndpointConsent(), flow.AuthorizationURL))
	return true
}

func (h *Handler) consentFlow(c *gin.Context) *types.AuthFlow {
	flow := h.loadAuthFlow(c, c.Request.Context())
	if flow == nil {
		return nil
	}
	if flow.State != types.FlowStateAuthenticated || flow.User == nil || flow.Application == nil || !requiresConsent(flow) {
		h.errorResponse(c, autherrors.NewInvalidRequest("no pending consent"))
		return nil
	}
	return flow
}

// GetConsent 返回当前认证会话需要确认的全部 scope。
func (h *Handler) GetConsent(c *gin.Context) {
	flow := h.consentFlow(c)
	if flow == nil {
		return
	}
	scopeSet := make(map[string]struct{})
	for _, scope := range flow.Request.Scope {
		scopeSet[scope] = struct{}{}
	}
	for _, audience := range flow.Request.Audiences {
		if audience != nil {
			for scope := range strings.FieldsSeq(audience.Scope) {
				scopeSet[scope] = struct{}{}
			}
		}
	}
	names := make([]string, 0, len(scopeSet))
	for scope := range scopeSet {
		names = append(names, scope)
	}
	slices.Sort(names)
	scopes := make([]gin.H, 0, len(names))
	for _, name := range names {
		scopes = append(scopes, gin.H{"name": name, "description": name, "required": true})
	}
	c.JSON(http.StatusOK, gin.H{
		"client_name": flow.Application.Name,
		"client_logo": flow.Application.LogoURL,
		"scopes":      scopes,
		"user":        gin.H{"nickname": flow.User.GetNickname(), "avatar": flow.User.GetPicture()},
	})
}

// Consent 确认或拒绝当前认证会话的授权请求。
func (h *Handler) Consent(c *gin.Context) {
	var req struct {
		Confirm *bool `json:"confirm"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Confirm == nil {
		h.errorResponse(c, autherrors.NewInvalidRequest("confirm is required"))
		return
	}
	flow := h.consentFlow(c)
	if flow == nil {
		return
	}
	ctx := c.Request.Context()
	defer h.saveFlow(ctx, flow)
	if !*req.Confirm {
		flow.Fail(autherrors.NewAccessDenied("consent denied"))
		clearAuthSessionCookie(c)
		actionRedirect(c, authorizationErrorURL(flow.Request.RedirectURI, flow.Request.State, "access_denied", "consent denied"))
		return
	}
	flow.ConsentGranted = true
	authCode, err := h.authorizeAndGenerateCode(ctx, flow)
	if err != nil {
		h.errorResponse(c, err)
		return
	}
	clearAuthSessionCookie(c)
	actionRedirect(c, buildAuthCodeRedirectURL(flow.Request.RedirectURI, authCode))
}

func requiresFreshAuthentication(req *types.AuthRequest) bool {
	return req.Prompt.Contains(types.PromptLogin) || (req.MaxAge != nil && *req.MaxAge == 0)
}
