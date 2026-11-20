package auth

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/heliantheon/aegis/config"
	autherrors "github.com/heliantheon/aegis/errors"
	"github.com/heliantheon/aegis/internal/types"
)

func validateAuthorizationPrompt(prompts []string) *autherrors.AuthError {
	for i, prompt := range prompts {
		if slices.Contains(prompts[:i], prompt) {
			return autherrors.NewInvalidRequest("prompt values must not repeat")
		}
		if prompt != types.PromptNone && prompt != types.PromptLogin && prompt != types.PromptConsent {
			return autherrors.NewInvalidRequest("unsupported prompt")
		}
	}
	if slices.Contains(prompts, types.PromptNone) && len(prompts) != 1 {
		return autherrors.NewInvalidRequest("prompt none cannot be combined with other values")
	}
	return nil
}

func ssoAuthenticationFresh(authenticatedAt time.Time, maxAge *uint64, now time.Time) bool {
	if authenticatedAt.After(now) {
		return false
	}
	if maxAge == nil {
		return true
	}
	return !authenticatedAt.IsZero() && *maxAge != 0 && uint64(now.Unix()-authenticatedAt.Unix()) <= *maxAge
}

// consentScopes 组织本次请求的用户同意范围，不决定实际签发的权限。
func consentScopes(req *types.AuthRequest) map[string][]string {
	scopes := make(map[string][]string, len(req.Audiences)+2)
	scopes[""] = req.Scope
	if req.Audience != "" {
		scopes[req.Audience] = req.Scope
	}
	for audience, requested := range req.Audiences {
		scopes[audience] = strings.Fields(requested.Scope)
	}
	return scopes
}

// requiresConsent 复用已同意的范围，显式 consent 始终要求本次确认。
func (h *Handler) requiresConsent(ctx context.Context, flow *types.AuthFlow) (bool, error) {
	if flow.ConsentGranted {
		return false, nil
	}
	if flow.Request.Prompt.Contains(types.PromptConsent) {
		return true, nil
	}
	requested := consentScopes(flow.Request)
	oidc := false
	for _, scopes := range requested {
		if slices.Contains(scopes, "openid") {
			oidc = true
			break
		}
	}
	if !oidc {
		return false, nil
	}
	granted, err := h.cache.GetConsent(ctx, flow.Application.DomainID, flow.User.OpenID, flow.Application.AppID)
	if err != nil {
		return false, fmt.Errorf("check consent: %w", err)
	}
	for audience, scopes := range requested {
		for _, scope := range scopes {
			if !slices.Contains(granted[audience], scope) {
				return true, nil
			}
		}
	}
	return false, nil
}

func (h *Handler) requestConsent(c *gin.Context, ctx context.Context, flow *types.AuthFlow, navigate func(*gin.Context, string)) bool {
	consent, err := h.requiresConsent(ctx, flow)
	if err != nil {
		authorizationError(c, flow.Request, autherrors.NewServerError("check consent failed"))
		return true
	}
	if !consent {
		return false
	}
	if flow.Request.Prompt.Contains(types.PromptNone) {
		authorizationError(c, flow.Request, autherrors.New(http.StatusBadRequest, "consent_required", "explicit consent is required"))
		return true
	}
	h.issueSSOCookie(c, ctx, flow)
	setAuthSessionCookie(c, flow.ID)
	navigate(c, config.GetEndpointConsent())
	return true
}

func (h *Handler) consentFlow(c *gin.Context) *types.AuthFlow {
	flow := h.loadAuthFlow(c, c.Request.Context())
	if flow == nil {
		return nil
	}
	if flow.State != types.FlowStateAuthenticated || flow.User == nil || flow.Application == nil || flow.ConsentGranted {
		h.errorResponse(c, autherrors.NewInvalidRequest("no pending consent"))
		return nil
	}
	consent, err := h.requiresConsent(c.Request.Context(), flow)
	if err != nil {
		h.errorResponse(c, autherrors.NewServerError("check consent failed"))
		return nil
	}
	if !consent {
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
	if err := h.cache.GrantConsent(ctx, flow.Application.DomainID, flow.User.OpenID, flow.Application.AppID, consentScopes(flow.Request), config.GetSSOTTL()); err != nil {
		h.errorResponse(c, autherrors.NewServerError("save consent failed"))
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
