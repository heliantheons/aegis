package auth

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/heliantheon/aegis/internal/types"
)

// consentScopes 将身份声明和各资源的 scope 分开，避免跨资源复用同意。
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
