package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/heliantheon/aegis/config"
	autherrors "github.com/heliantheon/aegis/errors"
	"github.com/heliantheon/aegis/internal/authenticator/idp"
	"github.com/heliantheon/aegis/internal/cache"
	"github.com/heliantheon/aegis/internal/token"
	"github.com/heliantheon/aegis/internal/types"
	"github.com/heliantheon/aegis/models"
	"github.com/heliantheon/common/logger"
)

// prepareAuthorization 校验应用、回调、服务与连接配置并创建 AuthFlow。
func (h *Handler) prepareAuthorization(ctx context.Context, req *types.AuthRequest) (*types.AuthFlow, error) {
	if authErr := validateAuthorizeRequest(req); authErr != nil {
		return nil, authErr
	}
	app, err := h.provisionSvc.GetApplication(ctx, req.ClientID)
	if err != nil {
		return nil, autherrors.NewClientNotFoundf("application not found: %s", req.ClientID)
	}
	if !app.ValidateAllowedRedirectURI(req.RedirectURI) {
		return nil, autherrors.NewInvalidRequest("invalid redirect_uri")
	}
	flow := types.NewAuthFlow(req, time.Duration(config.GetCookieMaxAge())*time.Second, config.GetAuthFlowMaxLifetime())
	flow.Application = app
	audiences, authErr := collectAudiences(req)
	if authErr != nil {
		return flow, authErr
	}
	services, authErr := h.validateAudiences(ctx, req.ClientID, audiences)
	if authErr != nil {
		return flow, authErr
	}
	idpConfigs, err := h.provisionSvc.ListApplicationIDPConfigs(ctx, req.ClientID)
	if err != nil {
		return flow, autherrors.NewServerError("query idp configs failed")
	}
	if len(idpConfigs) == 0 {
		return flow, autherrors.NewNoConnectionAvailable("")
	}
	if len(req.Audiences) > 0 {
		flow.Services = services
	} else {
		flow.Service = &services[0]
	}
	flow.SetConnectionMap(h.authenticateSvc.SetConnections(idpConfigs))
	return flow, nil
}

// verifySSOToken 校验非空 SSO Token 的签名与类型。
func (h *Handler) verifySSOToken(ctx context.Context, raw string) (*token.SSOToken, error) {
	t, err := h.tokenSvc.Verify(ctx, raw)
	if err != nil {
		logger.Debugf("[Handler] SSO token 验证失败: %v", err)
		return nil, err
	}
	sso, ok := t.(*token.SSOToken)
	if !ok {
		logger.Debugf("[Handler] SSO token 类型不匹配: %T", t)
		return nil, fmt.Errorf("unexpected SSO token type: %T", t)
	}
	return sso, nil
}

// restoreSSO 从 flow.SSO 中恢复当前域的活跃用户到 flow 上。
func (h *Handler) restoreSSO(ctx context.Context, flow *types.AuthFlow) {
	domainID := flow.Application.DomainID
	openID := flow.SSO[domainID]
	if openID == "" {
		logger.Debugf("[Handler] SSO token 中无域 %s 的身份", domainID)
		return
	}
	user, err := h.userSvc.GetUser(ctx, openID)
	if err != nil {
		logger.Debugf("[Handler] SSO 用户查找失败: domain=%s, openID=%s, err=%v", domainID, openID, err)
		return
	}
	if !user.IsActive() {
		logger.Infof("[Handler] SSO 用户已禁用: domain=%s, openID=%s", domainID, user.OpenID)
		return
	}
	flow.SetAuthenticated(user)
	for connection, cfg := range flow.ConnectionMap {
		if cfg.Type == types.ConnTypeIDP {
			flow.SetConnection(connection)
			break
		}
	}
}

func (h *Handler) loadFlow(ctx context.Context, flowID string) (*types.AuthFlow, error) {
	if flowID == "" {
		return nil, autherrors.NewFlowNotFound("missing session")
	}
	flow := h.authenticateSvc.GetAndValidateFlow(ctx, flowID)
	if flow.Failed() {
		return flow, flowAuthError(flow)
	}
	return flow, nil
}

func flowAuthError(flow *types.AuthFlow) *autherrors.AuthError {
	if flow.Error == nil {
		return autherrors.NewServerError("unknown error")
	}
	return &autherrors.AuthError{
		HTTPStatus: flow.Error.HTTPStatus, Code: flow.Error.Code,
		Description: flow.Error.Description, Data: flow.Error.Data,
	}
}

// authenticateFlow 只执行认证；前置条件未满足或非 IDP 验证完成时返回 false 暂停后续步骤。
func (h *Handler) authenticateFlow(ctx context.Context, flow *types.AuthFlow, req *LoginRequest) (bool, error) {
	cfg := flow.GetCurrentConnConfig()
	if cfg == nil {
		return false, autherrors.NewInvalidRequestf("unknown connection: %s", flow.Connection)
	}
	if !cfg.Verified {
		if len(unmetRequirements(flow)) > 0 {
			return false, nil
		}
		passed, err := h.authenticateSvc.Authenticate(ctx, flow, req.Proof, req.Principal, req.Strategy, req.UID)
		if err != nil {
			return false, err
		}
		if !passed {
			return false, autherrors.NewInvalidCredentials("authentication failed")
		}
	}
	return cfg.Type == types.ConnTypeIDP && len(unmetRequirements(flow)) == 0, nil
}

func (h *Handler) initiateIDP(ctx context.Context, flow *types.AuthFlow, req *IDPInitiateRequest) (*IDPInitiateResponse, string, error) {
	initiator, err := h.idpInitiator(req.Connection)
	if err != nil {
		return nil, "", err
	}
	initiation := &idp.InitiateContext{Flow: flow}
	if idp.IsOAuthRedirectConnection(req.Connection) {
		initiation.Transaction, err = idp.NewOAuthTransaction(flow.ID, req.Connection, config.GetIDPRedirectURI(req.Connection))
		if err != nil {
			return nil, "", autherrors.NewServerError("oauth transaction initialization failed")
		}
	}
	resp, err := initiator.Initiate(ctx, initiation, req.Strategy)
	if err != nil {
		return nil, "", autherrors.NewServerErrorf("idp initiate failed: %v", err)
	}
	if idp.IsOAuthRedirectConnection(req.Connection) {
		if resp.URL == "" {
			return nil, "", autherrors.NewServerError("oauth authorization URL is empty")
		}
		if err := validateOAuthAuthorizationURL(flow.Connection, resp.URL, initiation.Transaction); err != nil {
			return nil, "", autherrors.NewServerError("oauth authorization URL is invalid")
		}
		if err := h.authenticateSvc.SaveOAuthTransaction(ctx, initiation.Transaction, config.GetOAuthStateExpiresIn()); err != nil {
			return nil, "", autherrors.NewServerError("save oauth transaction failed")
		}
		return nil, resp.URL, nil
	}
	return &IDPInitiateResponse{
		Connection: req.Connection, UID: resp.UID, URL: resp.URL,
		Action: resp.Action, Params: resp.Params, Options: resp.Options,
	}, "", nil
}

func (h *Handler) linkIdentifiedUser(ctx context.Context, flow *types.AuthFlow) error {
	identity := flow.GetIdentity(flow.Connection)
	if identity == nil {
		return autherrors.NewServerError("identity not found in flow")
	}
	now := time.Now()
	linked := &models.UserIdentity{
		Domain: identity.Domain, IDP: identity.IDP, TOpenID: identity.TOpenID,
		UID: flow.User.OpenID, RawData: identity.RawData, CreatedAt: now, UpdatedAt: now,
	}
	if err := h.userSvc.LinkIdentity(ctx, linked); err != nil {
		return autherrors.NewServerError("identity linking failed")
	}
	identities, err := h.userSvc.ListIdentitiesByIdentity(ctx, linked)
	if err != nil {
		return autherrors.NewServerError("failed to load identities")
	}
	flow.Identities = identities
	flow.SetAuthenticated(flow.User)
	return nil
}

func (h *Handler) respondAuthorize(c *gin.Context, flow *types.AuthFlow, authCode *cache.AuthorizationCode) {
	switch flow.State {
	case types.FlowStateInitialized:
		setAuthSessionCookie(c, flow.ID)
		actionRedirect(c, config.GetEndpointLogin())
	case types.FlowStateCompleted:
		if authCode == nil {
			h.respondAuthorizeError(c, flow, autherrors.NewServerError("completed authentication has no authorization code"))
			return
		}
		if len(flow.SSO) > 0 {
			h.issueSSOCookie(c, c.Request.Context(), flow)
		}
		actionRedirect(c, buildAuthCodeRedirectURL(flow.Request.RedirectURI, authCode))
	default:
		h.respondAuthorizeError(c, flow, autherrors.NewServerError("authentication flow has no response outcome"))
	}
}

func (h *Handler) respondAuthorizeError(c *gin.Context, _ *types.AuthFlow, err error) {
	authErr := autherrors.ToAuthError(err)
	c.JSON(authErr.HTTPStatus, gin.H{"error": authErr.Code, "error_description": authErr.Description})
}

// respondFlow 根据 flow.State 与可选的 authCode 统一交付认证结果。
// browser 为 true 时使用 HTTP 303 浏览器跳转，否则使用 HTTP 300 动作指令。
func (h *Handler) respondFlow(c *gin.Context, flow *types.AuthFlow, authCode *cache.AuthorizationCode, browser bool) {
	switch flow.State {
	case types.FlowStateInitialized:
		h.respondPendingFlow(c, flow, browser)
	case types.FlowStateCompleted:
		if authCode == nil {
			h.errorResponse(c, autherrors.NewServerError("completed authentication has no authorization code"))
			return
		}
		h.issueSSOCookie(c, c.Request.Context(), flow)
		clearAuthSessionCookie(c)
		location := buildAuthCodeRedirectURL(flow.Request.RedirectURI, authCode)
		if browser {
			browserRedirect(c, location)
		} else {
			actionRedirect(c, location)
		}
	default:
		h.errorResponse(c, autherrors.NewServerError("authentication flow has no response outcome"))
	}
}

func (h *Handler) respondPendingFlow(c *gin.Context, flow *types.AuthFlow, browser bool) {
	if cfg := flow.GetCurrentConnConfig(); cfg != nil && cfg.Type != types.ConnTypeIDP {
		actionRedirect(c, config.GetEndpointLogin())
		return
	}
	if actions := unmetRequirements(flow); len(actions) > 0 {
		actionRedirect(c, buildActionURL(actions))
		return
	}
	if flow.IdentifiedUser() {
		if browser {
			browserRedirect(c, "/binding")
		} else {
			actionRedirect(c, buildActionURL([]string{"identify"}))
		}
		return
	}
	actionRedirect(c, buildActionURL(nil))
}

func (h *Handler) respondFlowError(c *gin.Context, flow *types.AuthFlow, err error) {
	authErr := autherrors.ToAuthError(err)
	if flow != nil && flow.Failed() && (authErr.Code == autherrors.CodeFlowNotFound || authErr.Code == autherrors.CodeFlowExpired) {
		clearAuthSessionCookie(c)
	}
	h.errorResponse(c, authErr)
}
