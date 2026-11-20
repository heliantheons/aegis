package main

import (
	"context"
	"fmt"
	"os"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/heliantheon/aegis-go/guard"
	"github.com/heliantheon/aegis/auth"
	aegisconfig "github.com/heliantheon/aegis/config"
	"github.com/heliantheon/aegis/internal/cache"
	"github.com/heliantheon/aegis/middleware"
	hermesrpc "github.com/heliantheon/aegis/rpc/hermes"
	"github.com/heliantheon/common/config"
	"github.com/heliantheon/common/logger"
	"github.com/heliantheon/common/observability"
	pkgredis "github.com/heliantheon/common/redis"
)

func main() {
	config.LoadAegis()
	logger.InitWithConfig(logger.Config{
		Format: config.GetLogFormat(),
		Level:  config.GetLogLevel(),
		Debug:  config.IsDebug(),
	})
	defer logger.Sync()
	defer initTracing()()
	if err := aegisconfig.Validate(); err != nil {
		logger.Fatalf("Aegis 配置校验失败: %v", err)
	}

	hermesAddr := os.Getenv("HERMES_GRPC_ADDR")
	if hermesAddr == "" {
		hermesAddr = "hermes:50051"
	}
	conn, err := grpc.NewClient(
		hermesAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithStatsHandler(observability.GRPCClientStatsHandler()),
	)
	if err != nil {
		logger.Fatalf("连接 hermes gRPC 失败: %v", err)
	}
	defer conn.Close()

	client := hermesrpc.New(conn)

	if err := initTokenManager(); err != nil {
		logger.Fatalf("初始化 Aegis token manager 失败: %v", err)
	}

	redisURL := aegisconfig.Cfg().GetString("redis.url")
	if redisURL == "" {
		redisURL = "redis://localhost:6379/0"
	}
	redis, err := pkgredis.NewClient(redisURL)
	if err != nil {
		logger.Fatalf("连接 Redis 失败: %v", err)
	}
	logger.Infof("[Auth] Redis 连接成功")

	cacheManager := cache.NewManager(client, redis)
	aegisHandler, err := initializeAegis(client, cacheManager)
	if err != nil {
		logger.Fatalf("初始化 aegis 失败: %v", err)
	}

	if !config.IsDebug() {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(observability.GinMiddleware("aegis")...)
	r.Use(gin.Recovery())
	r.RedirectTrailingSlash = false

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	loginOrigins := aegisconfig.GetCORSOrigins()
	corsOptions := middleware.CORSOptions{
		ResolveOrigin:    middleware.AllowedOrigins(loginOrigins),
		AllowCredentials: true,
	}
	cookieProtection := middleware.ProtectCookieRequests(loginOrigins)

	api := r.Group("/api")
	registerAuthRoutes(api, aegisHandler, corsOptions, cookieProtection)

	if err := registerAccountRoutes(api, aegisHandler, aegisconfig.GetIrisAudience()); err != nil {
		logger.Fatalf("初始化 Iris 鉴权中间件失败: %v", err)
	}

	addr := fmt.Sprintf(":%d", config.GetServerPort())
	logger.Infof("aegis 服务启动: %s", addr)
	if err := r.Run(addr); err != nil {
		logger.Fatalf("服务启动失败: %v", err)
	}
}

func initTracing() func() {
	shutdown, err := observability.Init(context.Background(), observability.Config{ServiceName: "aegis"})
	if err != nil {
		logger.Warnf("初始化 OpenTelemetry 失败，链路追踪保持降级: %v", err)
	}
	return shutdown
}

func initTokenManager() error {
	endpoint := aegisconfig.GetIssuer()
	audience := aegisconfig.GetIrisAudience()
	seed, err := aegisconfig.GetIrisSecretKeyBytes()
	if err != nil {
		return fmt.Errorf("加载 Iris 服务密钥: %w", err)
	}
	return configureProfileTokenManager(endpoint, audience, seed)
}

func configureProfileTokenManager(endpoint, audience string, seed []byte) error {
	return guard.NewServiceTokenManager(endpoint, audience, seed)
}

func registerAuthRoutes(api *gin.RouterGroup, aegisHandler *auth.Handler, corsOptions middleware.CORSOptions, cookieProtection gin.HandlerFunc) {
	publicOptions := middleware.CORSOptions{
		ResolveOrigin: middleware.AnyOrigin,
		AllowMethods:  []string{"GET", "OPTIONS"},
	}
	public := api.Group("", middleware.Preflight(publicOptions), middleware.CORS(publicOptions))
	public.GET("/.well-known/openid-configuration", aegisHandler.Discovery)
	public.GET("/jwks", aegisHandler.JWKS)
	public.GET("/pubkeys", aegisHandler.PublicKeys)
	for _, path := range []string{"/.well-known/openid-configuration", "/jwks", "/pubkeys"} {
		public.OPTIONS(path)
	}
	protocol := api.Group("", middleware.Preflight(middleware.CORSOptions{
		ResolveOrigin: middleware.AnyOrigin,
		AllowMethods:  []string{"GET", "POST", "OPTIONS"},
	}), middleware.NoStore)
	protocol.GET("/userinfo", aegisHandler.UserInfo)
	protocol.POST("/userinfo", aegisHandler.UserInfo)
	protocol.POST("/token", aegisHandler.Token)
	protocol.POST("/revoke", aegisHandler.Revoke)
	for _, path := range []string{"/userinfo", "/token", "/revoke"} {
		protocol.OPTIONS(path)
	}

	api.GET("/authorize", middleware.NoStore, middleware.NoReferrer, aegisHandler.Authorize(auth.QueryParameters, auth.BrowserResponse))
	api.POST("/authorize", middleware.NoStore, middleware.NoReferrer, aegisHandler.Authorize(auth.BodyParameters, auth.BrowserResponse))
	sessions := api.Group("", middleware.Preflight(corsOptions), middleware.CORS(corsOptions), middleware.NoStore, cookieProtection)
	authRoutes := []struct {
		method, path string
		handler      gin.HandlerFunc
	}{
		{"GET", "/consent", aegisHandler.GetConsent},
		{"POST", "/consent", aegisHandler.Consent},
		{"GET", "/connections", aegisHandler.GetConnections},
		{"GET", "/context", aegisHandler.GetContext},
		{"POST", "/login", aegisHandler.Login},
		{"POST", "/idps", aegisHandler.IDPs},
		{"GET", "/binding", aegisHandler.GetIdentifyContext},
		{"POST", "/binding", aegisHandler.ConfirmIdentify},
		{"POST", "/challenge", aegisHandler.InitiateChallenge},
		{"POST", "/challenge/:cid", aegisHandler.ContinueChallenge},
		{"POST", "/logout", aegisHandler.Logout},
		{"GET", "/logout", aegisHandler.LogoutGET},
	}
	registered := make(map[string]bool)
	for _, route := range authRoutes {
		sessions.Handle(route.method, route.path, route.handler)
		if !registered[route.path] {
			sessions.OPTIONS(route.path)
			registered[route.path] = true
		}
	}
	api.GET("/idps/:connection/callback", middleware.NoStore, middleware.NoReferrer, aegisHandler.OAuthCallback)
	api.POST("/check", middleware.NoStore, aegisHandler.Check)
}

func registerAccountRoutes(api *gin.RouterGroup, aegisHandler *auth.Handler, audience string) error {
	irisGuard, err := guard.NewGin(audience)
	if err != nil {
		return err
	}
	profile := aegisHandler.Profile()
	accounts := api.Group("", middleware.NoStore, irisGuard.Require())
	userRoutes := []struct {
		method, path string
		handler      gin.HandlerFunc
	}{
		{"GET", "/profile", profile.GetProfile},
		{"PATCH", "/profile", profile.UpdateProfile},
		{"GET", "/identities", profile.ListIdentities},
		{"POST", "/identities/:idp", profile.BindIdentity},
		{"DELETE", "/identities/:idp", profile.UnbindIdentity},
		{"GET", "/mfa", profile.GetMFAStatus},
		{"POST", "/mfa", profile.SetupMFA},
		{"POST", "/mfa/:uid", profile.CompleteMFA},
		{"PATCH", "/mfa", profile.UpdateMFA},
		{"DELETE", "/mfa", profile.DeleteMFA},
	}
	for _, route := range userRoutes {
		accounts.Handle(route.method, route.path, route.handler)
	}
	return nil
}
