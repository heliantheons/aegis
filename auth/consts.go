package auth

// ==================== 常量 ====================

const (
	HeaderAuthorization = "Authorization" // Authorization 请求头
	BearerPrefix        = "Bearer "       // Bearer Token 前缀

	// Query 参数
	QueryClientID = "client_id" // Client ID 查询参数

	// Cookie
	AuthSessionCookie = "aegis-session" // Auth 会话 Cookie 名称
)
