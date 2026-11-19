package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	wildcard             = "*"
	defaultAllowMethods  = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
	defaultAllowHeaders  = "Content-Type, Authorization, X-Requested-With, traceparent, tracestate, baggage"
	defaultExposeHeaders = "Location, WWW-Authenticate, X-Trace-ID"
	defaultMaxAge        = "86400"
)

// OriginResolver 返回允许写入响应的 Origin，空字符串表示不开放跨域读取。
type OriginResolver func(string) string

// CORSOptions 按来源、凭证和方法组合跨域行为，与认证协议无关。
type CORSOptions struct {
	ResolveOrigin    OriginResolver
	AllowCredentials bool
	AllowMethods     []string
}

// AnyOrigin 允许任意来源读取不携带凭证的响应。
func AnyOrigin(_ string) string { return wildcard }

// CORS 使用同一实现处理预检、凭证和响应头暴露。
func CORS(options CORSOptions) gin.HandlerFunc {
	methods := defaultAllowMethods
	if len(options.AllowMethods) > 0 {
		methods = strings.Join(options.AllowMethods, ", ")
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		allowed := false
		if origin != "" && options.ResolveOrigin != nil {
			allowed = setCORSHeaders(c, &options, origin, methods)
		}
		if c.Request.Method == http.MethodOptions && origin != "" && c.GetHeader("Access-Control-Request-Method") != "" {
			if !allowed {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func setCORSHeaders(c *gin.Context, options *CORSOptions, origin, methods string) bool {
	allowedOrigin := options.ResolveOrigin(origin)
	if allowedOrigin != wildcard || options.AllowCredentials {
		c.Writer.Header().Add("Vary", "Origin")
	}
	if allowedOrigin == "" {
		return false
	}
	if options.AllowCredentials && allowedOrigin == wildcard {
		allowedOrigin = origin
	}
	c.Header("Access-Control-Allow-Origin", allowedOrigin)
	c.Header("Access-Control-Allow-Methods", methods)
	c.Header("Access-Control-Allow-Headers", defaultAllowHeaders)
	c.Header("Access-Control-Expose-Headers", defaultExposeHeaders)
	c.Header("Access-Control-Max-Age", defaultMaxAge)
	if options.AllowCredentials {
		c.Header("Access-Control-Allow-Credentials", "true")
	}
	return true
}
