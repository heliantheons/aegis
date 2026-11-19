package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// ProtectCookieRequests 统一保护使用浏览器自动携带 Cookie 的状态变更接口。
// 信任来自服务配置；请求必须提供可信 Origin、同源 Fetch Metadata 或可信 Referer。
func ProtectCookieRequests(trustedOrigin string) gin.HandlerFunc {
	trusted := normalizeOrigin(strings.TrimRight(trustedOrigin, "/"))
	return func(c *gin.Context) {
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}
		if !trustedCookieRequest(c, trusted) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}

func trustedCookieRequest(c *gin.Context, trusted string) bool {
	if trusted == "" || c.GetHeader("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	if origin := c.GetHeader("Origin"); origin != "" {
		return origin == trusted || normalizeOrigin(origin) == trusted
	}
	if c.GetHeader("Sec-Fetch-Site") == "same-origin" {
		return true
	}
	if referer, err := url.Parse(c.GetHeader("Referer")); err == nil && referer != nil && referer.User == nil {
		return normalizeOrigin(referer.Scheme+"://"+referer.Host) == trusted
	}
	return false
}
