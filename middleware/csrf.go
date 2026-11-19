package middleware

import (
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

// ProtectCookieRequests 统一保护使用浏览器自动携带 Cookie 的状态变更接口。
// 信任来自服务配置；请求必须提供可信 Origin、同源 Fetch Metadata 或可信 Referer。
func ProtectCookieRequests(trustedOrigins []string) gin.HandlerFunc {
	trusted := make([]string, 0, len(trustedOrigins))
	for _, origin := range trustedOrigins {
		if normalized := normalizeOrigin(origin); normalized != "" {
			trusted = append(trusted, normalized)
		}
	}
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

func trustedCookieRequest(c *gin.Context, trusted []string) bool {
	if len(trusted) == 0 {
		return false
	}
	if origin := c.GetHeader("Origin"); origin != "" {
		return containsOrigin(trusted, origin)
	}
	if c.GetHeader("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	if c.GetHeader("Sec-Fetch-Site") == "same-origin" {
		return true
	}
	if referer, err := url.Parse(c.GetHeader("Referer")); err == nil && referer != nil && referer.User == nil {
		return containsOrigin(trusted, referer.Scheme+"://"+referer.Host)
	}
	return false
}

func containsOrigin(origins []string, origin string) bool {
	for _, candidate := range origins {
		if candidate == origin {
			return true
		}
	}
	normalized := normalizeOrigin(origin)
	if normalized == "" {
		return false
	}
	for _, candidate := range origins {
		if candidate == normalized {
			return true
		}
	}
	return false
}
