package middleware

import "github.com/gin-gonic/gin"

// NoStore 禁止 HTTP 缓存保存响应，兼容需要 Pragma 的旧客户端。
// 在下游执行前设置，确保错误、跳转和成功响应具有相同策略。
func NoStore(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Next()
}

// NoReferrer 限制浏览器导航中的 Referer 传播。
func NoReferrer(c *gin.Context) {
	c.Header("Referrer-Policy", "no-referrer")
	c.Next()
}
