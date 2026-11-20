package middleware

import (
	"net/url"
	"strings"
)

// AllowedOrigins 仅根据服务配置判断来源，不解析业务请求或访问应用缓存。
func AllowedOrigins(origins []string) OriginResolver {
	allowed := make([]string, 0, len(origins))
	for _, origin := range origins {
		if origin == wildcard {
			allowed = append(allowed, wildcard)
		} else if normalized := normalizeOrigin(strings.TrimRight(origin, "/")); normalized != "" {
			allowed = append(allowed, normalized)
		}
	}
	return func(origin string) string {
		for _, candidate := range allowed {
			if candidate != wildcard && candidate == origin {
				return origin
			}
		}
		normalized := normalizeOrigin(origin)
		if normalized == "" {
			return ""
		}
		for _, candidate := range allowed {
			if candidate == wildcard {
				return wildcard
			}
			if candidate == normalized {
				return origin
			}
		}
		return ""
	}
}

func normalizeOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Hostname() == "" || u.Opaque != "" || u.Path != "" || strings.ContainsAny(raw, "?#") {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return ""
	}
	host := strings.ToLower(u.Host)
	if port := u.Port(); (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		host = strings.TrimSuffix(host, ":"+port)
	}
	return scheme + "://" + host
}
