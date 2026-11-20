package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const grantConsentScript = `
for i = 2, #ARGV do
    redis.call('SADD', KEYS[1], ARGV[i])
end
return redis.call('PEXPIRE', KEYS[1], ARGV[1])
`

func consentKey(domainID, openID, clientID string) string {
	identity, _ := json.Marshal([3]string{domainID, openID, clientID})
	digest := sha256.Sum256(identity)
	return "aegis:consent:" + hex.EncodeToString(digest[:])
}

// GetConsent 返回各资源已同意的 scope，空资源 ID 表示身份声明范围。
// 没有同意记录时返回 nil。
func (cm *Manager) GetConsent(ctx context.Context, domainID, openID, clientID string) (map[string][]string, error) {
	members, err := cm.redis.SMembers(ctx, consentKey(domainID, openID, clientID))
	if err != nil {
		return nil, fmt.Errorf("get consent: %w", err)
	}
	if len(members) == 0 {
		return nil, nil
	}

	scopes := make(map[string][]string)
	for _, member := range members {
		var fact []*string
		if err := json.Unmarshal([]byte(member), &fact); err != nil {
			return nil, fmt.Errorf("decode consent fact: %w", err)
		}
		if len(fact) != 2 || fact[0] == nil || fact[1] == nil || *fact[1] == "" {
			return nil, fmt.Errorf("invalid consent fact %q", member)
		}
		scopes[*fact[0]] = append(scopes[*fact[0]], *fact[1])
	}
	return scopes, nil
}

// GrantConsent 原子合并同意范围并刷新过期时间。
func (cm *Manager) GrantConsent(ctx context.Context, domainID, openID, clientID string, scopes map[string][]string, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("consent TTL must be positive")
	}
	milliseconds := ttl.Milliseconds()
	if ttl%time.Millisecond != 0 {
		milliseconds++
	}
	count := 0
	for _, resourceScopes := range scopes {
		count += len(resourceScopes)
	}
	if count == 0 {
		return nil
	}
	args := make([]any, 1, count+1)
	args[0] = milliseconds
	for resource, resourceScopes := range scopes {
		for _, scope := range resourceScopes {
			if scope == "" {
				return fmt.Errorf("consent scope must not be empty")
			}
			fact, _ := json.Marshal([2]string{resource, scope})
			args = append(args, string(fact))
		}
	}
	if _, err := cm.redis.Eval(ctx, grantConsentScript, []string{consentKey(domainID, openID, clientID)}, args...); err != nil {
		return fmt.Errorf("grant consent: %w", err)
	}
	return nil
}
