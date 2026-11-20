package cache

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"

	pkgredis "github.com/heliantheon/common/redis"
)

// This stub models set union and captures the script boundary; it does not
// execute Lua or prove Redis atomicity and expiration behavior.
type consentRedisStub struct {
	pkgredis.Client
	sets     map[string]map[string]struct{}
	ttls     map[string]int64
	readErr  error
	writeErr error
	writes   int
}

func (s *consentRedisStub) SMembers(_ context.Context, key string) ([]string, error) {
	if s.readErr != nil {
		return nil, s.readErr
	}
	var members []string
	for member := range s.sets[key] {
		members = append(members, member)
	}
	return members, nil
}

func (s *consentRedisStub) Eval(_ context.Context, script string, keys []string, args ...any) (any, error) {
	s.writes++
	if s.writeErr != nil {
		return nil, s.writeErr
	}
	if script != grantConsentScript || len(keys) != 1 || len(args) < 2 {
		return nil, errors.New("unexpected consent script invocation")
	}
	if s.sets == nil {
		s.sets = make(map[string]map[string]struct{})
		s.ttls = make(map[string]int64)
	}
	if s.sets[keys[0]] == nil {
		s.sets[keys[0]] = make(map[string]struct{})
	}
	for _, arg := range args[1:] {
		member, ok := arg.(string)
		if !ok {
			return nil, errors.New("unexpected consent fact")
		}
		s.sets[keys[0]][member] = struct{}{}
	}
	ttl, ok := args[0].(int64)
	if !ok {
		return nil, errors.New("unexpected consent TTL")
	}
	s.ttls[keys[0]] = ttl
	return int64(1), nil
}

func TestConsentIsolationAndUnion(t *testing.T) {
	ctx := context.Background()
	redis := &consentRedisStub{}
	manager := &Manager{redis: redis}
	identities := [][3]string{
		{"domain", "user", "client"},
		{"other-domain", "user", "client"},
		{"domain", "other-user", "client"},
		{"domain", "user", "other-client"},
		{"a:b", "c", "d"},
		{"a", "b:c", "d"},
	}
	for i, identity := range identities {
		scopes := map[string][]string{"": {"openid"}, identity[0]: {identity[1]}}
		if err := manager.GrantConsent(ctx, identity[0], identity[1], identity[2], scopes, time.Minute); err != nil {
			t.Fatalf("grant identity %d: %v", i, err)
		}
	}
	for _, identity := range identities {
		got, err := manager.GetConsent(ctx, identity[0], identity[1], identity[2])
		want := map[string][]string{"": {"openid"}, identity[0]: {identity[1]}}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("get %v = %v, %v; want %v", identity, got, err, want)
		}
	}

	additional := map[string][]string{"": {"openid", "profile"}, "other-api": {"write"}, "api:read": {"write"}, "api": {"read", "read", "read:write"}}
	if err := manager.GrantConsent(ctx, "domain", "user", "client", additional, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	got, err := manager.GetConsent(ctx, "domain", "user", "client")
	if err != nil {
		t.Fatal(err)
	}
	for _, scopes := range got {
		sort.Strings(scopes)
	}
	want := map[string][]string{"": {"openid", "profile"}, "domain": {"user"}, "api": {"read", "read:write"}, "other-api": {"write"}, "api:read": {"write"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged consent = %v, want %v", got, want)
	}
	if gotTTL := redis.ttls[consentKey("domain", "user", "client")]; gotTTL != (2 * time.Minute).Milliseconds() {
		t.Fatalf("TTL = %d", gotTTL)
	}
	if got, err := manager.GetConsent(ctx, "missing", "user", "client"); got != nil || err != nil {
		t.Fatalf("missing consent = %v, %v", got, err)
	}
}

func TestConsentMalformedFacts(t *testing.T) {
	for _, member := range []string{"invalid", "null", "[]", `["api"]`, `["api","read","extra"]`, `[null,"read"]`, `["api",null]`, `["api",1]`, `["api",""]`} {
		t.Run(member, func(t *testing.T) {
			redis := &consentRedisStub{sets: map[string]map[string]struct{}{consentKey("domain", "user", "client"): {member: {}}}}
			got, err := (&Manager{redis: redis}).GetConsent(context.Background(), "domain", "user", "client")
			if err == nil || got != nil {
				t.Fatalf("malformed consent = %v, %v", got, err)
			}
		})
	}
}

func TestConsentErrorsAndInvalidTTL(t *testing.T) {
	ctx := context.Background()
	failure := errors.New("redis unavailable")
	redis := &consentRedisStub{readErr: failure, writeErr: failure}
	manager := &Manager{redis: redis}
	if got, err := manager.GetConsent(ctx, "domain", "user", "client"); got != nil || !errors.Is(err, failure) {
		t.Fatalf("read error = %v, %v", got, err)
	}
	scopes := map[string][]string{"": {"openid"}}
	if err := manager.GrantConsent(ctx, "domain", "user", "client", scopes, time.Minute); !errors.Is(err, failure) {
		t.Fatalf("write error = %v", err)
	}
	writes := redis.writes
	for _, ttl := range []time.Duration{0, -time.Second} {
		if err := manager.GrantConsent(ctx, "domain", "user", "client", scopes, ttl); err == nil {
			t.Fatalf("TTL %v accepted", ttl)
		}
	}
	if redis.writes != writes {
		t.Fatal("invalid TTL wrote to Redis")
	}
	redis.writeErr = nil
	if err := manager.GrantConsent(ctx, "domain", "user", "client", scopes, time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	if got := redis.ttls[consentKey("domain", "user", "client")]; got != 1 {
		t.Fatalf("sub-millisecond TTL = %d, want 1", got)
	}
}
