package idp

import "testing"

func TestLoginPrincipal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		params []any
		want   string
		ok     bool
	}{
		{name: "principal follows app id", params: []any{"grafana", "user@example.com", "password", ""}, want: "user@example.com", ok: true},
		{name: "missing principal", params: []any{"grafana"}},
		{name: "empty principal", params: []any{"grafana", ""}},
		{name: "non-string principal", params: []any{"grafana", 42}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := LoginPrincipal(tt.params...)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("LoginPrincipal() = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.ok)
			}
		})
	}
}
