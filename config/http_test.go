package config

import (
	"os"
	"reflect"
	"testing"

	baseconfig "github.com/heliantheon/common/config"
)

func TestMain(m *testing.M) {
	directory, err := os.MkdirTemp("", "aegis-http-config-test-")
	if err != nil {
		panic(err)
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(directory+"/config.toml", []byte("[aegis]\nendpoint = 'https://aegis.example'\n"), 0600); err != nil {
		panic(err)
	}
	if err := os.Chdir(directory); err != nil {
		panic(err)
	}
	baseconfig.LoadAegis()
	if err := os.Chdir(workingDirectory); err != nil {
		panic(err)
	}
	code := m.Run()
	if err := os.RemoveAll(directory); err != nil {
		panic(err)
	}
	os.Exit(code)
}

func setHTTPTestConfig(t *testing.T, key string, value any) {
	t.Helper()
	previous := Cfg().Get(key)
	Cfg().Set(key, value)
	t.Cleanup(func() { Cfg().Set(key, previous) })
}

func TestCORSOriginsIncludeServiceAndConfiguredFrontends(t *testing.T) {
	setHTTPTestConfig(t, "aegis.endpoint", "https://aegis.example")
	for _, tt := range []struct {
		name         string
		extras, want []string
	}{
		{"service only", nil, []string{"https://aegis.example"}},
		{"trusted login frontend", []string{"https://login.example"}, []string{"https://aegis.example", "https://login.example"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			setHTTPTestConfig(t, "cors.origins", tt.extras)
			if got := GetCORSOrigins(); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("GetCORSOrigins() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHTTPOriginValidation(t *testing.T) {
	setHTTPTestConfig(t, "aegis.endpoint", "https://aegis.example")
	setHTTPTestConfig(t, "cors.origins", []string{})
	if err := validateHTTPOrigins(); err != nil {
		t.Fatalf("empty optional origins rejected: %v", err)
	}
	for _, origin := range []string{"*", "null", "", "https://*.example", "https://ui.example/", "https://ui.example/path", "https://ui.example?", "https://ui.example#", "https://user@ui.example", "file://ui.example", "https://"} {
		t.Run(origin, func(t *testing.T) {
			setHTTPTestConfig(t, "cors.origins", []string{origin})
			if err := validateHTTPOrigins(); err == nil {
				t.Fatalf("invalid trusted origin accepted: %q", origin)
			}
		})
	}
	Cfg().Set("cors.origins", []string{"https://ui.example", "http://localhost:18000"})
	if err := validateHTTPOrigins(); err != nil {
		t.Fatal(err)
	}
}
