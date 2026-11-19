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

func TestUIOriginsAlwaysIncludeEndpointAndStayIndependent(t *testing.T) {
	setHTTPTestConfig(t, "aegis.endpoint", "https://aegis.example")
	setHTTPTestConfig(t, "cors.login-origins", []string{})
	setHTTPTestConfig(t, "cors.management-origins", []string{})
	for _, origins := range [][]string{GetLoginOrigins(), GetManagementOrigins()} {
		if !reflect.DeepEqual(origins, []string{"https://aegis.example"}) {
			t.Fatalf("empty extra policy lost primary UI: %v", origins)
		}
	}
	Cfg().Set("cors.login-origins", []string{"https://login.example"})
	Cfg().Set("cors.management-origins", []string{"https://iris.example"})
	if !reflect.DeepEqual(GetLoginOrigins(), []string{"https://aegis.example", "https://login.example"}) || !reflect.DeepEqual(GetManagementOrigins(), []string{"https://aegis.example", "https://iris.example"}) {
		t.Fatalf("UI policies crossed: login=%v management=%v", GetLoginOrigins(), GetManagementOrigins())
	}
}

func TestHTTPOriginValidation(t *testing.T) {
	setHTTPTestConfig(t, "aegis.endpoint", "https://aegis.example")
	setHTTPTestConfig(t, "cors.login-origins", []string{})
	setHTTPTestConfig(t, "cors.management-origins", []string{})
	if err := validateHTTPOrigins(); err != nil {
		t.Fatalf("empty optional policies rejected: %v", err)
	}
	for _, key := range []string{"cors.login-origins", "cors.management-origins"} {
		for _, origin := range []string{"*", "null", "", "https://*.example", "https://ui.example/", "https://ui.example/path", "https://ui.example?", "https://ui.example#", "https://user@ui.example", "file://ui.example", "https://"} {
			t.Run(key+"/"+origin, func(t *testing.T) {
				Cfg().Set(key, []string{origin})
				if err := validateHTTPOrigins(); err == nil {
					t.Fatalf("invalid trusted origin accepted: %q", origin)
				}
				Cfg().Set(key, []string{})
			})
		}
		Cfg().Set(key, []string{"https://ui.example", "http://localhost:18000"})
		if err := validateHTTPOrigins(); err != nil {
			t.Fatal(err)
		}
		Cfg().Set(key, []string{})
	}
}
