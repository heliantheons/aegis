package auth

import (
	"os"
	"path/filepath"
	"testing"

	baseconfig "github.com/heliantheon/common/config"
)

// TestMain 将配置隔离到临时目录，所有认证测试共享不可变的测试 issuer。
func TestMain(m *testing.M) {
	directory, err := os.MkdirTemp("", "aegis-auth-test-")
	if err != nil {
		panic(err)
	}
	original, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "config.toml"), []byte("[aegis]\nendpoint = \"https://issuer.example\"\n[iris]\naudience = \"iris\"\n"), 0o600); err != nil {
		panic(err)
	}
	if err := os.Chdir(directory); err != nil {
		panic(err)
	}
	baseconfig.LoadAegis()
	if err := os.Chdir(original); err != nil {
		panic(err)
	}
	exitCode := m.Run()
	if err := os.RemoveAll(directory); err != nil {
		panic(err)
	}
	os.Exit(exitCode)
}
