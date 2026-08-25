package main

import (
	"bytes"
	"testing"

	"github.com/heliantheon/aegis-go/guard"
)

func TestConfigureProfileTokenManagerUsesIrisServiceSeed(t *testing.T) {
	if err := configureProfileTokenManager("https://aegis.example.com/api", "iris", bytes.Repeat([]byte{1}, 48)); err != nil {
		t.Fatalf("configureProfileTokenManager() error = %v", err)
	}
	if guard.GetTokenManager() == nil {
		t.Fatal("configureProfileTokenManager() did not configure the guard token manager")
	}
}

func TestConfigureProfileTokenManagerRejectsSigningSeed(t *testing.T) {
	if err := configureProfileTokenManager("https://aegis.example.com/api", "iris", bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("configureProfileTokenManager() error = nil, want invalid service seed error")
	}
}
