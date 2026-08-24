package cache

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestDeriveApplicationClientSecretVerifier(t *testing.T) {
	t.Parallel()

	seed := bytes.Repeat([]byte{0x42}, 48)
	first, err := deriveApplicationClientSecretVerifier(seed)
	if err != nil {
		t.Fatalf("deriveApplicationClientSecretVerifier() error = %v", err)
	}
	second, err := deriveApplicationClientSecretVerifier(seed)
	if err != nil {
		t.Fatalf("deriveApplicationClientSecretVerifier() second error = %v", err)
	}
	if first != second {
		t.Fatal("deriveApplicationClientSecretVerifier() is not deterministic")
	}
	if first == ([sha256.Size]byte{}) {
		t.Fatal("deriveApplicationClientSecretVerifier() returned an empty verifier")
	}
	want := sha256.Sum256([]byte("G24kZfyp4aI6VIrms1ghmjMMuMA0vvEWkR5pEAU_UUY"))
	if first != want {
		t.Fatal("derived verifier does not match the protocol test vector")
	}

}
