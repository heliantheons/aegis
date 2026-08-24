package authorize

import (
	"crypto/sha256"
	"testing"
)

func TestClientSecretMatches(t *testing.T) {
	t.Parallel()

	oldVerifier := sha256.Sum256([]byte("old-secret"))
	currentVerifier := sha256.Sum256([]byte("current-secret"))
	verifiers := [][sha256.Size]byte{currentVerifier, oldVerifier}

	if !clientSecretMatches(verifiers, "current-secret") {
		t.Fatal("clientSecretMatches() rejected the current secret")
	}
	if !clientSecretMatches(verifiers, "old-secret") {
		t.Fatal("clientSecretMatches() rejected an unexpired rotated secret")
	}
	if clientSecretMatches(verifiers, "wrong-secret") {
		t.Fatal("clientSecretMatches() accepted an invalid secret")
	}
}
