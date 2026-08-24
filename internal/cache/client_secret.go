package cache

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	pasetokit "github.com/heliantheon/aegis-go/utilities/paseto"
)

const applicationClientSecretPurpose = "client-secret"

func deriveApplicationClientSecretVerifier(seed []byte) ([sha256.Size]byte, error) {
	if len(seed) != 48 {
		return [sha256.Size]byte{}, fmt.Errorf("invalid application seed length: got %d, want 48", len(seed))
	}

	parsed, err := pasetokit.ParseSeed(seed)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("parse application seed: %w", err)
	}
	derived := parsed.Derive(applicationClientSecretPurpose)
	encoded := base64.RawURLEncoding.EncodeToString(derived)
	return sha256.Sum256([]byte(encoded)), nil
}
