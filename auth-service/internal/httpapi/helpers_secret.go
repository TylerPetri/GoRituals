package httpapi

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// SecretFromEnv reads an env var and decodes it as a key.
// Accepts base64url (no padding), base64url (padded), or standard base64.
// Returns a []byte suitable for HS256 HMAC keys.
func SecretFromEnv(envKey string) ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv(envKey))
	if raw == "" {
		return nil, fmt.Errorf("missing env %s", envKey)
	}

	// Try base64url **without** padding first (recommended)
	if b, err := base64.RawURLEncoding.DecodeString(raw); err == nil {
		return b, nil
	}
	// Try base64url (with padding)
	if b, err := base64.URLEncoding.DecodeString(raw); err == nil {
		return b, nil
	}
	// Try standard base64
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil {
		return b, nil
	}

	return nil, fmt.Errorf("%s is not valid base64/base64url", envKey)
}
