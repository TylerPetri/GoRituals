package authrepo

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// HashPassword returns a PHC-formatted Argon2id hash like:
// $argon2id$v=19$m=65536,t=3,p=2$<b64salt>$<b64key>
func HashPassword(plain string, p Argon2Params) (string, error) {
	if plain == "" {
		return "", errors.New("password cannot be empty")
	}
	if p.SaltLen == 0 || p.KeyLen == 0 || p.Memory == 0 || p.Time == 0 || p.Threads == 0 {
		return "", fmt.Errorf("invalid Argon2Params: %+v", p)
	}

	salt := make([]byte, p.SaltLen)
	if err := randRead(salt); err != nil {
		return "", fmt.Errorf("randRead: %w", err)
	}

	key := argon2.IDKey(append([]byte(plain), Pepper...), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return encodeArgon2Hash(p, salt, key), nil
}

// VerifyPassword compares a plaintext password to a PHC-formatted Argon2id hash.
func VerifyPassword(plain, encoded string) (bool, error) {
	if encoded == "" {
		return false, errors.New("empty encoded hash")
	}
	params, salt, key, err := decodeArgon2Hash(encoded)
	if err != nil {
		return false, fmt.Errorf("decode hash: %w", err)
	}
	test := argon2.IDKey(append([]byte(plain), Pepper...), salt, params.Time, params.Memory, params.Threads, params.KeyLen)
	return subtleConstantTimeEq(key, test), nil
}

// Optional: detect if a stored hash should be rehashed with stronger params.
func NeedsRehash(encoded string, want Argon2Params) (bool, error) {
	got, _, _, err := decodeArgon2Hash(encoded)
	if err != nil {
		return false, err
	}
	if got.Time != want.Time || got.Memory != want.Memory || got.Threads != want.Threads || got.KeyLen != want.KeyLen {
		return true, nil
	}
	return false, nil
}
