package authrepo

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// randRead fills dst with crypto-random bytes.
func randRead(dst []byte) error {
	_, err := rand.Read(dst)
	return err
}

// encodeArgon2Hash returns a PHC string like:
// $argon2id$v=19$m=65536,t=3,p=2$<base64 salt>$<base64 key>
func encodeArgon2Hash(p Argon2Params, salt, key []byte) string {
	b64 := base64.RawStdEncoding // PHC uses base64 without padding
	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		p.Memory, p.Time, p.Threads,
		b64.EncodeToString(salt),
		b64.EncodeToString(key),
	)
}

// decodeArgon2Hash parses a PHC string and returns params, salt, key.
func decodeArgon2Hash(encoded string) (Argon2Params, []byte, []byte, error) {
	var p Argon2Params

	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=..,t=..,p=..", "<salt>", "<key>"]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return p, nil, nil, errors.New("invalid argon2id hash format")
	}
	if parts[2] != "v=19" {
		return p, nil, nil, fmt.Errorf("unsupported argon2 version: %s", parts[2])
	}

	paramKV := strings.Split(parts[3], ",")
	for _, kv := range paramKV {
		pair := strings.SplitN(kv, "=", 2)
		if len(pair) != 2 {
			return p, nil, nil, errors.New("invalid argon2 params")
		}
		val, err := strconv.ParseUint(pair[1], 10, 32)
		if err != nil {
			return p, nil, nil, err
		}
		switch pair[0] {
		case "m":
			p.Memory = uint32(val)
		case "t":
			p.Time = uint32(val)
		case "p":
			p.Threads = uint8(val)
		default:
			return p, nil, nil, fmt.Errorf("unknown argon2 param %q", pair[0])
		}
	}

	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return p, nil, nil, err
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil {
		return p, nil, nil, err
	}

	p.SaltLen = uint32(len(salt))
	p.KeyLen = uint32(len(key))
	return p, salt, key, nil
}

// subtleConstantTimeEq compares two byte slices in constant time.
func subtleConstantTimeEq(a, b []byte) bool {
	if len(a) != len(b) {
		// Keep timing consistent-ish even for mismatched lengths
		// by comparing against itself.
		if len(a) == 0 {
			return false
		}
		_ = subtle.ConstantTimeCompare(a, a)
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
