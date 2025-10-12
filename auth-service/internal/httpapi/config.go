package httpapi

import (
	"encoding/base64"
	"errors"
	"os"
	"strings"
)

type Alg string

const (
	AlgHS256 Alg = "HS256"
	AlgRS256 Alg = "RS256"
	AlgEdDSA Alg = "EdDSA" // Ed25519
)

type Config struct {
	HTTPAddr      string // e.g. ":8080"
	PublicBaseURL string // e.g. "https://auth.example.com"
	Issuer        string // iss
	Audience      string // aud
	Alg           Alg    // one of HS256, RS256, EdDSA

	// HS256
	HSDefaultKID   string // e.g. "v1"
	HSSecretBase64 string // base64 of raw secret bytes

	// RS256
	RSAActiveKID      string
	RSAPrivateKeyFile string            // path to PKCS#1/PKCS#8 private key (unencrypted)
	RSAPublicKeyFiles map[string]string // kid -> path to public PEM (for old keys)

	// Ed25519 (EdDSA)
	EdActiveKID      string
	EdPrivateKeyFile string            // path to PKCS#8 private key (unencrypted)
	EdPublicKeyFiles map[string]string // kid -> path to public PEM (for old keys)
}

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func must(k string) string {
	v := os.Getenv(k)
	if v == "" {
		panic("missing env " + k)
	}
	return v
}

func LoadConfigFromEnv() (Config, error) {
	cfg := Config{
		HTTPAddr:          getEnv("HTTP_ADDR", ":8080"),
		PublicBaseURL:     must("PUBLIC_BASE_URL"),
		Issuer:            must("JWT_ISSUER"),
		Audience:          must("JWT_AUDIENCE"),
		Alg:               Alg(getEnv("JWT_ALG", "RS256")),
		RSAPublicKeyFiles: map[string]string{},
		EdPublicKeyFiles:  map[string]string{},
	}

	switch cfg.Alg {
	case AlgHS256:
		cfg.HSDefaultKID = getEnv("JWT_HS256_KID", "v1")
		cfg.HSSecretBase64 = must("JWT_HS256_SECRET_B64") // base64 of secret
	case AlgRS256:
		cfg.RSAActiveKID = must("JWT_RS256_ACTIVE_KID")
		cfg.RSAPrivateKeyFile = must("JWT_RS256_PRIVATE_KEY_FILE")
	case AlgEdDSA:
		cfg.EdActiveKID = must("JWT_ED25519_ACTIVE_KID")
		cfg.EdPrivateKeyFile = must("JWT_ED25519_PRIVATE_KEY_FILE")
	default:
		return cfg, errors.New("JWT_ALG must be HS256, RS256, or EdDSA")
	}

	// Optional: extra public keys for rotation windows
	// Format: kid=/path/to/key.pem,k2=/path/old.pem
	if s := os.Getenv("JWT_RS256_PUBLIC_KEYS"); strings.TrimSpace(s) != "" {
		for _, p := range strings.Split(s, ",") {
			kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
			if len(kv) == 2 {
				cfg.RSAPublicKeyFiles[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}
	if s := os.Getenv("JWT_ED25519_PUBLIC_KEYS"); strings.TrimSpace(s) != "" {
		for _, p := range strings.Split(s, ",") {
			kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
			if len(kv) == 2 {
				cfg.EdPublicKeyFiles[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}

	// quick sanity for HS secret
	if cfg.Alg == AlgHS256 {
		if _, err := base64.RawStdEncoding.DecodeString(cfg.HSSecretBase64); err != nil {
			return cfg, errors.New("JWT_HS256_SECRET_B64 must be unpadded base64")
		}
	}

	return cfg, nil
}
