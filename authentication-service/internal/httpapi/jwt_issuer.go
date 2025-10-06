package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strconv"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// ----------------------
// Shared helpers
// ----------------------

func now() time.Time { return time.Now().UTC() }

func makeClaims(iss, aud string, userID int64, ttl time.Duration) jwt.RegisteredClaims {
	n := now()
	rc := jwt.RegisteredClaims{
		Subject:   strconv.FormatInt(userID, 10),
		Issuer:    iss,
		IssuedAt:  jwt.NewNumericDate(n),
		NotBefore: jwt.NewNumericDate(n),
		ExpiresAt: jwt.NewNumericDate(n.Add(ttl)),
	}
	if aud != "" {
		rc.Audience = jwt.ClaimStrings{aud}
	}
	return rc
}

// ----------------------
// HS256 (HMAC) issuer
// ----------------------

type HS256Issuer struct {
	Secret   []byte
	Issuer   string
	Audience string
	KID      string           // optional, useful if you rotate shared secrets
	Clock    func() time.Time // test hook (defaults to UTC now)
}

func NewHS256Issuer(secret []byte, issuer, audience, kid string) *HS256Issuer {
	return &HS256Issuer{
		Secret:   secret,
		Issuer:   issuer,
		Audience: audience,
		KID:      kid,
		Clock:    now,
	}
}

func (h *HS256Issuer) IssueAccessToken(_ context.Context, userID int64, ttl time.Duration) (string, error) {
	claims := makeClaims(h.Issuer, h.Audience, userID, ttl)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	if h.KID != "" {
		tok.Header["kid"] = h.KID
	}
	return tok.SignedString(h.Secret)
}

// ----------------------
// RSA (RS256) + JWKS issuer
// ----------------------

// RSAJWKSIssuer issues RS256 tokens with a 'kid' and serves a JWKS for verification.
// Supports rotation by swapping ActiveKID/ActiveKey and keeping old public keys.
type RSAJWKSIssuer struct {
	Issuer    string
	Audience  string
	ActiveKID string
	ActiveKey *rsa.PrivateKey
	PubKeys   map[string]*rsa.PublicKey // kid -> public key
	Clock     func() time.Time          // test hook (defaults to UTC now)
}

func NewRSAJWKSIssuer(activeKID string, activePriv *rsa.PrivateKey, issuer, audience string) *RSAJWKSIssuer {
	return &RSAJWKSIssuer{
		Issuer:    issuer,
		Audience:  audience,
		ActiveKID: activeKID,
		ActiveKey: activePriv,
		PubKeys:   map[string]*rsa.PublicKey{activeKID: &activePriv.PublicKey},
		Clock:     now,
	}
}

// Add a previous/next key (public only) so verifiers can validate older tokens.
// Use this when rotating to a new Active key: add the *new* public key first,
// then switch ActiveKID/ActiveKey.
func (r *RSAJWKSIssuer) AddPublicKey(kid string, pub *rsa.PublicKey) {
	if r.PubKeys == nil {
		r.PubKeys = make(map[string]*rsa.PublicKey)
	}
	r.PubKeys[kid] = pub
}

func (r *RSAJWKSIssuer) IssueAccessToken(_ context.Context, userID int64, ttl time.Duration) (string, error) {
	if r.ActiveKey == nil || r.ActiveKID == "" {
		return "", errors.New("rsa issuer not configured")
	}
	claims := makeClaims(r.Issuer, r.Audience, userID, ttl)
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = r.ActiveKID
	return tok.SignedString(r.ActiveKey)
}

// JWKSHandler returns an http.Handler that serves a JWKS with all public keys.
// Mount at e.g. GET /.well-known/jwks.json
func (r *RSAJWKSIssuer) JWKSHandler() http.Handler {
	type jwk struct {
		Kty string `json:"kty"`
		Use string `json:"use,omitempty"`
		Kid string `json:"kid,omitempty"`
		Alg string `json:"alg,omitempty"`
		N   string `json:"n,omitempty"` // base64url big-endian modulus
		E   string `json:"e,omitempty"` // base64url big-endian exponent
	}
	type jwks struct {
		Keys []jwk `json:"keys"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		setNoCache(w)
		var out jwks
		for kid, pub := range r.PubKeys {
			out.Keys = append(out.Keys, jwk{
				Kty: "RSA",
				Use: "sig",
				Kid: kid,
				Alg: "RS256",
				N:   b64url(pub.N.Bytes()),
				E:   b64url(big.NewInt(int64(pub.E)).Bytes()),
			})
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(out)
	})
}

// ----------------------
// Small utilities
// ----------------------

func setNoCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// ----------------------
// (Optional) quick key helpers
// ----------------------

// Generate a new RSA private key (e.g., for tests or local dev).
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	if bits == 0 {
		bits = 2048
	}
	return rsa.GenerateKey(rand.Reader, bits)
}
