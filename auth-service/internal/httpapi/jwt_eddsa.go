package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// -------- Issuer (EdDSA) --------

type Ed25519Issuer struct {
	Issuer    string
	Audience  string
	ActiveKID string
	ActiveKey ed25519.PrivateKey
	PubKeys   map[string]ed25519.PublicKey
}

func NewEd25519Issuer(kid string, priv ed25519.PrivateKey, iss, aud string) *Ed25519Issuer {
	pub := priv.Public().(ed25519.PublicKey)
	return &Ed25519Issuer{
		Issuer: iss, Audience: aud,
		ActiveKID: kid, ActiveKey: priv,
		PubKeys: map[string]ed25519.PublicKey{kid: pub},
	}
}
func (e *Ed25519Issuer) AddPublicKey(kid string, pub ed25519.PublicKey) {
	if e.PubKeys == nil {
		e.PubKeys = make(map[string]ed25519.PublicKey)
	}
	e.PubKeys[kid] = pub
}
func (e *Ed25519Issuer) IssueAccessToken(_ context.Context, userID int64, ttl time.Duration) (string, error) {
	if e.ActiveKey == nil || e.ActiveKID == "" {
		return "", errors.New("eddsa issuer not configured")
	}
	claims := makeClaims(e.Issuer, e.Audience, userID, ttl) // reuse from RS code
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = e.ActiveKID
	return tok.SignedString(e.ActiveKey)
}

// -------- JWKS (OKP) --------

type okpJWK struct {
	Kty string `json:"kty"` // "OKP"
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"` // "EdDSA"
	Crv string `json:"crv,omitempty"` // "Ed25519"
	X   string `json:"x,omitempty"`   // base64url public key
}
type okpJWKS struct {
	Keys []okpJWK `json:"keys"`
}

func (e *Ed25519Issuer) JWKSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		setNoCache(w)
		var out okpJWKS
		for kid, pub := range e.PubKeys {
			out.Keys = append(out.Keys, okpJWK{
				Kty: "OKP", Use: "sig", Kid: kid, Alg: "EdDSA", Crv: "Ed25519",
				X: base64.RawURLEncoding.EncodeToString(pub),
			})
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(out)
	})
}

// -------- Verifier (EdDSA) --------

type Ed25519KeyProvider interface {
	Get(ctx context.Context, kid string) (ed25519.PublicKey, error)
}

type StaticEd25519Keys struct{ keys map[string]ed25519.PublicKey }

func NewStaticEd25519Keys() *StaticEd25519Keys {
	return &StaticEd25519Keys{keys: map[string]ed25519.PublicKey{}}
}
func (s *StaticEd25519Keys) Add(kid string, pub ed25519.PublicKey) *StaticEd25519Keys {
	s.keys[kid] = pub
	return s
}
func (s *StaticEd25519Keys) Get(_ context.Context, kid string) (ed25519.PublicKey, error) {
	pub, ok := s.keys[kid]
	if !ok {
		return nil, errors.New("unknown kid")
	}
	return pub, nil
}

type Ed25519Verifier struct {
	Issuer   string
	Audience string
	Keys     Ed25519KeyProvider
}

func (v *Ed25519Verifier) Verify(ctx context.Context, tokenStr string) (*jwt.RegisteredClaims, error) {
	claims := &jwt.RegisteredClaims{}
	keyFunc := func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != "EdDSA" {
			return nil, errors.New("unexpected alg")
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}
		return v.Keys.Get(ctx, kid)
	}
	tok, err := jwt.ParseWithClaims(tokenStr, claims, keyFunc,
		jwt.WithAudience(v.Audience),
		jwt.WithIssuer(v.Issuer),
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil || !tok.Valid {
		return nil, errors.New("unauthorized")
	}
	return claims, nil
}
