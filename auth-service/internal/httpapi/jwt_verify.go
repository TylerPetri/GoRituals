package httpapi

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// =====================
// PEM Loaders (RSA)
// =====================

// LoadRSAPrivateKeyPEM parses an RSA private key (PKCS#1 or PKCS#8, unencrypted).
func LoadRSAPrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse pkcs1: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse pkcs8: %w", err)
		}
		rsaKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("pkcs8 is not rsa private key")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}
}

// LoadRSAPublicKeyPEM parses an RSA public key (PKCS#1 "RSA PUBLIC KEY" or X.509 "PUBLIC KEY").
func LoadRSAPublicKeyPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "RSA PUBLIC KEY":
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse pkcs1 pub: %w", err)
		}
		return key, nil
	case "PUBLIC KEY":
		k, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse spki pub: %w", err)
		}
		rsaKey, ok := k.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("public key is not RSA")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}
}

// =====================
// JWKS Provider(s)
// =====================

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

func b64urlDecode(b64 string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(b64)
}
func rsaFromJWK(j jwk) (*rsa.PublicKey, error) {
	if !strings.EqualFold(j.Kty, "RSA") {
		return nil, fmt.Errorf("jwk kty %q not RSA", j.Kty)
	}
	nb, err := b64urlDecode(j.N)
	if err != nil {
		return nil, fmt.Errorf("decode N: %w", err)
	}
	eb, err := b64urlDecode(j.E)
	if err != nil {
		return nil, fmt.Errorf("decode E: %w", err)
	}
	var e int
	for _, b := range eb {
		e = (e << 8) | int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
}

// JwksProvider fetches / supplies RSA public keys by KID.
type JwksProvider interface {
	Get(ctx context.Context, kid string) (*rsa.PublicKey, error)
}

// StaticJWKSProvider holds keys in-memory.
type StaticJWKSProvider struct {
	mu   sync.RWMutex
	keys map[string]*rsa.PublicKey
}

func NewStaticJWKSProvider() *StaticJWKSProvider {
	return &StaticJWKSProvider{keys: make(map[string]*rsa.PublicKey)}
}
func (p *StaticJWKSProvider) Add(kid string, pub *rsa.PublicKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys[kid] = pub
}
func (p *StaticJWKSProvider) Get(_ context.Context, kid string) (*rsa.PublicKey, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	pub, ok := p.keys[kid]
	if !ok {
		return nil, fmt.Errorf("kid %q not found", kid)
	}
	return pub, nil
}

// HTTPJWKSProvider fetches JWKS from a URL and caches for TTL.
type HTTPJWKSProvider struct {
	URL        string
	TTL        time.Duration
	HTTPClient *http.Client

	mu        sync.RWMutex
	lastFetch time.Time
	keys      map[string]*rsa.PublicKey
}

func NewHTTPJWKSProvider(url string, ttl time.Duration) *HTTPJWKSProvider {
	return &HTTPJWKSProvider{
		URL:        url,
		TTL:        ttl,
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
		keys:       make(map[string]*rsa.PublicKey),
	}
}

func (p *HTTPJWKSProvider) Get(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	// Serve from cache if fresh and present
	p.mu.RLock()
	pub, ok := p.keys[kid]
	fresh := time.Since(p.lastFetch) < p.TTL
	p.mu.RUnlock()
	if ok && fresh {
		return pub, nil
	}

	// Fetch/refresh
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		// If we have a cached key for this kid, fall back to it
		p.mu.RLock()
		defer p.mu.RUnlock()
		if pub, ok := p.keys[kid]; ok {
			return pub, nil
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks http %d", resp.StatusCode)
	}

	var doc jwks
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}
	newMap := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if strings.EqualFold(k.Kty, "RSA") && (k.Alg == "" || strings.EqualFold(k.Alg, "RS256")) {
			pub, err := rsaFromJWK(k)
			if err == nil && k.Kid != "" {
				newMap[k.Kid] = pub
			}
		}
	}
	if len(newMap) == 0 {
		return nil, errors.New("jwks has no rsa keys")
	}

	p.mu.Lock()
	p.keys = newMap
	p.lastFetch = time.Now()
	pub, ok = p.keys[kid]
	p.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("kid %q not found after refresh", kid)
	}
	return pub, nil
}

// =====================
// JWT Verifier (RS256)
// =====================

type JWTVerifier struct {
	Issuer   string
	Audience string
	Keys     JwksProvider
}

var (
	ErrNoAuthHeader = errors.New("missing Authorization header")
	ErrBadBearer    = errors.New("invalid Authorization header")
)

func (v *JWTVerifier) Verify(ctx context.Context, tokenStr string) (*jwt.RegisteredClaims, error) {
	claims := &jwt.RegisteredClaims{}

	keyFunc := func(t *jwt.Token) (any, error) {
		// Enforce alg
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok || t.Method.Alg() != "RS256" {
			return nil, fmt.Errorf("unexpected alg %q", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}
		return v.Keys.Get(ctx, kid)
	}

	tok, err := jwt.ParseWithClaims(
		tokenStr, claims, keyFunc,
		jwt.WithAudience(v.Audience),
		jwt.WithIssuer(v.Issuer),
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithLeeway(30*time.Second), // small clock skew
	)
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

// =====================
// Middleware helper
// =====================

type ctxKey int

const userIDKey ctxKey = 1

// UserIDFromContext returns the authenticated user id, if present.
// func UserIDFromContext(ctx context.Context) (int64, bool) {
// 	v := ctx.Value(userIDKey)
// 	if v == nil {
// 		return 0, false
// 	}
// 	id, ok := v.(int64)
// 	return id, ok
// }

// AuthMiddleware extracts Bearer token, verifies it, and puts userID in context.
func AuthMiddleware(ver *JWTVerifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, ErrNoAuthHeader.Error(), http.StatusUnauthorized)
			return
		}
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			http.Error(w, ErrBadBearer.Error(), http.StatusUnauthorized)
			return
		}
		claims, err := ver.Verify(r.Context(), strings.TrimSpace(parts[1]))
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// subject is userID as string (per our issuer)
		if claims.Subject == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		uid, err := strconv.ParseInt(claims.Subject, 10, 64)
		if err != nil || uid <= 0 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), userIDKey, uid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
