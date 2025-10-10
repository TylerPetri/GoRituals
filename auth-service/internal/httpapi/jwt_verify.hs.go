package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// ---------- HS256 secret provider ----------

type HSSecretProvider interface {
	// Get returns the secret for a kid. If kid is "", provider may return a default.
	Get(ctx context.Context, kid string) ([]byte, error)
}

type StaticHSSecrets struct {
	mu         sync.RWMutex
	secrets    map[string][]byte
	defaultKID string
}

func NewStaticHSSecrets() *StaticHSSecrets {
	return &StaticHSSecrets{secrets: make(map[string][]byte)}
}
func (p *StaticHSSecrets) Add(kid string, secret []byte) *StaticHSSecrets {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.secrets[kid] = secret
	return p
}
func (p *StaticHSSecrets) SetDefault(kid string) *StaticHSSecrets {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.defaultKID = kid
	return p
}
func (p *StaticHSSecrets) Get(_ context.Context, kid string) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if kid != "" {
		if s, ok := p.secrets[kid]; ok {
			return s, nil
		}
		return nil, errors.New("hs256: unknown kid")
	}
	if p.defaultKID != "" {
		if s, ok := p.secrets[p.defaultKID]; ok {
			return s, nil
		}
	}
	return nil, errors.New("hs256: missing kid and no default secret")
}

// ---------- HS256 verifier (matches your RS verifier API) ----------

type HS256Verifier struct {
	Issuer   string
	Audience string
	Keys     HSSecretProvider
}

func (v *HS256Verifier) Verify(ctx context.Context, tokenStr string) (*jwt.RegisteredClaims, error) {
	claims := &jwt.RegisteredClaims{}
	keyFunc := func(t *jwt.Token) (any, error) {
		// Enforce HS256
		if m, ok := t.Method.(*jwt.SigningMethodHMAC); !ok || m.Alg() != "HS256" {
			return nil, errors.New("unexpected alg")
		}
		kid, _ := t.Header["kid"].(string)
		return v.Keys.Get(ctx, kid)
	}
	tok, err := jwt.ParseWithClaims(
		tokenStr, claims, keyFunc,
		jwt.WithAudience(v.Audience),
		jwt.WithIssuer(v.Issuer),
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

// ---------- Generic middleware (works for HS or RS verifiers) ----------

type accessVerifier interface {
	Verify(ctx context.Context, token string) (*jwt.RegisteredClaims, error)
}

func AuthMiddlewareAny(ver accessVerifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims, err := ver.Verify(r.Context(), strings.TrimSpace(parts[1]))
		if err != nil || claims.Subject == "" {
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
