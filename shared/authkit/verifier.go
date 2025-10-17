package authkit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Options struct {
	Issuer   string
	Audience string
	Leeway   time.Duration
}

type Verifier interface {
	Verify(token string) (*Claims, error)
}

// --- HS256 ---

type hs256Verifier struct {
	key []byte
	opt Options
}

func NewVerifierHS256(secret []byte, opt Options) Verifier {
	return &hs256Verifier{key: secret, opt: opt}
}

func (v *hs256Verifier) Verify(tok string) (*Claims, error) {
	t, err := jwt.Parse(tok, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("alg=%s", t.Method.Alg())
		}
		return v.key, nil
	}, jwt.WithLeeway(v.opt.Leeway))
	if err != nil || !t.Valid {
		return nil, ErrVerify
	}
	var uc Claims
	if err := mapClaims(t.Claims, &uc, v.opt); err != nil {
		return nil, err
	}
	return &uc, nil
}

// --- RS256 via JWKS ---

type rs256Verifier struct {
	jwks *JWKSProvider
	opt  Options
}

func NewVerifierRS256(j *JWKSProvider, opt Options) Verifier {
	return &rs256Verifier{jwks: j, opt: opt}
}

func (v *rs256Verifier) Verify(tok string) (*Claims, error) {
	t, err := jwt.Parse(tok, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("alg=%s", t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}

		// 1) try cache
		if pub, ok := v.jwks.Get(kid); ok {
			return pub, nil
		}
		// 2) on-demand fetch + retry (handles startup race)
		_ = v.jwks.Fetch(context.Background())
		if pub, ok := v.jwks.Get(kid); ok {
			return pub, nil
		}
		return nil, errors.New("kid not found")
	}, jwt.WithLeeway(v.opt.Leeway))
	if err != nil || !t.Valid {
		return nil, ErrVerify
	}
	var uc Claims
	if err := mapClaims(t.Claims, &uc, v.opt); err != nil {
		return nil, err
	}
	return &uc, nil
}

// --- EdDSA via JWKS (Ed25519) ---

type eddsaVerifier struct {
	jwks *JWKSProvider
	opt  Options
}

func NewVerifierEdDSA(j *JWKSProvider, opt Options) Verifier {
	return &eddsaVerifier{jwks: j, opt: opt}
}

func (v *eddsaVerifier) Verify(tok string) (*Claims, error) {
	t, err := jwt.Parse(tok, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodEdDSA {
			return nil, fmt.Errorf("alg=%s", t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}

		// 1) try cache
		if pub, ok := v.jwks.Get(kid); ok {
			return pub, nil
		}
		// 2) on-demand fetch + retry (handles startup race)
		_ = v.jwks.Fetch(context.Background())
		if pub, ok := v.jwks.Get(kid); ok {
			return pub, nil
		}
		return nil, errors.New("kid not found")
	}, jwt.WithLeeway(v.opt.Leeway))
	if err != nil || !t.Valid {
		return nil, ErrVerify
	}

	var uc Claims
	if err := mapClaims(t.Claims, &uc, v.opt); err != nil {
		return nil, err
	}
	return &uc, nil
}

// --- common claims mapping + iss/aud checks ---

func mapClaims(src jwt.Claims, dst *Claims, opt Options) error {
	m, ok := src.(jwt.MapClaims)
	if !ok {
		return ErrVerify
	}

	iss, _ := m["iss"].(string)

	// aud can be string or array
	var audVal string
	var audMatch bool
	switch v := m["aud"].(type) {
	case string:
		audVal = v
		audMatch = (opt.Audience == "" || v == opt.Audience)
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok {
				if opt.Audience == "" || s == opt.Audience {
					audVal = s
					audMatch = true
					break
				}
			}
		}
	case []string:
		for _, s := range v {
			if opt.Audience == "" || s == opt.Audience {
				audVal = s
				audMatch = true
				break
			}
		}
	}

	// exp
	var expUnix int64
	switch v := m["exp"].(type) {
	case float64:
		expUnix = int64(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			expUnix = n
		}
	}
	if expUnix == 0 {
		return ErrVerify
	}

	// iss/aud checks
	if opt.Issuer != "" && iss != opt.Issuer {
		return ErrVerify
	}
	if opt.Audience != "" && !audMatch {
		return ErrVerify
	}

	dst.Iss, dst.Aud = iss, audVal
	dst.Exp = time.Unix(expUnix, 0)

	// app claims:
	// prefer uid (int), else derive from sub if numeric string
	switch v := m["uid"].(type) {
	case float64:
		dst.UserID = int64(v)
	case int64:
		dst.UserID = v
	}
	if sub, ok := m["sub"].(string); ok {
		dst.Sub = sub
		if dst.UserID == 0 {
			if n, err := strconv.ParseInt(sub, 10, 64); err == nil {
				dst.UserID = n
			}
		}
	}
	// scopes optional
	if scp, ok := m["scp"].([]any); ok {
		dst.Scopes = dst.Scopes[:0]
		for _, s := range scp {
			if str, ok := s.(string); ok {
				dst.Scopes = append(dst.Scopes, str)
			}
		}
	}
	if jti, ok := m["jti"].(string); ok {
		dst.Jti = jti
	}

	return nil
}
