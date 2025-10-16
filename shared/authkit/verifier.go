package authkit

import (
	"errors"
	"fmt"
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
		pub, ok := v.jwks.Get(kid)
		if !ok {
			return nil, errors.New("kid not found")
		}
		return pub, nil
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
		pub, ok := v.jwks.Get(kid)
		if !ok {
			return nil, errors.New("kid not found")
		}
		return pub, nil
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
	// Required
	iss, _ := m["iss"].(string)
	aud, _ := m["aud"].(string)
	expf, ok := m["exp"].(float64)
	if !ok {
		return ErrVerify
	}

	if opt.Issuer != "" && iss != opt.Issuer {
		return ErrVerify
	}
	if opt.Audience != "" && aud != opt.Audience {
		return ErrVerify
	}

	dst.Iss, dst.Aud = iss, aud
	dst.Exp = time.Unix(int64(expf), 0)

	// Optional app claims
	switch v := m["uid"].(type) {
	case float64:
		dst.UserID = int64(v)
	case int64:
		dst.UserID = v
	}
	if scp, ok := m["scp"].([]any); ok {
		dst.Scopes = make([]string, 0, len(scp))
		for _, s := range scp {
			if str, ok := s.(string); ok {
				dst.Scopes = append(dst.Scopes, str)
			}
		}
	}
	if sub, ok := m["sub"].(string); ok {
		dst.Sub = sub
	}
	if jti, ok := m["jti"].(string); ok {
		dst.Jti = jti
	}
	return nil
}
