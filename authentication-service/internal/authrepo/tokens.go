// internal/authrepo/tokens.go
package authrepo

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"authentication/internal/dbgen"
)

var (
	ErrInvalidTokenFormat = errors.New("invalid refresh token format")
	ErrTokenExpired       = errors.New("refresh token expired")
	ErrTokenMismatch      = errors.New("invalid refresh token")
)

type Tokens struct{ q dbgen.Querier }

func NewTokens(q dbgen.Querier) *Tokens { return &Tokens{q: q} }

// HashPassword + DefaultArgon2 assumed from your existing helpers.
func (t *Tokens) Mint(ctx context.Context, userID int64, ttl time.Duration, ua, ip string) (plain string, id int64, err error) {
	// 32 bytes → URL-safe base64 (no padding)
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", 0, err
	}
	plain = base64.RawURLEncoding.EncodeToString(raw)

	// Store only a hash server-side
	hash, err := HashPassword(plain, DefaultArgon2)
	if err != nil {
		return "", 0, err
	}

	expires := time.Now().Add(ttl)

	newID, err := t.q.InsertRefreshToken(ctx, dbgen.InsertRefreshTokenParams{
		UserID:    userID,
		TokenHash: hash,
		ExpiresAt: expires,
		UserAgent: ua,
		Ip:        ip,
	})
	if err != nil {
		return "", 0, err
	}
	return fmt.Sprintf("%d.%s", newID, plain), int64(newID), nil
}

func (t *Tokens) Verify(ctx context.Context, token string) (dbgen.RefreshToken, error) {
	var zero dbgen.RefreshToken

	// Expect "id.plain"
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return zero, ErrInvalidTokenFormat
	}

	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || id <= 0 {
		return zero, ErrInvalidTokenFormat
	}
	plain := parts[1]

	// Load active (not revoked) token by id
	rt, err := t.q.GetActiveRefreshTokenByID(ctx, id)
	if err != nil {
		return zero, err
	}

	// Expiry check
	if time.Now().After(rt.ExpiresAt) {
		return zero, ErrTokenExpired
	}

	// Constant-time verify against stored hash
	ok, err := VerifyPassword(plain, rt.TokenHash)
	if err != nil {
		return zero, err
	}
	if !ok {
		return zero, ErrTokenMismatch
	}

	return rt, nil
}
