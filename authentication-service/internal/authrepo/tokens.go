// internal/authrepo/tokens.go
package authrepo

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"authentication/internal/dbgen"
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
	return plain, int64(newID), nil
}

func (t *Tokens) Verify(ctx context.Context, plain string) (dbgen.RefreshToken, error) {
	// Need a query to fetch by hash — but we don't store plain hashes.
	// Common trick: keep many rows, but to find candidate rows, either:
	// 1) Use a fast hash (HMAC) column for lookup + Argon2id verification, or
	// 2) Store a token id prefix in the token (e.g., "id.plain") and fetch by id then verify.
	// Here, prefer (2) for simplicity: include id in the bearer token externally.
	return dbgen.RefreshToken{}, errors.New("design token format to include token id; then fetch by id and VerifyPassword(plain, token_hash)")
}
