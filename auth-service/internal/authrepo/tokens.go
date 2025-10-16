// internal/authrepo/tokens.go
package authrepo

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/tylerpetri/GoRituals/auth-service/internal/dbgen"
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

	addr, perr := netip.ParseAddr(ip)
	if perr != nil {
		addr = netip.MustParseAddr("0.0.0.0") // safe fallback for INET NOT NULL
	}

	newID, err := t.q.InsertRefreshToken(ctx, dbgen.InsertRefreshTokenParams{
		UserID:    userID,
		TokenHash: hash,
		ExpiresAt: expires,
		Ua:        ua,
		Ip:        addr,
	})
	if err != nil {
		return "", 0, err
	}
	return fmt.Sprintf("%d.%s", newID.ID, plain), int64(newID.ID), nil
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

func joinIDToken(id int64, plain string) string {
	return fmt.Sprintf("%d.%s", id, plain)
}

func splitIDToken(tok string) (id int64, plain string, err error) {
	parts := strings.SplitN(tok, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return 0, "", ErrInvalidTokenFormat
	}
	v, parseErr := strconv.ParseInt(parts[0], 10, 64)
	if parseErr != nil || v <= 0 {
		return 0, "", ErrInvalidTokenFormat
	}
	return v, parts[1], nil
}

// Rotate verifies the presented token, revokes it, and mints a new one.
// Not atomic; if you need strict atomicity, use RotateInTx with a DB tx.
func (t *Tokens) Rotate(ctx context.Context, presented string, ttl time.Duration, ua, ip string) (newCombined string, newRT dbgen.RefreshToken, err error) {
	// 1) Verify current token (format, active, not expired, hash matches)
	rt, err := t.Verify(ctx, presented)
	if err != nil {
		return "", dbgen.RefreshToken{}, err
	}

	// 2) Revoke the OLD token
	if err := t.q.RevokeRefreshTokenByID(ctx, rt.ID); err != nil {
		return "", dbgen.RefreshToken{}, err
	}

	// 3) Mint NEW token for same user
	combined, newID, err := t.Mint(ctx, rt.UserID, ttl, ua, ip) // first return is already "<id>.<plain>"
	if err != nil {
		return "", dbgen.RefreshToken{}, err
	}

	// 4) Fetch & return the new DB row (optional but handy)
	newRT, err = t.q.GetActiveRefreshTokenByID(ctx, newID)
	if err != nil {
		return "", dbgen.RefreshToken{}, err
	}

	return combined, newRT, nil
}

// RotateInTx performs rotation atomically. Call it inside a DB transaction.
// q must be bound to a transactional connection (pgx.Tx).
func RotateInTx(ctx context.Context, q dbgen.Querier, token, ua, ip string, ttl time.Duration) (string, dbgen.RefreshToken, error) {
	id, plain, err := splitIDToken(token)
	if err != nil {
		return "", dbgen.RefreshToken{}, err
	}

	// 1) Lock the token row to avoid races
	cur, err := q.LockActiveRefreshTokenByID(ctx, id)
	if err != nil {
		return "", dbgen.RefreshToken{}, err
	}

	// 2) Expiry & hash check
	if time.Now().After(cur.ExpiresAt) {
		return "", dbgen.RefreshToken{}, ErrTokenExpired
	}
	ok, err := VerifyPassword(plain, cur.TokenHash)
	if err != nil {
		return "", dbgen.RefreshToken{}, err
	}
	if !ok {
		return "", dbgen.RefreshToken{}, ErrTokenMismatch
	}

	// 3) Revoke current
	if err := q.RevokeRefreshTokenByID(ctx, id); err != nil {
		return "", dbgen.RefreshToken{}, err
	}

	// 4) Mint new (inline, so we stay in the same tx)
	//    This mirrors t.Mint but uses q directly.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", dbgen.RefreshToken{}, err
	}
	newPlain := base64.RawURLEncoding.EncodeToString(raw)

	hash, err := HashPassword(newPlain, DefaultArgon2)
	if err != nil {
		return "", dbgen.RefreshToken{}, err
	}

	addr, perr := netip.ParseAddr(ip)
	if perr != nil {
		addr = netip.MustParseAddr("0.0.0.0") // safe fallback for INET NOT NULL
	}

	newID, err := q.InsertRefreshToken(ctx, dbgen.InsertRefreshTokenParams{
		UserID:    cur.UserID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(ttl),
		Ua:        ua,
		Ip:        addr,
	})
	if err != nil {
		return "", dbgen.RefreshToken{}, err
	}

	newRT, err := q.GetActiveRefreshTokenByID(ctx, newID.ID)
	if err != nil {
		return "", dbgen.RefreshToken{}, err
	}

	return joinIDToken(newID.ID, newPlain), newRT, nil
}

// Revoke verifies the token first, then revokes it (non-atomic).
func (t *Tokens) Revoke(ctx context.Context, token string) error {
	rt, err := t.Verify(ctx, token)
	if err != nil {
		return err
	}
	return t.q.RevokeRefreshTokenByID(ctx, rt.ID)
}

// RevokeAllForUser is straightforward with the named query.
func (t *Tokens) RevokeAllForUser(ctx context.Context, userID int64) error {
	return t.q.RevokeAllForUser(ctx, userID)
}
