package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"authentication/internal/authrepo"
	"authentication/internal/dbgen"
	"authentication/internal/store"

	"github.com/jackc/pgx/v5"
)

// Wire this from main.go
type Handler struct {
	Store  *store.Store
	Tokens *authrepo.Tokens
	// Optionally: JWT issuer dependencies (keys, issuer, audience...)
	JWTIssuer JWTIssuer
}

// How long new refresh tokens should live
const RefreshTTL = 30 * 24 * time.Hour // 30 days

// ----- Public route -----

// POST /v1/tokens/refresh
// Accepts refresh token from Authorization: Bearer <id.plain>
// OR JSON body { "refresh_token": "<id.plain>" }
// Returns { refresh_token, refresh_expires_at, access_token }
func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()

	// 1) Extract presented token
	token := bearerToken(r)
	if token == "" {
		if t2, ok := tokenFromJSON(r); ok {
			token = t2
		}
	}
	if token == "" {
		if t3, ok := tokenFromCookie(r, "refresh_token"); ok {
			token = t3
		}
	}
	if token == "" {
		writeJSON(w, http.StatusUnauthorized, errorBody("missing refresh token"))
		return
	}

	ua := r.UserAgent()
	ip := clientIP(r)

	// 2) Rotate atomically in a DB transaction
	var newCombined string
	var newRow dbgen.RefreshToken
	err := h.Store.WithTx(ctx, func(ctx context.Context, q dbgen.Querier) error {
		var err error
		newCombined, newRow, err = authrepo.RotateInTx(ctx, q, token, ua, ip, RefreshTTL)
		return err
	})
	if err != nil {
		// Error mapping
		switch {
		case errors.Is(err, authrepo.ErrInvalidTokenFormat),
			errors.Is(err, authrepo.ErrTokenMismatch),
			errors.Is(err, authrepo.ErrTokenExpired):
			writeJSON(w, http.StatusUnauthorized, errorBody(err.Error()))
			return
		case errors.Is(err, pgx.ErrNoRows):
			// No active row to lock -> already revoked/rotated
			writeJSON(w, http.StatusConflict, errorBody("refresh token already used or revoked"))
			return
		default:
			// keep details out of response in prod; log internally
			writeJSON(w, http.StatusInternalServerError, errorBody("internal error"))
			return
		}
	}

	// 3) (Optional) Mint a new ACCESS token (short-lived JWT)
	access := ""
	if h.JWTIssuer != nil {
		at, err := h.JWTIssuer.IssueAccessToken(ctx, newRow.UserID, 15*time.Minute)
		if err != nil {
			// Non-fatal; you can decide to fail or return only refresh token
			writeJSON(w, http.StatusInternalServerError, errorBody("failed to issue access token"))
			return
		}
		access = at
	}

	// 4) Respond
	resp := map[string]any{
		"refresh_token":      newCombined,      // "id.plain"
		"refresh_expires_at": newRow.ExpiresAt, // time.Time (sqlc override)
		"access_token":       access,           // may be ""
		"token_type":         "Bearer",
	}
	writeJSON(w, http.StatusOK, resp)
}

// ----- Helpers -----

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func tokenFromJSON(r *http.Request) (string, bool) {
	defer r.Body.Close()
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		return "", false
	}
	return strings.TrimSpace(body.RefreshToken), body.RefreshToken != ""
}

func tokenFromCookie(r *http.Request, name string) (string, bool) {
	c, err := r.Cookie(name)
	if err != nil || c == nil {
		return "", false
	}
	return strings.TrimSpace(c.Value), c.Value != ""
}

func clientIP(r *http.Request) string {
	// If behind proxy, prefer standard headers (trust only in known infra!)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// use the left-most IP
		if comma := strings.Index(xff, ","); comma >= 0 {
			return strings.TrimSpace(xff[:comma])
		}
		return strings.TrimSpace(xff)
	}
	if cip := r.Header.Get("CF-Connecting-IP"); cip != "" {
		return strings.TrimSpace(cip)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func errorBody(msg string) map[string]string {
	return map[string]string{"error": msg}
}
