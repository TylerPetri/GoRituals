package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/tylerpetri/GoRituals/auth-service/internal/authrepo"
	"github.com/tylerpetri/GoRituals/auth-service/internal/store"
)

// Wire this from main.go
type Handler struct {
	Store         *store.Store
	Tokens        *authrepo.Tokens
	JWTIssuer     JWTIssuer
	CookieRefresh bool
	Cfg           Config
	Logger        *slog.Logger
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
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	presented := bearerToken(r)
	if presented == "" {
		if t, ok := tokenFromJSON(r); ok {
			presented = t
		}
	}
	if presented == "" {
		if t, ok := tokenFromCookie(r, "refresh_token"); ok {
			presented = t
		}
	}
	if presented == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing refresh token"})
		return
	}

	ctx := r.Context()
	ua := r.UserAgent() // may be ""
	ip := clientIP(r)   // now never ""

	// Rotate (revokes old, creates new)
	newCombined, newRow, err := h.Tokens.Rotate(ctx, presented, RefreshTTL, ua, ip)
	uid := newRow.UserID
	if err != nil {
		if h.Logger != nil {
			h.Logger.Error("refresh rotate failed", "err", err)
		}
		// Treat invalid token / replay as 401; unknowns as 500
		// (If your Rotate returns typed errors, switch on them and return 401/409 accordingly.)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	at, err := h.JWTIssuer.IssueAccessToken(ctx, uid, 15*time.Minute)
	if err != nil {
		if h.Logger != nil {
			h.Logger.Error("issue access token failed", "err", err)
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":       at,
		"token_type":         "Bearer",
		"refresh_token":      newCombined,
		"refresh_expires_at": time.Now().Add(RefreshTTL),
	})
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

func errorBody(msg string) map[string]string {
	return map[string]string{"error": msg}
}
