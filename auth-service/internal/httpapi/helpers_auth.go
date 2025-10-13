package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgconn"

	"authentication/internal/authrepo"
	"authentication/internal/dbgen"
)

type signupReq struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}
type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type userDTO struct {
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name,omitempty"`
	LastName  string    `json:"last_name,omitempty"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}
type authResp struct {
	User             userDTO   `json:"user"`
	AccessToken      string    `json:"access_token"`
	TokenType        string    `json:"token_type"`
	RefreshToken     string    `json:"refresh_token"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

// POST /v1/auth/signup
func (h *Handler) SignUp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req signupReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" || req.Password == "" {
		writeErr(w, http.StatusBadRequest, "email and password are required")
		return
	}

	ctx := r.Context()
	users := authrepo.NewUsers(dbgen.New(h.Store.Pool))
	id, err := users.Create(ctx, req.Email, req.FirstName, req.LastName, req.Password, true)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			writeErr(w, http.StatusConflict, "email already in use")
			return
		}
		writeErr(w, http.StatusInternalServerError, "could not create user")
		return
	}
	u, err := dbgen.New(h.Store.Pool).GetUserByID(ctx, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not load user")
		return
	}

	ua := r.UserAgent()
	ip := clientIP(r)
	combined, refreshID, err := h.Tokens.Mint(ctx, u.ID, RefreshTTL, ua, ip)
	if err != nil {
		if h.Logger != nil {
			h.Logger.Error("mint refresh failed", "err", err, "ua", ua, "ip", ip)
		}
		writeErr(w, http.StatusInternalServerError, "could not mint refresh token")
		return
	}
	if h.Logger != nil {
		h.Logger.Info("minted refresh", "user_id", u.ID, "refresh_id", refreshID, "ua", ua, "ip", ip)
	}

	access := ""
	if h.JWTIssuer != nil {
		if at, err := h.JWTIssuer.IssueAccessToken(ctx, u.ID, 15*time.Minute); err == nil {
			access = at
		} else {
			writeErr(w, http.StatusInternalServerError, "could not issue access token")
			return
		}
	}
	if h.CookieRefresh {
		setRefreshCookie(w, combined)
	}

	resp := authResp{
		User: toUserDTO(u), AccessToken: access, TokenType: "Bearer",
		RefreshToken: combined, RefreshExpiresAt: time.Now().Add(RefreshTTL),
	}
	writeJSON(w, http.StatusCreated, resp)
}

// POST /v1/auth/login
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req loginReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" || req.Password == "" {
		writeErr(w, http.StatusBadRequest, "email and password are required")
		return
	}

	ctx := r.Context()
	q := dbgen.New(h.Store.Pool)
	u, err := q.GetUserByEmail(ctx, req.Email)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if !u.UserActive {
		writeErr(w, http.StatusForbidden, "account disabled")
		return
	}

	ok, err := authrepo.VerifyPassword(req.Password, u.Password)
	if err != nil || !ok {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if need, _ := authrepo.NeedsRehash(u.Password, authrepo.DefaultArgon2); need {
		_ = authrepo.NewUsers(q).ResetPassword(ctx, u.ID, req.Password)
	}

	ua := r.UserAgent()
	ip := clientIP(r)
	combined, refreshID, err := h.Tokens.Mint(ctx, u.ID, RefreshTTL, ua, ip)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not mint refresh token")
		return
	}
	if h.Logger != nil {
		h.Logger.Info("minted refresh", "user_id", u.ID, "refresh_id", refreshID, "ua", ua, "ip", ip)
	}

	access := ""
	if h.JWTIssuer != nil {
		if at, err := h.JWTIssuer.IssueAccessToken(ctx, u.ID, 15*time.Minute); err == nil {
			access = at
		} else {
			writeErr(w, http.StatusInternalServerError, "could not issue access token")
			return
		}
	}
	if h.CookieRefresh {
		setRefreshCookie(w, combined)
	}

	resp := authResp{
		User: toUserDTO(u), AccessToken: access, TokenType: "Bearer",
		RefreshToken: combined, RefreshExpiresAt: time.Now().Add(RefreshTTL),
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /v1/auth/logout
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ctx := r.Context()

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
		writeErr(w, http.StatusUnauthorized, "missing refresh token")
		return
	}

	if err := h.Tokens.Revoke(ctx, token); err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid or already revoked")
		return
	}
	if h.Logger != nil {
		h.Logger.Info("revoked refresh token")
	}

	http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

// POST /v1/auth/logout-all
func (h *Handler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ctx := r.Context()
	uid, ok := UserIDFromContext(ctx)
	if !ok || uid <= 0 {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := h.Tokens.RevokeAllForUser(ctx, uid); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not revoke tokens")
		return
	}
	if h.Logger != nil {
		h.Logger.Info("revoked all refresh tokens", "user_id", uid)
	}

	http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

// GET /v1/me
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ctx := r.Context()
	uid, ok := UserIDFromContext(ctx)
	if !ok || uid <= 0 {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	u, err := dbgen.New(h.Store.Pool).GetUserByID(ctx, uid)
	if err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, toUserDTO(u))
}
