package authkit

import (
	"net/http"
	"strings"
)

// AuthMiddleware verifies Bearer access tokens and injects Claims into context.
func AuthMiddleware(v Verifier, onUnauthorized func(w http.ResponseWriter, r *http.Request)) func(next http.Handler) http.Handler {
	if onUnauthorized == nil {
		onUnauthorized = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b := r.Header.Get("Authorization")
			if !strings.HasPrefix(b, "Bearer ") {
				onUnauthorized(w, r)
				return
			}
			token := strings.TrimSpace(strings.TrimPrefix(b, "Bearer "))
			claims, err := v.Verify(token)
			if err != nil {
				onUnauthorized(w, r)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
		})
	}
}
