package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Healthcheck (Ed25519): ensure active kid is present in remote JWKS,
// then issue a short token and verify it via the HTTP JWKS provider.
func jwksHealthEdRemote(iss *Ed25519Issuer, publicBase string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type out struct {
			Status    string   `json:"status"`
			ActiveKID string   `json:"active_kid"`
			JWKSURL   string   `json:"jwks_url"`
			Checks    []string `json:"checks"`
			Error     string   `json:"error,omitempty"`
		}
		res := out{
			Status: "ok", ActiveKID: iss.ActiveKID,
			JWKSURL: publicBase + "/.well-known/jwks.json",
		}
		fail := func(err error) {
			res.Status = "fail"
			res.Error = err.Error()
			writeJSON(w, http.StatusServiceUnavailable, res)
		}

		prov := NewHTTPMultiJWKSProvider(res.JWKSURL, 2*time.Second)
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		// Ensure the active Ed25519 key is available via JWKS
		if _, err := prov.GetEd25519(ctx, iss.ActiveKID); err != nil {
			res.Checks = append(res.Checks, "jwks.get.ed25519: fail")
			fail(fmt.Errorf("jwks get ed25519 kid: %w", err))
			return
		}
		res.Checks = append(res.Checks, "jwks.get.ed25519: ok")

		// Sign a short-lived token, then verify it via JWKS
		tok, err := iss.IssueAccessToken(ctx, 1, 30*time.Second)
		if err != nil {
			res.Checks = append(res.Checks, "issue.token: fail")
			fail(fmt.Errorf("issue token: %w", err))
			return
		}

		ver := &Ed25519Verifier{
			Issuer:   iss.Issuer,
			Audience: iss.Audience,
			Keys:     jwksEdAdapter{P: prov}, // adapter below
		}
		if _, err := ver.Verify(ctx, tok); err != nil {
			res.Checks = append(res.Checks, "verify.token: fail")
			fail(fmt.Errorf("verify via jwks: %w", err))
			return
		}
		res.Checks = append(res.Checks, "verify.token: ok")

		writeJSON(w, http.StatusOK, res)
	}
}

// Adapter so Ed25519Verifier can use HTTPMultiJWKSProvider.
type jwksEdAdapter struct{ P *HTTPMultiJWKSProvider }

func (a jwksEdAdapter) Get(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	return a.P.GetEd25519(ctx, kid)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
