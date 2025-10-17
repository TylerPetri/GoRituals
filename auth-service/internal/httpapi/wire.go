package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"time"

	authkit "github.com/tylerpetri/GoRituals/shared/authkit"
)

// BuildIssuer builds the configured JWTIssuer and (optionally) the RSA/Ed issuers used for JWKS.
func BuildIssuer(cfg Config) (JWTIssuer, *RSAJWKSIssuer, *Ed25519Issuer) {
	switch cfg.Alg {
	case AlgHS256:
		secret, _ := base64.RawStdEncoding.DecodeString(cfg.HSSecretBase64)
		iss := NewHS256Issuer(secret, cfg.Issuer, cfg.Audience, cfg.HSDefaultKID)
		return iss, nil, nil

	case AlgRS256:
		priv := mustLoadRSAPrivate(cfg.RSAPrivateKeyFile)
		rsaIss := NewRSAJWKSIssuer(cfg.RSAActiveKID, priv, cfg.Issuer, cfg.Audience)
		for kid, path := range cfg.RSAPublicKeyFiles {
			rsaIss.AddPublicKey(kid, mustLoadRSAPublic(path))
		}
		return rsaIss, rsaIss, nil

	case AlgEdDSA:
		priv := mustLoadEdPrivate(cfg.EdPrivateKeyFile)
		edIss := NewEd25519Issuer(cfg.EdActiveKID, priv, cfg.Issuer, cfg.Audience)
		for kid, path := range cfg.EdPublicKeyFiles {
			edIss.AddPublicKey(kid, mustLoadEdPublic(path))
		}
		return edIss, nil, edIss
	default:
		panic("unknown alg")
	}
}

func mustLoadRSAPrivate(path string) *rsa.PrivateKey {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read rsa private: %v", err)
	}
	k, err := LoadRSAPrivateKeyPEM(b)
	if err != nil {
		log.Fatalf("parse rsa private: %v", err)
	}
	return k
}
func mustLoadRSAPublic(path string) *rsa.PublicKey {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read rsa public: %v", err)
	}
	k, err := LoadRSAPublicKeyPEM(b)
	if err != nil {
		log.Fatalf("parse rsa public: %v", err)
	}
	return k
}
func mustLoadEdPrivate(path string) ed25519.PrivateKey {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read ed25519 private: %v", err)
	}
	k, err := LoadEd25519PrivateKeyPEM(b)
	if err != nil {
		log.Fatalf("parse ed25519 private: %v", err)
	}
	return k
}
func mustLoadEdPublic(path string) ed25519.PublicKey {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read ed25519 public: %v", err)
	}
	k, err := LoadEd25519PublicKeyPEM(b)
	if err != nil {
		log.Fatalf("parse ed25519 public: %v", err)
	}
	return k
}

// RS256 health: fetch JWKS over HTTP, confirm active KID present and
// verify a freshly issued token via the remote JWKS provider.
func jwksHealthRS(iss *RSAJWKSIssuer, publicBase string) http.HandlerFunc {
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

		if _, err := prov.GetRSA(ctx, iss.ActiveKID); err != nil {
			res.Checks = append(res.Checks, "jwks.get.rsa: fail")
			fail(err)
			return
		}
		res.Checks = append(res.Checks, "jwks.get.rsa: ok")

		tok, err := iss.IssueAccessToken(ctx, 1, 30*time.Second)
		if err != nil {
			res.Checks = append(res.Checks, "issue.token: fail")
			fail(err)
			return
		}
		ver := &JWTVerifier{Issuer: iss.Issuer, Audience: iss.Audience, Keys: jwksRSAAdapter{P: prov}}
		if _, err := ver.Verify(ctx, tok); err != nil {
			res.Checks = append(res.Checks, "verify.token: fail")
			fail(err)
			return
		}
		res.Checks = append(res.Checks, "verify.token: ok")
		writeJSON(w, http.StatusOK, res)
	}
}

// adapter so JWTVerifier can use HTTPMultiJWKSProvider
type jwksRSAAdapter struct{ P *HTTPMultiJWKSProvider }

func (a jwksRSAAdapter) Get(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	return a.P.GetRSA(ctx, kid)
}

// BuildAuthMiddleware returns a middleware that verifies access tokens using the configured algorithm.
func BuildAuthMiddleware(cfg Config, rsaIss *RSAJWKSIssuer, edIss *Ed25519Issuer) func(http.Handler) http.Handler {
	switch cfg.Alg {
	case AlgHS256:
		// HS256: local static secret provider (no JWKS)
		secret, _ := base64.RawStdEncoding.DecodeString(cfg.HSSecretBase64)
		secrets := NewStaticHSSecrets().Add(cfg.HSDefaultKID, secret).SetDefault(cfg.HSDefaultKID)
		ver := &HS256Verifier{Issuer: cfg.Issuer, Audience: cfg.Audience, Keys: secrets}
		return func(next http.Handler) http.Handler { return AuthMiddlewareAny(ver, next) }

	case AlgRS256:
		// RS256: verify against local in-process public keys (from issuer)
		static := NewStaticJWKSProvider()
		for kid, pub := range rsaIss.PubKeys {
			static.Add(kid, pub)
		}
		ver := &JWTVerifier{Issuer: cfg.Issuer, Audience: cfg.Audience, Keys: static}
		return func(next http.Handler) http.Handler { return AuthMiddleware(ver, next) }

	case AlgEdDSA:
		// Ed25519: local static map
		keys := NewStaticEd25519Keys()
		for kid, pub := range edIss.PubKeys {
			keys.Add(kid, pub)
		}
		ver := &Ed25519Verifier{Issuer: cfg.Issuer, Audience: cfg.Audience, Keys: keys}
		return func(next http.Handler) http.Handler { return AuthMiddlewareAny(ver, next) }

	default:
		// should not happen
		return func(next http.Handler) http.Handler { return next }
	}
}

func NewMux(h *Handler, ver authkit.Verifier, rsaIss *RSAJWKSIssuer, edIss *Ed25519Issuer, publicBase string) *http.ServeMux {
	mux := http.NewServeMux()

	// public routes
	mux.Handle("/.well-known/jwks.json", CombinedJWKSHandler(rsaIss, edIss))
	if rsaIss != nil {
		mux.HandleFunc("/health/jwks/rs256", jwksHealthRS(rsaIss, publicBase))
	}
	if edIss != nil {
		mux.HandleFunc("/health/jwks/eddsa", jwksHealthEdRemote(edIss, publicBase))
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/v1/auth/signup", h.SignUp)
	mux.HandleFunc("/v1/auth/login", h.Login)
	mux.HandleFunc("/v1/auth/logout", h.Logout)          // uses refresh token (not protected by AT)
	mux.HandleFunc("/v1/tokens/refresh", h.RefreshToken) // uses refresh token

	// protected by ACCESS token:
	protected := authkit.AuthMiddleware(ver, nil)
	mux.Handle("/v1/auth/logout-all", protected(http.HandlerFunc(h.LogoutAll)))
	mux.Handle("/v1/me", protected(http.HandlerFunc(h.Me)))

	// (JWKS and alg-specific health routes you already have)
	return mux
}
