package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/tylerpetri/GoRituals/auth-service/internal/authrepo"
	"github.com/tylerpetri/GoRituals/auth-service/internal/dbgen"
	"github.com/tylerpetri/GoRituals/auth-service/internal/httpapi"
	"github.com/tylerpetri/GoRituals/auth-service/internal/store"
	"github.com/tylerpetri/GoRituals/shared/authkit"
)

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("missing env %s", k)
	}
	return v
}

func main() {
	cfg, err := httpapi.LoadConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}

	var ver authkit.Verifier

	switch cfg.Alg { // HS256 | RS256 | EdDSA
	case "HS256":
		// secret is base64url in env (no padding)
		secret, err := httpapi.SecretFromEnv("JWT_HS256_SECRET_B64")
		if err != nil {
			log.Fatal(err)
		}
		ver = authkit.NewVerifierHS256(secret, authkit.Options{
			Issuer: cfg.Issuer, Audience: cfg.Audience, Leeway: 30 * time.Second,
		})

	case "RS256":
		j := authkit.NewJWKSProvider(cfg.PublicBaseURL+"/.well-known/jwks.json", "RS256")
		j.Start(context.Background(), 5*time.Minute)
		ver = authkit.NewVerifierRS256(j, authkit.Options{
			Issuer: cfg.Issuer, Audience: cfg.Audience, Leeway: 30 * time.Second,
		})

	case "EdDSA":
		j := authkit.NewJWKSProvider(cfg.PublicBaseURL+"/.well-known/jwks.json", "EdDSA")
		j.Start(context.Background(), 5*time.Minute)
		ver = authkit.NewVerifierEdDSA(j, authkit.Options{
			Issuer: cfg.Issuer, Audience: cfg.Audience, Leeway: 30 * time.Second,
		})

	default:
		log.Fatalf("unsupported JWT_ALG: %s", cfg.Alg)
	}

	level := slog.LevelInfo
	if os.Getenv("LOG_LEVEL") == "debug" {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	ctx := context.Background()
	st, err := store.Open(ctx, store.Config{
		DSN:             mustEnv("DATABASE_URL"),
		MaxConns:        10,
		MinConns:        1,
		MaxConnIdleTime: 5 * time.Minute,
		HealthTimeout:   3 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	tokens := authrepo.NewTokens(dbgen.New(st.Pool))
	issuer, rsaIss, edIss := httpapi.BuildIssuer(cfg)

	h := &httpapi.Handler{
		Store:         st,
		Tokens:        tokens,
		JWTIssuer:     issuer,
		CookieRefresh: true,
		Logger:        logger,
		Cfg:           cfg,
	}
	mux := httpapi.NewMux(h, ver, rsaIss, edIss, cfg.PublicBaseURL)

	log.Printf("auth service on %s (alg=%s, iss=%s)", cfg.HTTPAddr, cfg.Alg, cfg.Issuer)
	if err := http.ListenAndServe(cfg.HTTPAddr, mux); err != nil {
		log.Fatal(err)
	}
}
