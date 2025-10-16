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
	mux := httpapi.NewMux(h, rsaIss, edIss, cfg.PublicBaseURL)

	log.Printf("auth service on %s (alg=%s, iss=%s)", cfg.HTTPAddr, cfg.Alg, cfg.Issuer)
	if err := http.ListenAndServe(cfg.HTTPAddr, mux); err != nil {
		log.Fatal(err)
	}
}
