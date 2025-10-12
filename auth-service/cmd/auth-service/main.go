package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"authentication/internal/authrepo"
	"authentication/internal/dbgen"
	"authentication/internal/httpapi"
	"authentication/internal/store"
)

func main() {
	// Load config from env
	cfg, err := httpapi.LoadConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}

	// Open DB (adjust config for your store)
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

	// Repos
	tokens := authrepo.NewTokens(dbgen.New(st.Pool))

	// Build issuer + JWKS
	issuer, rsaIss, edIss := httpapi.BuildIssuer(cfg)

	// HTTP Handler and Mux
	h := &httpapi.Handler{
		Store:     st,
		Tokens:    tokens,
		JWTIssuer: issuer,
	}
	mux := httpapi.NewMux(h, rsaIss, edIss, cfg.PublicBaseURL)

	log.Printf("auth service on %s (alg=%s)", cfg.HTTPAddr, cfg.Alg)
	if err := http.ListenAndServe(cfg.HTTPAddr, mux); err != nil {
		log.Fatal(err)
	}
}

func mustEnv(k string) string {
	v := getenv(k, "")
	if v == "" {
		log.Fatalf("missing env %s", k)
	}
	return v
}
func getenv(k, def string) string {
	if v := syscallGetenv(k); v != "" {
		return v
	}
	return def
}
func syscallGetenv(k string) string { return "" } // replace with os.Getenv in your code
