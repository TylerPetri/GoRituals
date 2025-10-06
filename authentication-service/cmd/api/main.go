package main

import (
	"log"
)

const webPort = "80"

type Config struct {
}

func main() {
	log.Println("Starting authentication service on port:", webPort)

	// h := &httpapi.Handler{
	// 	Store:     store,
	// 	Tokens:    authrepo.NewTokens(dbgen.New(store.Pool)), // or however you wire it
	// 	JWTIssuer: myJWTIssuer,                               // implements IssueAccessToken
	// }
	// mux.HandleFunc("/v1/tokens/refresh", h.RefreshToken)

	// ------------ SIMPLE SHARED SECRET ----------------

	// secret := []byte(os.Getenv("JWT_HS256_SECRET")) // length >= 32 recommended
	// issuer := "https://auth.example.com"
	// aud := "my-api"

	// h := &httpapi.Handler{
	// 	Store:     store,
	// 	Tokens:    authrepo.NewTokens(dbgen.New(store.Pool)),
	// 	JWTIssuer: httpapi.NewHS256Issuer(secret, issuer, aud, "v1"), // kid "v1" (optional)
	// }
	// mux.HandleFunc("/v1/tokens/refresh", h.RefreshToken)

	// ----------- RSA + JWKS (key rotation friendly) ----------------

	// Load/generate your active private key (PEM parsing not shown here).
	// priv, _ := httpapi.GenerateRSAKey(2048) // or load from disk/KMS
	// issuer := "https://auth.example.com"
	// aud := "my-api"

	// rsaIssuer := httpapi.NewRSAJWKSIssuer("kid-2025-10", priv, issuer, aud)

	// // Optionally add older public keys so existing tokens still verify:
	// rsaIssuer.AddPublicKey("kid-2025-06", &oldPriv.PublicKey) // if rotating

	// h := &httpapi.Handler{
	//     Store:     store,
	//     Tokens:    authrepo.NewTokens(dbgen.New(store.Pool)),
	//     JWTIssuer: rsaIssuer,
	// }
	// mux.Handle("/.well-known/jwks.json", rsaIssuer.JWKSHandler())
	// mux.HandleFunc("/v1/tokens/refresh", h.RefreshToken)

	// ------------------ VERIFY TOKEN ISSUED BY OWN SERVICE (local JWKS) ----------------------

	// Build a static provider from your issuer’s public keys
	// static := httpapi.NewStaticJWKSProvider()
	// for kid, pub := range rsaIssuer.PubKeys {
	// 	static.Add(kid, pub)
	// }
	// ver := &httpapi.JWTVerifier{
	// 	Issuer:   "https://auth.example.com",
	// 	Audience: "my-api",
	// 	Keys:     static,
	// }

	// // Protect routes
	// mux.Handle("/v1/me", httpapi.AuthMiddleware(ver, http.HandlerFunc(meHandler)))

	// ------------------ VERIFY TOKEN FROM ANOTHER SERVICE VITA HTTP JWKS --------------------------

	// jwksURL := "https://auth.example.com/.well-known/jwks.json"
	// prov := httpapi.NewHTTPJWKSProvider(jwksURL, 10*time.Minute)

	// ver := &httpapi.JWTVerifier{
	// 	Issuer:   "https://auth.example.com",
	// 	Audience: "my-api",
	// 	Keys:     prov,
	// }
	// mux.Handle("/v1/me", httpapi.AuthMiddleware(ver, http.HandlerFunc(meHandler)))

	// -------------------- HS256 WIRE IT UP ----------------------------------------------

	// Issuer side (you already have HS256Issuer for issuing)
	// secret := []byte(os.Getenv("JWT_HS256_SECRET")) // >=32 bytes recommended
	// issuer := "https://auth.example.com"
	// aud     := "my-api"

	// // Verifier (same service or another service)
	// secrets := NewStaticHSSecrets().
	// 	Add("v1", secret). // kid must match the HS256Issuer's KID
	// 	SetDefault("v1")   // allows tokens without kid header (optional)

	// hsVer := &HS256Verifier{
	// 	Issuer:   issuer,
	// 	Audience: aud,
	// 	Keys:     secrets,
	// }

	// // Protect routes with the generic middleware
	// mux.Handle("/v1/me", AuthMiddlewareAny(hsVer, http.HandlerFunc(meHandler)))

}

// For production, store HS256 secrets and RSA private keys in KMS/HSM or your secret manager, not in code or env if you can avoid it. When rotating RSA keys, publish the new public key to JWKS before switching ActiveKID, then switch and keep old keys in the JWKS until all old tokens have expired.
