# Temp notes
Health endpoints:
- RS: `GET /health/jwks/rs256`
- EdDSA: `GET /health/jwks/eddsa`


# SECRETS (.gitignore IMPORTANT)
```
mkdir secrets
mkdir secrets/dev && cd secrets/dev
touch rsa_pkcs1_private.pem rsa_pkcs8_private.pem rsa_public.pem
```

# Generate keys (PKCS#1 vs PKCS#8)

### 1) Generate PKCS#1 private key (unencrypted)
openssl genrsa -out secrets/dev/rsa_pkcs1_private.pem 2048

### 2) Derive public key (PEM)
openssl rsa -in secrets/dev/rsa_pkcs1_private.pem -pubout -out secrets/dev/rsa_public.pem

### 1) Generate a PKCS#1 first or use pkey directly:
openssl genrsa -out secrets/dev/rsa_pkcs1_private.pem 2048

### 2) Convert to PKCS#8 (unencrypted: -nocrypt)
openssl pkcs8 -topk8 -nocrypt \
  -in secrets/dev/rsa_pkcs1_private.pem \
  -out secrets/dev/rsa_pkcs8_private.pem

### 3) Derive public key from PKCS#8 (either file works)
openssl pkey -in secrets/dev/rsa_pkcs8_private.pem -pubout -out secrets/dev/rsa_public.pem

# Permissions (recommended)

`chmod 600 secrets/dev/*.pem`

```
// other-service main.go
jwksURL := os.Getenv("AUTH_JWKS_URL") // e.g., https://auth.example.com/.well-known/jwks.json
prov := httpapi.NewHTTPJWKSProvider(jwksURL, 10*time.Minute)
ver  := &httpapi.JWTVerifier{Issuer: os.Getenv("JWT_ISSUER"), Audience: os.Getenv("JWT_AUDIENCE"), Keys: prov}

mux.Handle("/v1/me", httpapi.AuthMiddleware(ver, http.HandlerFunc(meHandler)))
```