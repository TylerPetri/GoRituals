# Quick start (RS256):
```
make keys-rs KID=kid-2025-10
# (optional old pub for rotation)
make keys-rs KID=kid-2025-06

# fill .env from .env.example, e.g.:
cat > .env <<'ENV'
PUBLIC_BASE_URL=http://localhost:8080
JWT_ISSUER=http://localhost:8080
JWT_AUDIENCE=my-api
JWT_ALG=RS256
JWT_RS256_ACTIVE_KID=kid-2025-10
JWT_RS256_PRIVATE_KEY_FILE=/secrets/kid-2025-10.key
JWT_RS256_PUBLIC_KEYS=kid-2025-06=/secrets/kid-2025-06.pub
DATABASE_URL=postgres://user:pass@localhost:5432/app?sslmode=disable
HTTP_ADDR=:8080
ENV

docker compose up --build
```
### Switch to Ed25519:
```
make keys-ed KID=kid-ed-2025-10
# .env:
# JWT_ALG=EdDSA
# JWT_ED25519_ACTIVE_KID=kid-ed-2025-10
# JWT_ED25519_PRIVATE_KEY_FILE=/secrets/kid-ed-2025-10.key
docker compose up --build
```
### Use HS256:
```
make keys-hs    # copies secret into .env if present
# .env:
# JWT_ALG=HS256
# JWT_HS256_KID=v1
# JWT_HS256_SECRET_B64=<printed>
docker compose up --build
```

# Rotation flow
1. Generate the new keypair: 
    ```
    make keys-rs KID=kid-2026-01
    ```
2. Publish the new public key in JWKS:
    ```
    JWT_RS256_PUBLIC_KEYS="kid-2025-10=/secrets/kid-2025-10.pub,kid-2026-01=/secrets/kid-2026-01.pub"
    ```
3. Switch active in `.env`: 
    ```
    JWT_RS256_ACTIVE_KID=kid-2026-01
    JWT_RS256_PRIVATE_KEY_FILE=/secrets/kid-2026-01.key
    ```
4. `docker compose up -d --build` (restarts auth only).
5. Keep the old pub in `JWT_RS256_PUBLIC_KEYS` until old access tokens expire.
6. Check health:
    - RS: `GET /health/jwks/rs256`
    - Ed: `GET /health/jwks/eddsa`

# Sanity checks
- Print key details:
```
openssl pkey -in /secrets/rs256.key -text -noout
openssl pkey -in /secrets/ed25519.key -text -noout
openssl pkey -pubin -in /secrets/rs256.pub -text -noout
```
- File perms: private keys `chmod 600`.
- PEM types should be:
  - RSA private: `RSA PRIVATE KEY` (PKCS#1) or `PRIVATE KEY` (PKCS#8) - both are OK for this loader.
  - RSA public: `PUBLIC KEY`
  - Ed25519 private: `PRIVATE KEY` (PKCS#8)
  - Ed25519 public: `PUBLIC KEY`

# Generate keys

Makefile usage:
```
# RSA
make keys-rs KID=kid-2025-10

# Ed25519
make keys-ed KID=kid-ed-2025-10

# HS256 (prints secret; appends to .env if it exists)
make keys-hs
```

Script:
```
scripts/gen-keys.sh rs /secrets kid-2025-10
scripts/gen-keys.sh ed /secrets kid-ed-2025-10

Then set env like:

# RS256 issuing
JWT_ALG=RS256
JWT_RS256_ACTIVE_KID=kid-2025-10
JWT_RS256_PRIVATE_KEY_FILE=/secrets/kid-2025-10.key
# (optional extras during rotation)
JWT_RS256_PUBLIC_KEYS="kid-2025-06=/secrets/kid-2025-06.pub"

# Ed25519 issuing
JWT_ALG=EdDSA
JWT_ED25519_ACTIVE_KID=kid-ed-2025-10
JWT_ED25519_PRIVATE_KEY_FILE=/secrets/kid-ed-2025-10.key
JWT_ED25519_PUBLIC_KEYS="kid-ed-2025-06=/secrets/kid-ed-2025-06.pub"

Then make it executable:
chmod +x scripts/gen-keys.sh
```

CI/dev:
```
go build -o keygen ./cmd/keygen
./keygen -alg rs -out /secrets -kid kid-2025-10
./keygen -alg ed -out /secrets -kid kid-ed-2025-10
```

One-liners:

#### RS256 (RSA)
```
# Private key (PKCS#8, unencrypted)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /secrets/rs256.key
# Public key (X.509 SPKI "PUBLIC KEY")
openssl pkey -in /secrets/rs256.key -pubout -out /secrets/rs256.pub
chmod 600 /secrets/rs256.key
```

#### Ed25519 (EdDSA)
```
# Private key (PKCS#8, unencrypted)
openssl genpkey -algorithm Ed25519 -out /secrets/ed25519.key
# Public key (X.509 SPKI "PUBLIC KEY")
openssl pkey -in /secrets/ed25519.key -pubout -out /secrets/ed25519.pub
chmod 600 /secrets/ed25519.key
```

#### HS256 secret (base64url, no padding)
- Linux/macOS with Python:
```
python3 - <<'PY'
import os, base64
print(base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode())
PY
```
- POSIX (OpenSSL + base64, convert to URL-safe, strip =)
```
openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n'
```

# Sanity checks (handy)
- Verify compose sees your env:
`docker compose --env-file .env config | grep -A2 environment:`
- Shell into DB container and check:
`docker exec -it auth-db psql -U app -d app -c "select current_user, current_database();"`