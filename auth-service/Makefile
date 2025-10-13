ENV ?= .env

# ==========================================
# ============ AUTH-SERVICE ================
# ==========================================

.PHONY: auth-up auth-logs
auth-up:
	docker compose --env-file $(ENV) up -d --build auth
auth-logs:
	docker compose --env-file $(ENV) logs -f auth

# ==========================================
# ================== DB ====================
# ==========================================

.PHONY: db-up db-down db-reset db-recreate db-logs
db-up:
	docker compose --env-file $(ENV) up -d db
db-logs:
	docker compose logs -f db
db-down:
	docker compose down
db-recreate:
	docker compose --env-file $(ENV) down -v
	docker compose --env-file $(ENV) up -d db
	docker compose --env-file $(ENV) logs -f db
db-reset:
	docker compose down -v
	rm -rf ./secrets/* || true

MIGRATE_DB_URL := $(shell grep ^DATABASE_URL $(ENV) | cut -d= -f2-)
MIGRATE_BASE = docker compose --env-file $(ENV) run --rm migrate -path=/migrations -database "$(MIGRATE_DB_URL)"

.PHONY: migrate-up migrate-down migrate-version migrate-new
migrate-up:
	$(MIGRATE_BASE) up
migrate-down:
	$(MIGRATE_BASE) down 1
migrate-version:
	$(MIGRATE_BASE) version
migrate-new:
	docker compose --env-file $(ENV) run --rm migrate create -seq -ext sql -dir /migrations $(NAME)

# ==========================================
# ================ PGADMIN =================
# ==========================================

.PHONY: pgadmin-up pgadmin-logs pgadmin-down
pgadmin-up:
	docker compose --env-file $(ENV) up -d pgadmin

pgadmin-logs:
	docker compose --env-file $(ENV) logs -f pgadmin

pgadmin-down:
	docker compose --env-file $(ENV) rm -sfv pgadmin


# ==========================================
# ================ SECRETS =================
# ==========================================

SECRETS_DIR ?= ./secrets
ED_KID := $(shell grep -E '^JWT_ED25519_ACTIVE_KID=' $(ENV) | cut -d= -f2-)
RS_KID := $(shell grep -E '^JWT_RS256_ACTIVE_KID=' $(ENV) | cut -d= -f2-)

.PHONY: mkdir-secrets
mkdir-secrets:
	@mkdir -p $(SECRETS_DIR)

# ====== RSA (RS256) ======
# Generates PKCS#8 private and SPKI public PEMs:
#   secrets/<RS_KID>.key  (private, chmod 600)
#   secrets/<RS_KID>.pub  (public)
.PHONY: keys-rs
keys-rs: mkdir-secrets
	@openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $(SECRETS_DIR)/$(RS_KID).key
	@openssl pkey -in $(SECRETS_DIR)/$(RS_KID).key -pubout -out $(SECRETS_DIR)/$(RS_KID).pub
	@chmod 600 $(SECRETS_DIR)/$(RS_KID).key
	@echo "Wrote: $(SECRETS_DIR)/$(RS_KID).key (private), $(SECRETS_DIR)/$(RS_KID).pub (public)"

# ====== Ed25519 (EdDSA) ======
# Generates PKCS#8 private and SPKI public PEMs:
.PHONY: keys-ed
keys-ed: mkdir-secrets
	@openssl genpkey -algorithm Ed25519 -out $(SECRETS_DIR)/$(ED_KID).key
	@openssl pkey -in $(SECRETS_DIR)/$(ED_KID).key -pubout -out $(SECRETS_DIR)/$(ED_KID).pub
	@chmod 600 $(SECRETS_DIR)/$(ED_KID).key
	@echo "Wrote: $(SECRETS_DIR)/$(ED_KID).key (private), $(SECRETS_DIR)/$(ED_KID).pub (public)"

# ====== HS256 secret (base64url, no padding) ======
# Prints the secret and appends JWT_HS256_SECRET_B64=... to .env if present.
.PHONY: keys-hs
keys-hs:
	@SECRET=$$(openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n'); \
	echo $$SECRET; \
	if [ -f .env ]; then \
		echo "JWT_HS256_SECRET_B64=$$SECRET" >> .env; \
		echo "Appended JWT_HS256_SECRET_B64 to .env"; \
	fi

# ====== cleanup ======
.PHONY: clean-keys
clean-keys:
	@rm -f $(SECRETS_DIR)/*.key $(SECRETS_DIR)/*.pub
	@echo "Removed key files in $(SECRETS_DIR)"

# ==========================================
# ============== SMOKE TEST ================
# ==========================================

SMOKE_SCRIPT ?= ./scripts/smoke-auth.sh
BASE_URL     ?= http://localhost:8080
EMAIL        ?= smoke+$(shell date +%s)@example.com
PASSWORD     ?= Secret123!

.PHONY: smoke smoke-verbose smoke-email
# Run the full end-to-end auth smoke test (signup, me, refresh, logout, login, logout-all)
smoke:
	@command -v jq >/dev/null || (echo "jq is required (brew install jq / apt-get install jq)"; exit 1)
	@command -v curl >/dev/null || (echo "curl is required"; exit 1)
	BASE_URL=$(BASE_URL) EMAIL=$(EMAIL) PASSWORD='$(PASSWORD)' $(SMOKE_SCRIPT)

# Same as 'smoke' but verbose HTTP output
smoke-verbose:
	@command -v jq >/dev/null || (echo "jq is required (brew install jq / apt-get install jq)"; exit 1)
	@command -v curl >/dev/null || (echo "curl is required"; exit 1)
	BASE_URL=$(BASE_URL) EMAIL=$(EMAIL) PASSWORD='$(PASSWORD)' VERBOSE=1 $(SMOKE_SCRIPT)

# Example of overriding just the email on the CLI:
#   make smoke-email EMAIL=me@example.com
smoke-email: smoke