# ====== config ======
SECRETS_DIR ?= ./secrets
KID         ?= kid-$(shell date +%Y%m%d%H%M%S)

# ====== helpers ======
.PHONY: mkdir-secrets
mkdir-secrets:
	@mkdir -p $(SECRETS_DIR)

# ====== RSA (RS256) ======
# Generates PKCS#8 private and SPKI public PEMs:
#   secrets/<KID>.key  (private, chmod 600)
#   secrets/<KID>.pub  (public)
.PHONY: keys-rs
keys-rs: mkdir-secrets
	@openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $(SECRETS_DIR)/$(KID).key
	@openssl pkey -in $(SECRETS_DIR)/$(KID).key -pubout -out $(SECRETS_DIR)/$(KID).pub
	@chmod 600 $(SECRETS_DIR)/$(KID).key
	@echo "Wrote: $(SECRETS_DIR)/$(KID).key (private), $(SECRETS_DIR)/$(KID).pub (public)"

# ====== Ed25519 (EdDSA) ======
# Generates PKCS#8 private and SPKI public PEMs:
.PHONY: keys-ed
keys-ed: mkdir-secrets
	@openssl genpkey -algorithm Ed25519 -out $(SECRETS_DIR)/$(KID).key
	@openssl pkey -in $(SECRETS_DIR)/$(KID).key -pubout -out $(SECRETS_DIR)/$(KID).pub
	@chmod 600 $(SECRETS_DIR)/$(KID).key
	@echo "Wrote: $(SECRETS_DIR)/$(KID).key (private), $(SECRETS_DIR)/$(KID).pub (public)"

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
