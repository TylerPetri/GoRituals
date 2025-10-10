# -------- Config --------
APP_NAME       := auth-service
CMD_DIR        := ./cmd/auth-service
SECRETS_DIR    := secrets/dev
PKCS1_PRIV     := $(SECRETS_DIR)/rsa_pkcs1_private.pem
PKCS8_PRIV     := $(SECRETS_DIR)/rsa_pkcs8_private.pem
RSA_PUBLIC     := $(SECRETS_DIR)/rsa_public.pem
KEY_BITS       := 2048

IMAGE_NAME     := $(APP_NAME):latest
PORT           := 8080

# -------- Helpers --------
SHELL := /bin/bash

.PHONY: all dev-keys pkcs1 pkcs8 pub perms clean run run-pkcs1 run-pkcs8 build docker-build docker-run docker-run-pkcs1 docker-run-pkcs8

all: dev-keys

$(SECRETS_DIR):
	mkdir -p "$(SECRETS_DIR)"

# Generate PKCS#1 private key
pkcs1: | $(SECRETS_DIR)
	@if [ -f "$(PKCS1_PRIV)" ]; then \
		echo "PKCS#1 already exists: $(PKCS1_PRIV)"; \
	else \
		echo "Generating PKCS#1 private key → $(PKCS1_PRIV)"; \
		openssl genrsa -out "$(PKCS1_PRIV)" $(KEY_BITS); \
	fi

# Convert to PKCS#8 (unencrypted)
pkcs8: pkcs1
	@if [ -f "$(PKCS8_PRIV)" ]; then \
		echo "PKCS#8 already exists: $(PKCS8_PRIV)"; \
	else \
		echo "Converting PKCS#1 → PKCS#8 (unencrypted) → $(PKCS8_PRIV)"; \
		openssl pkcs8 -topk8 -nocrypt -in "$(PKCS1_PRIV)" -out "$(PKCS8_PRIV)"; \
	fi

# Derive public key (works from either PKCS#1 or PKCS#8)
pub: pkcs1
	@echo "Deriving RSA public key → $(RSA_PUBLIC)"
	@if openssl pkey -in "$(PKCS1_PRIV)" -pubout -out "$(RSA_PUBLIC)" 2>/dev/null; then \
		true; \
	else \
		openssl pkey -in "$(PKCS8_PRIV)" -pubout -out "$(RSA_PUBLIC)"; \
	fi

perms:
	@echo "Locking down permissions on PEMs"
	@chmod 600 "$(SECRETS_DIR)"/*.pem 2>/dev/null || true

# One-shot: generate everything you need for local dev
dev-keys: pkcs1 pkcs8 pub perms
	@echo "✔ Dev keys ready in $(SECRETS_DIR)"
	@echo
	@echo "Add these to your .env (example):"
	@echo "PORT=$(PORT)"
	@echo "AUTH_RSA_PRIVATE_KEY_PATH=$(PKCS1_PRIV)"
	@echo "AUTH_RSA_PUBLIC_KEY_PATH=$(RSA_PUBLIC)"
	@echo "AUTH_JWT_KID=dev-key-001"

clean:
	@echo "Cleaning $(SECRETS_DIR)"
	@rm -f "$(SECRETS_DIR)"/rsa_pkcs1_private.pem \
	       "$(SECRETS_DIR)"/rsa_pkcs8_private.pem \
	       "$(SECRETS_DIR)"/rsa_public.pem

# -------- Go run/build --------

# Loads .env if present, then runs the service.
# Uses whatever private key path you put in .env.
run:
	@set -a; [ -f .env ] && . ./.env; set +a; \
	echo "Running $(APP_NAME) on :$${PORT:-$(PORT)}"; \
	go run $(CMD_DIR)

# Force PKCS#1 or PKCS#8 path without editing .env
run-pkcs1: dev-keys
	@set -a; [ -f .env ] && . ./.env; \
	export AUTH_RSA_PRIVATE_KEY_PATH="$(PKCS1_PRIV)"; \
	export AUTH_RSA_PUBLIC_KEY_PATH="$(RSA_PUBLIC)"; \
	export PORT="$${PORT:-$(PORT)}"; set +a; \
	echo "Running (PKCS#1) $(APP_NAME) on :$$PORT"; \
	go run $(CMD_DIR)

run-pkcs8: dev-keys
	@set -a; [ -f .env ] && . ./.env; \
	export AUTH_RSA_PRIVATE_KEY_PATH="$(PKCS8_PRIV)"; \
	export AUTH_RSA_PUBLIC_KEY_PATH="$(RSA_PUBLIC)"; \
	export PORT="$${PORT:-$(PORT)}"; set +a; \
	echo "Running (PKCS#8) $(APP_NAME) on :$$PORT"; \
	go run $(CMD_DIR)

build:
	@echo "Building $(APP_NAME)"
	@go build -o bin/$(APP_NAME) $(CMD_DIR)

# -------- Docker --------

docker-build:
	@echo "Building image $(IMAGE_NAME)"
	@docker build -t $(IMAGE_NAME) .

# Mounts dev keys and forwards port.
docker-run: docker-build dev-keys
	@echo "Running container $(IMAGE_NAME) with keys from $(SECRETS_DIR)"
	@docker run --rm -p $(PORT):$(PORT) \
	  -e PORT=$(PORT) \
	  -e AUTH_RSA_PRIVATE_KEY_PATH=/run/keys/rsa_pkcs1_private.pem \
	  -e AUTH_RSA_PUBLIC_KEY_PATH=/run/keys/rsa_public.pem \
	  -e AUTH_JWT_KID=dev-key-001 \
	  -v $$PWD/$(SECRETS_DIR):/run/keys:ro \
	  $(IMAGE_NAME)

docker-run-pkcs1: docker-build dev-keys
	@docker run --rm -p $(PORT):$(PORT) \
	  -e PORT=$(PORT) \
	  -e AUTH_RSA_PRIVATE_KEY_PATH=/run/keys/rsa_pkcs1_private.pem \
	  -e AUTH_RSA_PUBLIC_KEY_PATH=/run/keys/rsa_public.pem \
	  -e AUTH_JWT_KID=dev-key-001 \
	  -v $$PWD/$(SECRETS_DIR):/run/keys:ro \
	  $(IMAGE_NAME)

docker-run-pkcs8: docker-build dev-keys
	@docker run --rm -p $(PORT):$(PORT) \
	  -e PORT=$(PORT) \
	  -e AUTH_RSA_PRIVATE_KEY_PATH=/run/keys/rsa_pkcs8_private.pem \
	  -e AUTH_RSA_PUBLIC_KEY_PATH=/run/keys/rsa_public.pem \
	  -e AUTH_JWT_KID=dev-key-001 \
	  -v $$PWD/$(SECRETS_DIR):/run/keys:ro \
	  $(IMAGE_NAME)
