ROOT    := $(abspath $(CURDIR))
OPENAPI := $(ROOT)/shared/openapi/openapi.yaml

.PHONY: gen-go-client
gen-go-client:
	@test -f "$(OPENAPI)" || (echo "Missing $(OPENAPI)"; exit 1)
	docker run --rm \
	  -v "$(ROOT):/work" -w /work \
	  ghcr.io/deepmap/oapi-codegen:v2.3.0 \
	  --package authclient \
	  --generate types,client \
	  --output /work/shared/clients/go/client.gen.go \
	  /work/shared/openapi/openapi.yaml

.PHONY: gen-ts-client
gen-ts-client:
	@test -f "$(OPENAPI)" || (echo "Missing $(OPENAPI)"; exit 1)
	docker run --rm \
	  -v "$(ROOT):/work" -w /work \
	  openapitools/openapi-generator-cli:v7.7.0 generate \
	  -i /work/shared/openapi/openapi.yaml \
	  -g typescript-fetch \
	  -o /work/shared/clients/ts \
	  --additional-properties=supportsES6=true,typescriptThreePlus=true

.PHONY: gen-clients
gen-clients: gen-go-client gen-ts-client
