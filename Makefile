BINARY    := concert
VERSION   := $(shell cat VERSION)
BIN_DIR   := bin
DIST_DIR  := dist
PLATFORMS := linux/amd64 linux/arm64

BINARIES      := concert wpconcert econcert bench-concert concert-client concert-kv concert-cache concert-watchdog
FIPS_BINARIES := concert-fips wpconcert-fips econcert-fips

GO_BUILD_FLAGS := -trimpath -buildvcs=false
GO_LDFLAGS     := -s -w

IMAGE_PREFIX     ?=
DOCKER_PLATFORMS ?= linux/amd64,linux/arm64
DOCKER_PUSH      ?= false

os   = $(word 1,$(subst /, ,$1))
arch = $(word 2,$(subst /, ,$1))
img  = $(if $(IMAGE_PREFIX),$(IMAGE_PREFIX)/$(1),$(1))

.PHONY: all test test-race test-testnet lint clean bench build build-fips dist docker docker-buildx sbom vulncheck checksums $(PLATFORMS)

all: lint clean test test-race bench summary build sbom checksums

test:
	go test -count=1 ./internal/... ./cmd/concert ./cmd/bench-concert ./cmd/concert-kv ./cmd/concert-cache ./cmd/concert-watchdog
	go test -count=1 -tags wordpress ./internal/... ./cmd/wpconcert
	go test -count=1 -tags "wordpress,enterprise" ./...

test-race:
	go test -race -count=1 ./internal/... ./cmd/concert ./cmd/bench-concert ./cmd/concert-kv ./cmd/concert-cache ./cmd/concert-watchdog
	go test -race -count=1 -tags wordpress ./internal/... ./cmd/wpconcert
	go test -race -count=1 -tags "wordpress,enterprise" ./...

test-testnet:
	go test -v -count=1 -tags "wordpress,enterprise,livetestnet" -timeout 10m ./internal/server -run TestLiveTestnet

bench:
	go test -bench=. -benchmem -tags "wordpress,enterprise" ./...

lint:
	go vet ./internal/... ./cmd/concert ./cmd/bench-concert ./cmd/concert-kv ./cmd/concert-cache ./cmd/concert-watchdog
	go vet -tags wordpress ./internal/... ./cmd/wpconcert
	go vet -tags "wordpress,enterprise" ./...

vulncheck:
	govulncheck ./cmd/concert ./cmd/bench-concert ./cmd/concert-kv ./cmd/concert-cache ./cmd/concert-watchdog
	govulncheck -tags wordpress ./cmd/wpconcert
	govulncheck -tags "wordpress,enterprise" ./...

sbom:
	@mkdir -p $(BIN_DIR)
	python3 scripts/generate-sbom.py --pkg ./cmd/concert --name concert -o $(BIN_DIR)/concert-sbom.cdx.json
	python3 scripts/generate-sbom.py --pkg ./cmd/wpconcert --tags wordpress --name wpconcert -o $(BIN_DIR)/wpconcert-sbom.cdx.json
	python3 scripts/generate-sbom.py --pkg ./cmd/econcert --tags "wordpress,enterprise" --name econcert -o $(BIN_DIR)/econcert-sbom.cdx.json

clean:
	go clean ./...
	rm -rf $(BIN_DIR) $(DIST_DIR)

summary:
	summarize -s useExpanded,internal/server/templates/lib,.git,.idea,summaries,lemmings -x useExpanded,png,jpg,LICENSE

build: $(PLATFORMS)

# FIPS 140-3 validated Go cryptographic module builds (Go 1.24+, Linux only).
build-fips:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOFIPS140=v1.0.0 GOOS=linux GOARCH=amd64 \
		go build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/concert-fips-linux-amd64 ./cmd/concert
	CGO_ENABLED=0 GOFIPS140=v1.0.0 GOOS=linux GOARCH=arm64 \
		go build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/concert-fips-linux-arm64 ./cmd/concert
	CGO_ENABLED=0 GOFIPS140=v1.0.0 GOOS=linux GOARCH=amd64 \
		go build -tags wordpress $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/wpconcert-fips-linux-amd64 ./cmd/wpconcert
	CGO_ENABLED=0 GOFIPS140=v1.0.0 GOOS=linux GOARCH=arm64 \
		go build -tags wordpress $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/wpconcert-fips-linux-arm64 ./cmd/wpconcert
	CGO_ENABLED=0 GOFIPS140=v1.0.0 GOOS=linux GOARCH=amd64 \
		go build -tags "wordpress,enterprise" $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/econcert-fips-linux-amd64 ./cmd/econcert
	CGO_ENABLED=0 GOFIPS140=v1.0.0 GOOS=linux GOARCH=arm64 \
		go build -tags "wordpress,enterprise" $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/econcert-fips-linux-arm64 ./cmd/econcert

checksums:
	@cd $(BIN_DIR) && shasum -a 256 $$(ls -1 concert-* wpconcert-* econcert-* bench-concert-* | sort -u) > SHA256SUMS.txt

# Package Linux release tarballs, CycloneDX 1.5 SBOMs, and SHA256SUMS.txt into dist/.
dist: build build-fips sbom
	@rm -rf $(DIST_DIR)
	@mkdir -p $(DIST_DIR)
	@for name in $(BINARIES) $(FIPS_BINARIES); do \
		for arch in amd64 arm64; do \
			stage=$$(mktemp -d); \
			cp $(BIN_DIR)/$$name-linux-$$arch $$stage/$$name; \
			chmod 0755 $$stage/$$name; \
			cp LICENSE VERSION $$stage/; \
			COPYFILE_DISABLE=1 tar -C $$stage -czf $(DIST_DIR)/$$name-$(VERSION)-linux-$$arch.tar.gz $$name LICENSE VERSION; \
			rm -rf $$stage; \
		done; \
	done
	@cp $(BIN_DIR)/concert-sbom.cdx.json $(DIST_DIR)/concert-$(VERSION)-sbom.cdx.json
	@cp $(BIN_DIR)/wpconcert-sbom.cdx.json $(DIST_DIR)/wpconcert-$(VERSION)-sbom.cdx.json
	@cp $(BIN_DIR)/econcert-sbom.cdx.json $(DIST_DIR)/econcert-$(VERSION)-sbom.cdx.json
	@cd $(DIST_DIR) && shasum -a 256 *.tar.gz *.cdx.json > SHA256SUMS.txt
	@echo "Packaged Linux $(VERSION) release artifacts in $(DIST_DIR)/"

# Build local distroless container images for all editions.
docker:
	docker build -f Dockerfile --build-arg VERSION=$(VERSION) \
		-t $(call img,concert):$(VERSION) -t $(call img,concert):latest .
	docker build -f Dockerfile.wpconcert --build-arg VERSION=$(VERSION) \
		-t $(call img,wpconcert):$(VERSION) -t $(call img,wpconcert):latest .
	docker build -f Dockerfile.econcert --build-arg VERSION=$(VERSION) \
		-t $(call img,econcert):$(VERSION) -t $(call img,econcert):latest .

# Build multi-arch Linux (amd64 + arm64) distroless images via Docker Buildx.
# Pass IMAGE_PREFIX=ghcr.io/andreimerlescu DOCKER_PUSH=true to publish manifests.
docker-buildx:
	docker buildx build --platform $(DOCKER_PLATFORMS) -f Dockerfile --build-arg VERSION=$(VERSION) \
		-t $(call img,concert):$(VERSION) -t $(call img,concert):latest \
		$(if $(filter true,$(DOCKER_PUSH)),--push,) .
	docker buildx build --platform $(DOCKER_PLATFORMS) -f Dockerfile.wpconcert --build-arg VERSION=$(VERSION) \
		-t $(call img,wpconcert):$(VERSION) -t $(call img,wpconcert):latest \
		$(if $(filter true,$(DOCKER_PUSH)),--push,) .
	docker buildx build --platform $(DOCKER_PLATFORMS) -f Dockerfile.econcert --build-arg VERSION=$(VERSION) \
		-t $(call img,econcert):$(VERSION) -t $(call img,econcert):latest \
		$(if $(filter true,$(DOCKER_PUSH)),--push,) .

$(PLATFORMS):
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=$(call os,$@) GOARCH=$(call arch,$@) \
		go build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/concert-$(call os,$@)-$(call arch,$@) ./cmd/concert
	CGO_ENABLED=0 GOOS=$(call os,$@) GOARCH=$(call arch,$@) \
		go build -tags wordpress $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/wpconcert-$(call os,$@)-$(call arch,$@) ./cmd/wpconcert
	CGO_ENABLED=0 GOOS=$(call os,$@) GOARCH=$(call arch,$@) \
		go build -tags "wordpress,enterprise" $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/econcert-$(call os,$@)-$(call arch,$@) ./cmd/econcert
	CGO_ENABLED=0 GOOS=$(call os,$@) GOARCH=$(call arch,$@) \
		go build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/bench-concert-$(call os,$@)-$(call arch,$@) ./cmd/bench-concert
	CGO_ENABLED=0 GOOS=$(call os,$@) GOARCH=$(call arch,$@) \
		go build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/concert-client-$(call os,$@)-$(call arch,$@) ./cmd/concert-client
	CGO_ENABLED=0 GOOS=$(call os,$@) GOARCH=$(call arch,$@) \
		go build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/concert-kv-$(call os,$@)-$(call arch,$@) ./cmd/concert-kv
	CGO_ENABLED=0 GOOS=$(call os,$@) GOARCH=$(call arch,$@) \
		go build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/concert-cache-$(call os,$@)-$(call arch,$@) ./cmd/concert-cache
	CGO_ENABLED=0 GOOS=$(call os,$@) GOARCH=$(call arch,$@) \
		go build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/concert-watchdog-$(call os,$@)-$(call arch,$@) ./cmd/concert-watchdog
