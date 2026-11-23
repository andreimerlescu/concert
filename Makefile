BINARY    := concert
BIN_DIR   := bin
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

GO_BUILD_FLAGS := -trimpath -buildvcs=false
GO_LDFLAGS     := -s -w

os   = $(word 1,$(subst /, ,$1))
arch = $(word 2,$(subst /, ,$1))
ext  = $(if $(filter windows,$(call os,$1)),.exe,)

.PHONY: all test test-race lint clean bench build build-fips sbom vulncheck checksums $(PLATFORMS)

all: lint clean test test-race bench summary build sbom checksums

test:
	go test -count=1 ./internal/... ./cmd/concert ./cmd/bench-concert
	go test -count=1 -tags wordpress ./internal/... ./cmd/wpconcert
	go test -count=1 -tags "wordpress,enterprise" ./...

test-race:
	go test -race -count=1 ./internal/... ./cmd/concert ./cmd/bench-concert
	go test -race -count=1 -tags wordpress ./internal/... ./cmd/wpconcert
	go test -race -count=1 -tags "wordpress,enterprise" ./...

bench:
	go test -bench=. -benchmem -tags "wordpress,enterprise" ./...

lint:
	go vet ./internal/... ./cmd/concert ./cmd/bench-concert
	go vet -tags wordpress ./internal/... ./cmd/wpconcert
	go vet -tags "wordpress,enterprise" ./...

vulncheck:
	govulncheck ./cmd/concert ./cmd/bench-concert
	govulncheck -tags wordpress ./cmd/wpconcert
	govulncheck -tags "wordpress,enterprise" ./...

sbom:
	@mkdir -p $(BIN_DIR)
	python3 scripts/generate-sbom.py --pkg ./cmd/concert --name concert -o $(BIN_DIR)/concert-sbom.cdx.json
	python3 scripts/generate-sbom.py --pkg ./cmd/wpconcert --tags wordpress --name wpconcert -o $(BIN_DIR)/wpconcert-sbom.cdx.json
	python3 scripts/generate-sbom.py --pkg ./cmd/econcert --tags "wordpress,enterprise" --name econcert -o $(BIN_DIR)/econcert-sbom.cdx.json

clean:
	go clean ./...
	rm -rf $(BIN_DIR)

summary:
	summarize -s useExpanded,internal/server/templates/lib,.git,.idea,summaries,lemmings -x useExpanded,png,jpg,LICENSE

build: $(PLATFORMS)

# FIPS 140-3 validated Go cryptographic module builds (Go 1.24+).
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
	@cd $(BIN_DIR) && shasum -a 256 concert-* wpconcert-* econcert-* bench-concert-* > SHA256SUMS.txt

$(PLATFORMS):
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=$(call os,$@) GOARCH=$(call arch,$@) \
		go build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/concert-$(call os,$@)-$(call arch,$@)$(call ext,$@) ./cmd/concert
	CGO_ENABLED=0 GOOS=$(call os,$@) GOARCH=$(call arch,$@) \
		go build -tags wordpress $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/wpconcert-$(call os,$@)-$(call arch,$@)$(call ext,$@) ./cmd/wpconcert
	CGO_ENABLED=0 GOOS=$(call os,$@) GOARCH=$(call arch,$@) \
		go build -tags "wordpress,enterprise" $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/econcert-$(call os,$@)-$(call arch,$@)$(call ext,$@) ./cmd/econcert
	CGO_ENABLED=0 GOOS=$(call os,$@) GOARCH=$(call arch,$@) \
		go build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/bench-concert-$(call os,$@)-$(call arch,$@)$(call ext,$@) ./cmd/bench-concert
