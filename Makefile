BINARY    := concert
BIN_DIR   := bin
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

GO_BUILD_FLAGS := -trimpath -buildvcs=false
GO_LDFLAGS     := -s -w

os   = $(word 1,$(subst /, ,$1))
arch = $(word 2,$(subst /, ,$1))
ext  = $(if $(filter windows,$(call os,$1)),.exe,)

.PHONY: all test test-race lint clean bench build build-fips sbom vulncheck checksums $(PLATFORMS)

all: lint clean test test-race bench summary build checksums

test:
	go test -count=1 -v ./...

test-race:
	go test -race -count=1 -v ./...

bench:
	go test -bench=. -benchmem ./...

lint:
	go vet ./...

vulncheck:
	govulncheck ./...

sbom:
	@mkdir -p $(BIN_DIR)
	python3 scripts/generate-sbom.py -o $(BIN_DIR)/$(BINARY)-sbom.cdx.json

clean:
	go clean ./...
	rm -rf $(BIN_DIR)

summary:
	summarize -s useExpanded,templates/lib,.git,.idea,summaries,lemmings -x useExpanded,png,jpg,LICENSE

build: $(PLATFORMS)

# FIPS 140-3 validated Go cryptographic module build (Go 1.24+).
build-fips:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOFIPS140=v1.0.0 GOOS=linux GOARCH=amd64 \
		go build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/$(BINARY)-fips-linux-amd64 .
	CGO_ENABLED=0 GOFIPS140=v1.0.0 GOOS=linux GOARCH=arm64 \
		go build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/$(BINARY)-fips-linux-arm64 .

checksums:
	@cd $(BIN_DIR) && shasum -a 256 $(BINARY)-* > SHA256SUMS.txt

$(PLATFORMS):
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=$(call os,$@) GOARCH=$(call arch,$@) \
		go build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/$(BINARY)-$(call os,$@)-$(call arch,$@)$(call ext,$@) .
