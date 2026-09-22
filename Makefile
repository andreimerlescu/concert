BINARY    := concert
BIN_DIR   := bin
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

GO_BUILD_FLAGS := -trimpath
GO_LDFLAGS     := -s -w

os   = $(word 1,$(subst /, ,$1))
arch = $(word 2,$(subst /, ,$1))
ext  = $(if $(filter windows,$(call os,$1)),.exe,)

.PHONY: all test test-race lint clean bench build $(PLATFORMS)

all: lint clean test test-race bench summary build

test:
	go test -count=1 -v ./...

test-race:
	go test -race -count=1 -v ./...

bench:
	go test -bench=. -benchmem ./...

lint:
	go vet ./...

clean:
	go clean ./...
	rm -rf $(BIN_DIR)

summary:
	summarize -s useExpanded,templates/lib,.git,.idea,summaries,lemmings -x useExpanded,jpg,LICENSE

build: $(PLATFORMS)

$(PLATFORMS):
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=$(call os,$@) GOARCH=$(call arch,$@) \
		go build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/$(BINARY)-$(call os,$@)-$(call arch,$@)$(call ext,$@) .
