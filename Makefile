BINARY := tyto
PKG := github.com/dukotah/tyto
BIN_DIR := bin
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X $(PKG)/pkg/version.Version=$(VERSION)

.PHONY: all build run test eval lint fmt tidy clean install release snapshot

all: build

build: ## Build the tyto binary
	@mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) ./cmd/tyto

run: build ## Build and run
	./$(BIN_DIR)/$(BINARY)

test: ## Run tests
	go test ./...

eval: ## Run the hermetic planner/guard evaluation scorer (no GPU needed)
	go test ./internal/eval/ -run TestHermetic -v

lint: ## Run golangci-lint (must be installed)
	golangci-lint run ./...

fmt: ## Format code
	go fmt ./...

tidy: ## Tidy modules
	go mod tidy

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)

install: build ## Install to GOBIN
	go install -ldflags "$(LDFLAGS)" ./cmd/tyto

release: ## Build and publish a release (requires a git tag; uses GoReleaser)
	goreleaser release --clean

snapshot: ## Build release artifacts locally without publishing (GoReleaser)
	goreleaser release --snapshot --clean
