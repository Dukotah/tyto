BINARY := tyto
PKG := github.com/dukotah/tyto
BIN_DIR := bin
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X $(PKG)/pkg/version.Version=$(VERSION)

.PHONY: all build run test lint fmt tidy clean install

all: build

build: ## Build the tyto binary
	@mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) ./cmd/tyto

run: build ## Build and run
	./$(BIN_DIR)/$(BINARY)

test: ## Run tests
	go test ./...

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
