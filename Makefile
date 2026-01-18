# Makefile for yrfy

# Version information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Build flags
LDFLAGS := -X github.com/andpalmier/yrfy/cmd.Version=$(VERSION) \
           -X github.com/andpalmier/yrfy/cmd.Commit=$(COMMIT) \
           -X github.com/andpalmier/yrfy/cmd.BuildDate=$(BUILD_DATE)

# Binary name
BINARY := yrfy

.PHONY: all
all: build

.PHONY: build
build:
	@echo "Building $(BINARY) $(VERSION)..."
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) main.go
	@echo "Build complete: ./$(BINARY)"

.PHONY: build-release
build-release:
	@echo "Building release binary $(BINARY) $(VERSION)..."
	go build -ldflags "-s -w $(LDFLAGS)" -o $(BINARY) main.go
	@echo "Release build complete: ./$(BINARY)"

.PHONY: install
install:
	@echo "Installing $(BINARY) $(VERSION)..."
	go install -ldflags "$(LDFLAGS)"
	@echo "Installed to $(shell go env GOPATH)/bin/$(BINARY)"

.PHONY: test
test:
	@echo "Running tests..."
	go test -v ./...

.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

.PHONY: lint
lint:
	@echo "Running linters..."
	go vet ./...
	go fmt ./...

.PHONY: clean
clean:
	@echo "Cleaning..."
	rm -f $(BINARY)
	rm -f coverage.out coverage.html
	@echo "Clean complete"

.PHONY: run
run: build
	./$(BINARY)

.PHONY: version
version:
	@echo "Version: $(VERSION)"
	@echo "Commit:  $(COMMIT)"
	@echo "Built:   $(BUILD_DATE)"

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  make build          - Build binary with version info"
	@echo "  make build-release  - Build optimized release binary"
	@echo "  make install        - Install to GOPATH/bin"
	@echo "  make test           - Run tests"
	@echo "  make test-coverage  - Run tests with coverage report"
	@echo "  make lint           - Run linters"
	@echo "  make clean          - Remove built binaries"
	@echo "  make run            - Build and run"
	@echo "  make version        - Show version information"
	@echo "  make help           - Show this help message"
