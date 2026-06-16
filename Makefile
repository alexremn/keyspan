BINARY := keyspan
PKG := ./cmd/keyspan
BIN_DIR := bin
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
ARGS ?=

.PHONY: build test lint cover run tidy

build:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) $(PKG)

test:
	go test -race ./...

lint:
	golangci-lint run

cover:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out | tail -n 1

run: build
	$(BIN_DIR)/$(BINARY) $(ARGS)

tidy:
	go mod tidy
