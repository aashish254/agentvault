BINARY  := agentvault
PKG     := github.com/aashish/agentvault
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test race bench lint vet clean install

build:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/$(BINARY) ./cmd/agentvault

test:
	go test ./...

race:
	go test -race ./...

bench:
	go test -bench=. -benchmem ./internal/policy/

vet:
	go vet ./...

lint:
	golangci-lint run ./...

install: build
	install -m 0755 bin/$(BINARY) $(HOME)/.local/bin/$(BINARY)

clean:
	rm -rf bin/
