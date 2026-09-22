BINARY  := agentvault
PKG     := github.com/aashish/agentvault
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test race bench redteam compare corpus lint vet clean install

build:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/$(BINARY) ./cmd/agentvault

test:
	go test ./...

race:
	go test -race ./...

bench:
	go test -bench=. -benchmem ./internal/policy/

redteam:
	REDTEAM_REPORT="$(CURDIR)/docs/redteam/RESULTS.md" go test -count=1 -v ./test/redteam/

# Cross-tool matrix: same attacks under srt/docker/firejail when present.
compare:
	COMPARE_REPORT="$(CURDIR)/docs/redteam/COMPARE_RESULTS.md" go test -count=1 -v -run TestCompareMatrix ./test/redteam/

# 100+ attack corpus across all sandbox tools; regenerates the public report.
corpus:
	CORPUS_REPORT="$(CURDIR)/docs/redteam/CORPUS_RESULTS.md" CORPUS_JSON="$(CURDIR)/docs/redteam/CORPUS_RESULTS.json" go test -count=1 -v -run TestAttackCorpus ./test/redteam/
	python3 scripts/corpus_chart.py

vet:
	go vet ./...

lint:
	golangci-lint run ./...

install: build
	install -m 0755 bin/$(BINARY) $(HOME)/.local/bin/$(BINARY)

clean:
	rm -rf bin/
