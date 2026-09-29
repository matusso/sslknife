# SSLKnife developer tasks.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PKG     := github.com/matusso/sslknife/internal/buildinfo
LDFLAGS := -s -w -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).Date=$(DATE)
FUZZTIME ?= 30s

.PHONY: build install test test-race vet lint vuln fuzz docs ui-check cross clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o sslknife .

install:
	CGO_ENABLED=0 go install -trimpath -ldflags '$(LDFLAGS)' .

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...
	test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

lint:
	golangci-lint run

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Short fuzzing pass over every parser that reads untrusted input.
fuzz:
	go test ./internal/certificate -run '^$$' -fuzz '^FuzzParse$$' -fuzztime $(FUZZTIME)
	go test ./internal/certificate -run '^$$' -fuzz '^FuzzSCTList$$' -fuzztime $(FUZZTIME)
	go test ./internal/certificate -run '^$$' -fuzz '^FuzzParseCSR$$' -fuzztime $(FUZZTIME)
	go test ./internal/keys -run '^$$' -fuzz '^FuzzParseKeys$$' -fuzztime $(FUZZTIME)
	go test ./internal/converter -run '^$$' -fuzz '^FuzzDecode$$' -fuzztime $(FUZZTIME)
	go test ./internal/scanner -run '^$$' -fuzz '^FuzzServerHello$$' -fuzztime $(FUZZTIME)
	go test ./internal/search -run '^$$' -fuzz '^FuzzCompile$$' -fuzztime $(FUZZTIME)

# Regenerate the Markdown command reference from the CLI definitions.
docs: build
	rm -rf docs/commands
	./sslknife docs --dir docs/commands

# Syntax check plus a DOM smoke test of the web UI (needs Node and a running
# server; see web/test/smoke.mjs).
ui-check:
	node --check web/static/app.js

cross:
	for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
		os=$${target%/*}; arch=$${target#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' -o dist/sslknife-$$os-$$arch$$ext . || exit 1; \
	done

clean:
	rm -rf sslknife dist
