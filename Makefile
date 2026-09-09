.PHONY: build test test-slow race lint fuzz cover bench oracle cross tidy

# Build everything in the root module (library + cmd/sphincsminus).
build:
	go build ./...

# Fast checks: vet + the default test suite (no race, no SLOW gate).
test:
	go vet ./...
	go test ./...

# Full C7/C13 signing roundtrips, gated behind SPHINCSMINUS_SLOW=1 (~20s).
test-slow:
	SPHINCSMINUS_SLOW=1 go test ./...

# Same as `test` but with the race detector (~1 min).
race:
	go vet ./...
	go test -race -count=1 ./...

# gofmt + staticcheck + govulncheck.
lint:
	test -z "$$(gofmt -l .)"
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# FuzzVerify for 30s. Override with: make fuzz FUZZTIME=5m
FUZZTIME ?= 30s
fuzz:
	go test -run xxx -fuzz FuzzVerify -fuzztime $(FUZZTIME) .

# Coverage profile, plus a human-readable summary.
cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

bench:
	go test -bench . -benchmem ./...

# The evmoracle nested module: runs the real Solidity verifier bytecode
# in go-ethereum's EVM. Needs network on first run (go-ethereum deps).
oracle:
	cd evmoracle && go test ./...

# Cross-compile the six platforms CI checks: linux/{amd64,arm64,386},
# windows/amd64, darwin/arm64, js/wasm.
cross:
	GOOS=linux   GOARCH=amd64 go build ./...
	GOOS=linux   GOARCH=arm64 go build ./...
	GOOS=linux   GOARCH=386   go build ./...
	GOOS=windows GOARCH=amd64 go build ./...
	GOOS=darwin  GOARCH=arm64 go build ./...
	GOOS=js      GOARCH=wasm  go build ./...

# go mod tidy for both modules.
tidy:
	go mod tidy
	cd evmoracle && go mod tidy
