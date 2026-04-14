# Contributing to dynip-dns

## Prerequisites

- Go 1.24+
- `dig` (for manual smoke-testing)

## Setup

```bash
git clone https://github.com/Vr00mm/dynip-dns.git
cd dynip-dns
go mod download
```

## Build

```bash
go build ./cmd/dynip-dns
```

## Test

```bash
# Unit tests
go test ./...

# With race detector (required before opening a PR)
go test -race ./...

# Integration tests (bind real UDP/TCP ports)
go test -tags=integration ./internal/pkg/server/

# Coverage report
go test -coverprofile=cover.out ./...
go tool cover -html=cover.out
```

All packages must maintain **100% statement coverage**. Add tests for every new code path.

## Code style

- `gofmt -s -w .` before committing
- Follow the existing patterns: injectable `exit`, injectable `listen`/`listenPacket` for testability
- No new dependencies — keep `go.mod` dependency-free

## Pull requests

1. Fork the repository and create a feature branch
2. Keep changes focused — one concern per PR
3. Run `go test -race ./...` and fix any failures
4. Open a PR against `main` with a short description of *why* the change is needed

## Project layout

```
cmd/dynip-dns/       entry point — wires config + server, no logic
internal/pkg/config/ env/file config loading
internal/pkg/dns/    DNS wire-format parser and response builder
internal/pkg/server/ UDP/TCP listeners, rate limiter
```
