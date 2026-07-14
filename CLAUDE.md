# CLAUDE.md

## Build & Test

```bash
cd quic-dissector

# Build
go build ./...

# Vet
go vet ./...

# Test
go test -v -cover ./...

# Fuzz (run all targets for 30s each)
for fn in $(grep -rhoE 'func (Fuzz[[:alnum:]_]+)' --include='*_test.go' . | sed 's/func //'); do
    go test -fuzz="^${fn}$" -fuzztime=30s .
done
```

Module: `github.com/go-gost/quic-dissector` — Go 1.25. Deps: `golang.org/x/crypto` (hkdf) and `github.com/go-gost/tls-dissector` (ClientHello parser).

## CI

GitHub Actions at `.github/workflows/ci.yml` — validates standalone module build with `GOWORK=off` (resolves the local tls-dissector dependency via `go mod edit -replace`), runs vet, test, and 30s fuzz per target. Same pattern as the tls-dissector CI.

## Architecture

| Layer | File | Responsibility |
|-------|------|----------------|
| Varint | `internal/quic/varint.go` | QUIC variable-length integer encode/decode (RFC 9000 §16) |
| HKDF | `internal/quic/hkdf.go` | HKDF-Expand-Label per RFC 8446 §7.1 |
| Initial | `internal/quic/initial.go` | QUIC Initial header parse, key derivation, AEAD decrypt, CRYPTO reassembly |
| Public API | `dissector.go` | `SniffQUIC(datagram []byte) → ClientHelloInfo` |

**Data flow**: raw UDP datagrams → `SniffInitialMulti` → key derivation (DCID → HKDF → AES keys) → per-packet header protection removal (AES-ECB) → AEAD decrypt (AES-128-GCM) → CRYPTO frame accumulation (cross-packet, by offset) → synthetic TLS record → `dissector.ParseClientHello` → `ClientHelloInfo`.

Variadic `SniffQUIC(dgrams ...[]byte)` accepts one or more Initial datagrams from the same connection. Keys are derived from the first datagram's DCID; subsequent datagrams that fail AEAD (e.g., Retry-keyed packets) are silently skipped. The old single-datagram signature `SniffQUIC(datagram []byte)` remains backward-compatible.

## Key patterns

- Reuses `github.com/go-gost/tls-dissector` for TLS ClientHello parsing — the same parser used by GOST's TCP TLS sniffer.
- Cross-datagram CRYPTO reassembly via `SniffInitialMulti` / `SniffQUIC(dgrams ...[])` collects fragments from multiple Initial packets (by offset), merging them into a contiguous buffer. Non-decryptable datagrams are silently skipped.
- Sentinel errors: `ErrNotQUIC` (not a QUIC packet / failed to parse), `ErrNotInitial` (QUIC but not an Initial packet).
- QUIC v1 + draft-29 supported. QUIC v2 (RFC 9369) is a documented follow-up.
- No `quic-go` dependency: varint and HKDF-Expand-Label are self-contained implementations.
