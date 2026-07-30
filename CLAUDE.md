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
| Internal | `internal/quic/initial.go` | `ParseInitialHeader`, `deriveInitialKeys`, `deriveServerInitialKeys`, `decryptDgram`, `collectCRYPTO`, `buildCRYPTO`, `SniffInitialMulti`, `SniffServerInitialMulti` |
| Public API | `dissector.go` | `SniffQUIC(dgrams ...[]byte) → ClientHelloInfo`, `SniffQUICServerHello(clientDgram, serverDgrams ...[]byte) → ServerHelloInfo` |

**Data flow (ClientHello)**: raw UDP datagrams → `SniffInitialMulti` → key derivation (DCID → HKDF → AES keys) → per-packet header protection removal (AES-ECB) → AEAD decrypt (AES-128-GCM) → CRYPTO frame accumulation (cross-packet, by offset) → synthetic TLS record → `dissector.ParseClientHello` → `ClientHelloInfo`.

**Data flow (ServerHello)**: client Initial → `ParseInitialHeader` (DCID + version) → `deriveServerInitialKeys` (uses `"server in"` label) → `SniffServerInitialMulti` → AEAD decrypt server datagrams → `dissector.ParseServerHello` → `ServerHelloInfo` (CipherSuite, Version, Proto).

Variadic `SniffQUIC(dgrams ...[]byte)` accepts one or more Initial datagrams from the same connection. Keys are derived from the first datagram's DCID; subsequent datagrams that fail AEAD (e.g., Retry-keyed packets) are silently skipped.

## Key patterns

- Reuses `github.com/go-gost/tls-dissector` for TLS ClientHello and ServerHello parsing — the same parser used by GOST's TCP TLS sniffer.
- Cross-datagram CRYPTO reassembly via `SniffInitialMulti` / `SniffQUIC(dgrams ...[])` collects fragments from multiple Initial packets (by offset), merging them into a contiguous buffer. Non-decryptable datagrams are silently skipped.
- Sentinel errors: `ErrNotQUIC` (not a QUIC packet / failed to parse, re-exported from `quic.ErrNotQUIC`), `ErrNotInitial` (QUIC but not an Initial packet, internal only).
- QUIC v1 (RFC 9000), v2 (RFC 9369), and draft-29 supported. Version-dependent salt (`quicSaltV1` / `quicSaltV2`) and HP label (`"quic hp"` / `"quic hp2"`) branching in `deriveInitialKeys` / `deriveServerInitialKeys`.
- No `quic-go` dependency: varint and HKDF-Expand-Label are self-contained implementations.
- `real_traffic_test.go` — tests against real captured packets (cloudflare-quic.com:443), plus synthetic v2 packets.
