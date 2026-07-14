# quic-dissector

Decrypt QUIC v1 Initial datagrams and extract the TLS ClientHello (SNI, ALPN) — no `quic-go` dependency.

Used by [go-gost](https://github.com/go-gost/gost) for transparent proxy SNI-based bypass decisions.

## Usage

```go
import "github.com/go-gost/quic-dissector"

info, err := quicdissector.SniffQUIC(datagram)
// info.ServerName, info.SupportedProtos
```

Multiple datagrams from the same connection (quic-go splits ClientHello across Initial packets):

```go
info, err := quicdissector.SniffQUIC(pkt0, pkt1)
```

## How it works

1. Parse QUIC long header → extract Destination Connection ID
2. Derive AES-128 keys via HKDF (RFC 9001 §5.2)
3. Remove header protection, AEAD-decrypt the payload
4. Merge CRYPTO frames across datagrams (by offset)
5. Parse the assembled TLS ClientHello via [tls-dissector](https://github.com/go-gost/tls-dissector)

## Status

QUIC v1 (RFC 9000) and draft-29. No QUIC v2 support yet. Fuzz-tested.

## License

MIT
