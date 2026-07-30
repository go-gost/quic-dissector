# quic-dissector

Decrypt QUIC v1/v2 Initial datagrams and extract the TLS ClientHello (SNI, ALPN) and ServerHello (cipher suite, version) — no `quic-go` dependency.

Used by [go-gost](https://github.com/go-gost/gost) for transparent proxy SNI-based bypass decisions.

## Usage

```go
import "github.com/go-gost/quic-dissector"

// ClientHello sniffing (SNI, ALPN)
info, err := quicdissector.SniffQUIC(datagram)
// info.ServerName, info.SupportedProtos

// ServerHello sniffing (cipher suite, version, ALPN)
serverInfo, err := quicdissector.SniffQUICServerHello(clientDgram, serverDgram)
// serverInfo.CipherSuite, serverInfo.Version, serverInfo.Proto
```

Multiple datagrams from the same connection (quic-go splits ClientHello across Initial packets):

```go
info, err := quicdissector.SniffQUIC(pkt0, pkt1)
```

## How it works

**ClientHello**:
1. Parse QUIC long header → extract Destination Connection ID
2. Derive AES-128 keys via HKDF (RFC 9001 §5.2)
3. Remove header protection, AEAD-decrypt the payload
4. Merge CRYPTO frames across datagrams (by offset)
5. Parse the assembled TLS ClientHello via [tls-dissector](https://github.com/go-gost/tls-dissector)

**ServerHello**:
1. Parse client Initial → extract DCID and QUIC version
2. Derive server Initial keys via HKDF with `"server in"` label
3. Decrypt server Initial datagrams, merge CRYPTO frames
4. Parse ServerHello → CipherSuite, TLS version, ALPN

## Status

QUIC v1 (RFC 9000), v2 (RFC 9369), and draft-29. Fuzz-tested.

## License

MIT
