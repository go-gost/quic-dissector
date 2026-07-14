// Package quicdissector decrypts QUIC Initial datagrams to extract
// the TLS ClientHello Server Name Indication (SNI) for transparent
// proxy bypass decisions and traffic recording.
//
// Multiple datagrams from the same connection are supported: CRYPTO frames
// from all are reassembled (gaps are zero-filled). Non-decryptable datagrams
// (wrong keys, corrupted) are silently skipped.
// Only QUIC v1 and draft-29 versions are supported.
package quicdissector

import (
	"bytes"
	"encoding/binary"

	"github.com/go-gost/quic-dissector/internal/quic"
	"github.com/go-gost/tls-dissector"
)

// ErrNotQUIC is returned when the datagram is not a parsable QUIC Initial packet.
var ErrNotQUIC = quic.ErrNotQUIC

// SniffQUIC decrypts QUIC Initial datagrams and parses the embedded TLS
// ClientHello. Returns the ClientHello info (ServerName=SNI, SupportedProtos=ALPN),
// or quic.ErrNotQUIC when the datagrams cannot be parsed.
//
// Multiple datagrams from the same connection are accepted: CRYPTO frames
// from all are reassembled (gaps are zero-filled). Non-decryptable datagrams
// are silently skipped. Single-datagram callers pass one argument with
// identical behavior to the original API.
func SniffQUIC(dgrams ...[]byte) (*dissector.ClientHelloInfo, error) {
	rawCH, err := quic.SniffInitialMulti(dgrams...)
	if err != nil {
		return nil, err
	}

	// Prepend a synthetic TLS record header: ContentType Handshake (0x16),
	// Version TLS 1.2 (0x0303), 2-byte length.
	record := make([]byte, 0, 5+len(rawCH))
	record = append(record, 0x16, 0x03, 0x03)
	record = binary.BigEndian.AppendUint16(record, uint16(len(rawCH)))
	record = append(record, rawCH...)

	return dissector.ParseClientHello(bytes.NewReader(record))
}
