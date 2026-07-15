package quicdissector

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"testing"

	"github.com/go-gost/quic-dissector/internal/quic"
	"github.com/go-gost/tls-dissector"
	"golang.org/x/crypto/hkdf"
)

// ---- programmatic QUIC Initial packet builder ----

// buildQUICInitial builds a valid QUIC Initial packet containing the
// given ClientHello handshake bytes (including the 4-byte handshake header).
// version selects the QUIC wire version (e.g. 0x00000001 for v1, 0x6b3343cf for v2).
func buildQUICInitial(t *testing.T, chBytes []byte, version uint32) []byte {
	t.Helper()

	// Build CRYPTO frame payload: type(0x06) + offset(0) + length + data.
	var payload []byte
	payload = quic.AppendVarint(payload, 0x06)           // CRYPTO frame type
	payload = quic.AppendVarint(payload, 0)              // offset = 0
	payload = quic.AppendVarint(payload, uint64(len(chBytes)))
	payload = append(payload, chBytes...)

	// Choose a DCID (8 bytes is typical).
	dcid := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, dcid); err != nil {
		t.Fatal(err)
	}
	scid := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, scid); err != nil {
		t.Fatal(err)
	}

	// Derive keys from DCID, selecting salt and HP label by version.
	var initialSalt []byte
	hpLabel := "quic hp"
	switch version {
	case 0x6b3343cf: // QUIC v2 (RFC 9369)
		initialSalt = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
		hpLabel = "quic hp2"
	default: // QUIC v1, draft-29
		initialSalt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	}
		initialSecret := hkdf.Extract(sha256.New, dcid, initialSalt)
		clientSecret := hkdfExpandLabel(t, initialSecret, "client in", nil, 32)
		key := hkdfExpandLabel(t, clientSecret, "quic key", nil, 16)
		iv := hkdfExpandLabel(t, clientSecret, "quic iv", nil, 12)
		hpKey := hkdfExpandLabel(t, clientSecret, hpLabel, nil, 16)

	// Build unprotected header.
	// Flags: Long Header(0x80) | Fixed Bit(0x40) | Initial(0x00) | PN Len(0x00 → 1 byte)
	flags := byte(0xc0) // will be XOR'd with header protection mask

	var hdr []byte
	hdr = append(hdr, flags)             // 1 byte flags (protected)
	hdr = binary.BigEndian.AppendUint32(hdr, version)
	hdr = append(hdr, byte(len(dcid)))   // DCID length
	hdr = append(hdr, dcid...)           // DCID
	hdr = append(hdr, byte(len(scid)))   // SCID length
	hdr = append(hdr, scid...)           // SCID
	// Token: zero-length
	hdr = quic.AppendVarint(hdr, 0) // token length = 0

	// Packet number (1 byte = 0).
	packetNumber := byte(0)

	// Payload: CRYPTO frame encrypted.
	// AEAD encrypt.
	nonce := make([]byte, 12)
	copy(nonce, iv)
	nonce[11] ^= packetNumber

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	// AAD = header (will be finalized after PN added).
	totalPNLen := 1 // 1-byte PN
	aadLenOffset := len(hdr)

	// Append payload length (varint)
	hdr = quic.AppendVarint(hdr, uint64(totalPNLen+len(payload)+gcm.Overhead()))

	// PN offset is after the payload length field.
	pnOffset := len(hdr)

	// Write PN byte.
	hdr = append(hdr, packetNumber) // temporary, will apply header protection

	// Encrypt.
	ct := gcm.Seal(nil, nonce, payload, hdr)

	// Full packet up to PN (header before PN) + ciphertext.
	packet := make([]byte, 0, aadLenOffset+len(hdr)-aadLenOffset+1+len(ct))
	packet = append(packet, hdr[:pnOffset]...)
	// PN byte (unprotected so far)
	packet = append(packet, hdr[pnOffset])
	// Ciphertext
	packet = append(packet, ct...)

	// Apply header protection.
	sampleStart := pnOffset + 4
	// We may need to pad if the packet is too short for the 16-byte sample.
	for len(packet) < sampleStart+16 {
		packet = append(packet, 0)
	}
	sample := packet[sampleStart : sampleStart+16]

	mask, err := aesECBEncrypt(hpKey, sample)
	if err != nil {
		t.Fatal(err)
	}

	// XOR flags byte with mask.
	packet[0] ^= (mask[0] & 0x0f)
	// XOR PN byte.
	packet[pnOffset] ^= mask[1]
	// Recover the flags byte with PN length in bits 1:0.
	// flags byte after mask: first nibble is 0xc0 | (0 & 0x0f), so bits 1:0 = 0 → 1-byte PN.
	// The mask might change this.

	return packet
}

func aesECBEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, aes.BlockSize)
	block.Encrypt(out, plaintext)
	return out, nil
}

func hkdfExpandLabel(t *testing.T, secret []byte, label string, context []byte, length int) []byte {
	t.Helper()
	fullLabel := "tls13 " + label
	info := make([]byte, 0, 2+1+len(fullLabel)+1+len(context))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, byte(len(context)))
	info = append(info, context...)

	r := hkdf.Expand(sha256.New, secret, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		t.Fatal(err)
	}
	return out
}

// ---- Tests ----

func TestSniffQUIC(t *testing.T) {
	ch := &dissector.ClientHelloMsg{
		Version:            0x0303,
		Random:             dissector.Random{Time: 1234567890},
		SessionID:          []byte{0x01, 0x02, 0x03},
		CipherSuites:       []uint16{0xC02B, 0xC02F, 0xCCA8},
		CompressionMethods: []uint8{0x00},
		Extensions: []dissector.Extension{
			&dissector.ServerNameExtension{NameType: 0, Name: "example.com"},
			&dissector.SupportedVersionsExtension{Versions: []uint16{0x0304, 0x0303}},
			&dissector.ALPNExtension{Protos: []string{"h2", "http/1.1"}},
		},
	}

	chBytes, err := ch.Encode()
	if err != nil {
		t.Fatal(err)
	}

	dgram := buildQUICInitial(t, chBytes, 0x00000001)
	info, err := SniffQUIC(dgram)
	if err != nil {
		t.Fatalf("SniffQUIC error: %v", err)
	}

	if info.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want %q", info.ServerName, "example.com")
	}
	if len(info.SupportedProtos) < 1 || info.SupportedProtos[0] != "h2" {
		t.Errorf("SupportedProtos = %v, want [h2 ...]", info.SupportedProtos)
	}
}

func TestSniffQUIC_ShortHeader(t *testing.T) {
	// 1-RTT (short header) packet.
	dgram := []byte{0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	_, err := SniffQUIC(dgram)
	if err == nil {
		t.Fatal("expected error for short header")
	}
}

func TestSniffQUIC_NonInitial(t *testing.T) {
	// Handshake packet (type 0x02).
	dgram := []byte{0xc2, 0x00, 0x00, 0x00, 0x01, 0x08}
	_, err := SniffQUIC(dgram)
	if err == nil {
		t.Fatal("expected error for non-Initial")
	}
}

func TestSniffQUIC_Empty(t *testing.T) {
	_, err := SniffQUIC(nil)
	if err == nil {
		t.Fatal("expected error for nil datagram")
	}
}

func TestSniffQUIC_UnknownVersion(t *testing.T) {
	// Version 0x00000002 (unknown).
	dgram := []byte{0xc0, 0x00, 0x00, 0x00, 0x02, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	_, err := SniffQUIC(dgram)
	if err == nil {
		t.Fatal("expected error for unknown version")
	}
}

func TestSniffQUIC_NoFixedBit(t *testing.T) {
	dgram := []byte{0x80, 0x00, 0x00, 0x00, 0x01, 0x08}
	_, err := SniffQUIC(dgram)
	if err == nil {
		t.Fatal("expected error for missing fixed bit")
	}
}

func TestSniffQUIC_Truncated(t *testing.T) {
	ch := &dissector.ClientHelloMsg{
		Version: 0x0303,
		Random:  dissector.Random{Time: 0},
	}
	chBytes, _ := ch.Encode()
	full := buildQUICInitial(t, chBytes, 0x00000001)

	// Try truncating to various prefixes.
	for _, trunc := range []int{5, 10, 20, 30, 40} {
		if trunc < len(full) {
			_, err := SniffQUIC(full[:trunc])
			if err == nil {
				t.Errorf("expected error for truncated datagram (len=%d)", trunc)
			}
		}
	}
}

func TestSniffQUIC_ClientHelloMissingSNI(t *testing.T) {
	ch := &dissector.ClientHelloMsg{
		Version:            0x0303,
		Random:             dissector.Random{Time: 0},
		CipherSuites:       []uint16{0xC02B},
		CompressionMethods: []uint8{0x00},
	}
	chBytes, err := ch.Encode()
	if err != nil {
		t.Fatal(err)
	}
	dgram := buildQUICInitial(t, chBytes, 0x00000001)
	info, err := SniffQUIC(dgram)
	if err != nil {
		t.Fatalf("SniffQUIC error: %v", err)
	}
	if info.ServerName != "" {
		t.Errorf("ServerName = %q, want empty", info.ServerName)
	}
}

func TestSniffQUIC_V2(t *testing.T) {
	ch := &dissector.ClientHelloMsg{
		Version:            0x0303,
		Random:             dissector.Random{Time: 1234567890},
		SessionID:          []byte{0x01, 0x02, 0x03},
		CipherSuites:       []uint16{0xC02B, 0xC02F, 0xCCA8},
		CompressionMethods: []uint8{0x00},
		Extensions: []dissector.Extension{
			&dissector.ServerNameExtension{NameType: 0, Name: "v2.example.com"},
			&dissector.SupportedVersionsExtension{Versions: []uint16{0x0304, 0x0303}},
			&dissector.ALPNExtension{Protos: []string{"h3", "http/1.1"}},
		},
	}

	chBytes, err := ch.Encode()
	if err != nil {
		t.Fatal(err)
	}

	dgram := buildQUICInitial(t, chBytes, 0x6b3343cf)
	info, err := SniffQUIC(dgram)
	if err != nil {
		t.Fatalf("SniffQUIC v2 error: %v", err)
	}

	if info.ServerName != "v2.example.com" {
		t.Errorf("ServerName = %q, want %q", info.ServerName, "v2.example.com")
	}
	if len(info.SupportedProtos) < 1 || info.SupportedProtos[0] != "h3" {
		t.Errorf("SupportedProtos = %v, want [h3 ...]", info.SupportedProtos)
	}
}

