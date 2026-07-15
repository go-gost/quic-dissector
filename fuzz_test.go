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

// FuzzSniffQUIC parses a QUIC Initial datagram. This is invoked by the SNI
// sniffer on EVERY inbound QUIC connection BEFORE any policy check, so a
// panic is a DoS on the sniffing proxy path. Seeds are built with the
// library's own packet builder (valid Initial with SNI, minimal, non-Initial,
// empty, truncated) and the fuzzer mutates the raw datagram bytes —
// including the header protection removal and AEAD decryption paths.
func FuzzSniffQUIC(f *testing.F) {
	// Seed: valid QUIC Initial with SNI.
	if pkt := buildQUICInitialRaw(f, makeClientHelloWithSNI()); pkt != nil {
		f.Add(pkt)
	}
	// Seed: valid QUIC Initial with minimal ClientHello (no SNI).
	if pkt := buildQUICInitialRaw(f, makeMinimalClientHello()); pkt != nil {
		f.Add(pkt)
	// Seed: valid QUIC v2 Initial with SNI.
	if pkt := buildQUICInitialRawV2(f, makeClientHelloWithSNI()); pkt != nil {
		f.Add(pkt)
	}
	// Seed: valid QUIC v2 Initial with minimal ClientHello.
	if pkt := buildQUICInitialRawV2(f, makeMinimalClientHello()); pkt != nil {
		f.Add(pkt)
	}
	}
	// Seed: non-Initial long-header (Handshake type).
	f.Add([]byte{0xc2, 0x00, 0x00, 0x00, 0x01, 0x08})
	// Seed: short-header (1-RTT) packet.
	f.Add([]byte{0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07})
	// Seed: empty.
	f.Add([]byte{})
	// Seed: truncated long header.
	f.Add([]byte{0xc0})
	// Seed: missing fixed bit.
	f.Add([]byte{0x80, 0x00, 0x00, 0x00, 0x01, 0x08})
	// Seed: unknown version.
	f.Add([]byte{0xc0, 0x00, 0x00, 0x00, 0x02, 0x08})

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = SniffQUIC(b)
	})
}

// FuzzSniffInitial exercises the internal SniffInitial function directly,
// skipping only the TLS record wrapping. This covers the AEAD decryption
// and CRYPTO frame reassembly paths with arbitrary mutations.
func FuzzSniffInitial(f *testing.F) {
	if pkt := buildQUICInitialRaw(f, makeMinimalClientHello()); pkt != nil {
		f.Add(pkt)
	}
	if pkt := buildQUICInitialRawV2(f, makeMinimalClientHello()); pkt != nil {
		f.Add(pkt)
	}
	f.Add([]byte{})
	f.Add([]byte{0xc0})

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = quic.SniffInitial(b)
	})
}

// FuzzReadVarint exercises the QUIC variable-length integer decoder against
// random inputs. ReadVarint is called on every decrypted payload byte to
// parse frame types and lengths, so a panic or infinite loop is a DoS.
func FuzzReadVarint(f *testing.F) {
	f.Add([]byte{0x00})
	f.Add([]byte{0x40, 0x00})
	f.Add([]byte{0x80, 0x00, 0x00, 0x00})
	f.Add([]byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{})
	f.Add([]byte{0xc0})

	f.Fuzz(func(t *testing.T, b []byte) {
		v, n := quic.ReadVarint(b)
		if n > len(b) {
			t.Errorf("ReadVarint returned n=%d > len=%d", n, len(b))
		}
		if n > 0 && n <= 8 {
			bb := quic.AppendVarint(nil, v)
			v2, n2 := quic.ReadVarint(bb)
			if n2 != len(bb) {
				t.Errorf("round-trip n2=%d != len(bb)=%d", n2, len(bb))
			}
			if v2 != v {
				t.Errorf("round-trip value: %d != %d", v2, v)
			}
		}
	})
}

// ---- ClientHello builders ----

func makeClientHelloWithSNI() []byte {
	ch := &dissector.ClientHelloMsg{
		Version: 0x0303,
		Random:  dissector.Random{Time: 100},
		CipherSuites:       []uint16{0x1301, 0x1302, 0x1303},
		CompressionMethods: []uint8{0x00},
		Extensions: []dissector.Extension{
			&dissector.ServerNameExtension{NameType: 0, Name: "example.com"},
			&dissector.SupportedVersionsExtension{Versions: []uint16{0x0304, 0x0303}},
			&dissector.ALPNExtension{Protos: []string{"h2", "http/1.1"}},
		},
	}
	body, _ := ch.Encode()
	return body
}

func makeMinimalClientHello() []byte {
	ch := &dissector.ClientHelloMsg{
		Version: 0x0303,
		Random:  dissector.Random{Time: 0},
	}
	body, _ := ch.Encode()
	return body
}

// ---- QUIC v1 Initial packet builder (fuzz-safe) ----

func buildQUICInitialRaw(f *testing.F, chBytes []byte) []byte {
	_ = f
	var payload []byte
	payload = quic.AppendVarint(payload, 0x06)
	payload = quic.AppendVarint(payload, 0)
	payload = quic.AppendVarint(payload, uint64(len(chBytes)))
	payload = append(payload, chBytes...)

	dcid := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, dcid); err != nil {
		return nil
	}
	scid := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, scid); err != nil {
		return nil
	}

	initialSalt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	initialSecret := hkdf.Extract(sha256.New, dcid, initialSalt)
	clientSecret := hkdfExpandRaw(initialSecret, "client in", nil, 32)
	key := hkdfExpandRaw(clientSecret, "quic key", nil, 16)
	iv := hkdfExpandRaw(clientSecret, "quic iv", nil, 12)
	hpKey := hkdfExpandRaw(clientSecret, "quic hp", nil, 16)
	if key == nil || iv == nil || hpKey == nil {
		return nil
	}

	flags := byte(0xc0)
	var hdr []byte
	hdr = append(hdr, flags)
	hdr = binary.BigEndian.AppendUint32(hdr, 0x00000001)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = quic.AppendVarint(hdr, 0)

	pn := byte(0)

	nonce := make([]byte, 12)
	copy(nonce, iv)
	nonce[11] ^= pn

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}

	aadLenOffset := len(hdr)
	hdr = quic.AppendVarint(hdr, uint64(1+len(payload)+gcm.Overhead()))
	pnOffset := len(hdr)
	hdr = append(hdr, pn)
	ct := gcm.Seal(nil, nonce, payload, hdr)

	packet := make([]byte, 0, aadLenOffset+len(hdr)-aadLenOffset+1+len(ct))
	packet = append(packet, hdr[:pnOffset]...)
	packet = append(packet, hdr[pnOffset])
	packet = append(packet, ct...)

	sampleStart := pnOffset + 4
	for len(packet) < sampleStart+16 {
		packet = append(packet, 0)
	}
	mask := aesECBEncryptRaw(hpKey, packet[sampleStart:sampleStart+16])
	if mask == nil {
		return nil
	}
	packet[0] ^= (mask[0] & 0x0f)
	packet[pnOffset] ^= mask[1]

	return packet
}

// buildQUICInitialRawV2 is like buildQUICInitialRaw but for QUIC v2 (RFC 9369).
func buildQUICInitialRawV2(f *testing.F, chBytes []byte) []byte {
	_ = f
	var payload []byte
	payload = quic.AppendVarint(payload, 0x06)
	payload = quic.AppendVarint(payload, 0)
	payload = quic.AppendVarint(payload, uint64(len(chBytes)))
	payload = append(payload, chBytes...)

	dcid := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, dcid); err != nil {
		return nil
	}
	scid := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, scid); err != nil {
		return nil
	}

	initialSalt := []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
	initialSecret := hkdf.Extract(sha256.New, dcid, initialSalt)
	clientSecret := hkdfExpandRaw(initialSecret, "client in", nil, 32)
	key := hkdfExpandRaw(clientSecret, "quic key", nil, 16)
	iv := hkdfExpandRaw(clientSecret, "quic iv", nil, 12)
	hpKey := hkdfExpandRaw(clientSecret, "quic hp2", nil, 16)
	if key == nil || iv == nil || hpKey == nil {
		return nil
	}

	flags := byte(0xc0)
	var hdr []byte
	hdr = append(hdr, flags)
	hdr = binary.BigEndian.AppendUint32(hdr, 0x6b3343cf)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = quic.AppendVarint(hdr, 0)

	pn := byte(0)

	nonce := make([]byte, 12)
	copy(nonce, iv)
	nonce[11] ^= pn

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}

	aadLenOffset := len(hdr)
	hdr = quic.AppendVarint(hdr, uint64(1+len(payload)+gcm.Overhead()))
	pnOffset := len(hdr)
	hdr = append(hdr, pn)
	ct := gcm.Seal(nil, nonce, payload, hdr)

	packet := make([]byte, 0, aadLenOffset+len(hdr)-aadLenOffset+1+len(ct))
	packet = append(packet, hdr[:pnOffset]...)
	packet = append(packet, hdr[pnOffset])
	packet = append(packet, ct...)

	sampleStart := pnOffset + 4
	for len(packet) < sampleStart+16 {
		packet = append(packet, 0)
	}
	mask := aesECBEncryptRaw(hpKey, packet[sampleStart:sampleStart+16])
	if mask == nil {
		return nil
	}
	packet[0] ^= (mask[0] & 0x0f)
	packet[pnOffset] ^= mask[1]

	return packet
}

func aesECBEncryptRaw(key, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	out := make([]byte, 16)
	block.Encrypt(out, plaintext)
	return out
}

func hkdfExpandRaw(secret []byte, label string, context []byte, length int) []byte {
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
		return nil
	}
	return out
}
