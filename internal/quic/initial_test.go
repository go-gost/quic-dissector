package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

func TestVarintRoundTrip(t *testing.T) {
	for _, v := range []uint64{0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, 1 << 60} {
		b := AppendVarint(nil, v)
		got, n := ReadVarint(b)
		if n != len(b) {
			t.Errorf("ReadVarint length for %d: got %d, want %d", v, n, len(b))
		}
		if got != v {
			t.Errorf("ReadVarint value: got %d, want %d", got, v)
		}
	}
}

func TestVarintTruncated(t *testing.T) {
	for _, b := range [][]byte{nil, {0x80}, {0xc0, 0x01}} {
		v, n := ReadVarint(b)
		if n != 0 || v != 0 {
			t.Errorf("expected truncated for %v, got %d,%d", b, v, n)
		}
	}
}

func TestSniffInitial(t *testing.T) {
	// Build a minimal QUIC Initial, encrypt it, then parse.
	dcid := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, dcid); err != nil {
		t.Fatal(err)
	}
	scid := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, scid); err != nil {
		t.Fatal(err)
	}

	// Fake ClientHello bytes (handshake type=0x01, length=0, no body).
	ch := []byte{0x01, 0x00, 0x00, 0x00}

	// Build CRYPTO frame.
	var payload []byte
	payload = AppendVarint(payload, 0x06) // CRYPTO
	payload = AppendVarint(payload, 0)    // offset = 0
	payload = AppendVarint(payload, uint64(len(ch)))
	payload = append(payload, ch...)

	// Derive keys.
	initialSalt := [...]byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	initialSecret := hkdf.Extract(sha256.New, dcid, initialSalt[:])
	clientSecret, err := hkdfExpandLabel(initialSecret, "client in", nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	key, err := hkdfExpandLabel(clientSecret, "quic key", nil, 16)
	if err != nil {
		t.Fatal(err)
	}
	iv, err := hkdfExpandLabel(clientSecret, "quic iv", nil, 12)
	if err != nil {
		t.Fatal(err)
	}
	hpKey, err := hkdfExpandLabel(clientSecret, "quic hp", nil, 16)
	if err != nil {
		t.Fatal(err)
	}

	flags := byte(0xc0)
	var hdr []byte
	hdr = append(hdr, flags)
	hdr = binary.BigEndian.AppendUint32(hdr, quicVersion1)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = AppendVarint(hdr, 0) // zero-length token

	// PN = 0 (1 byte).
	pn := byte(0)

	// AEAD encrypt.
	nonce := make([]byte, 12)
	copy(nonce, iv)
	nonce[11] ^= pn

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	hdr = AppendVarint(hdr, uint64(1+len(payload)+gcm.Overhead()))
	aadLenOffset := len(hdr)

	// Append PN (temporary, will mask).
	hdr = append(hdr, pn)
	ct := gcm.Seal(nil, nonce, payload, hdr)

	// Build final packet.
	pnOffset := aadLenOffset
	packet := make([]byte, pnOffset, pnOffset+1+len(ct))
	copy(packet, hdr[:pnOffset])
	packet = append(packet, hdr[pnOffset])
	packet = append(packet, ct...)

	// Pad to > 16 bytes for sample.
	for len(packet) < pnOffset+4+16 {
		packet = append(packet, 0)
	}

	// Apply header protection mask.
	sample := packet[pnOffset+4 : pnOffset+4+16]
	hpBlock, _ := aes.NewCipher(hpKey)
	mask := make([]byte, 16)
	hpBlock.Encrypt(mask, sample)
	packet[0] ^= (mask[0] & 0x0f)
	packet[pnOffset] ^= mask[1]

	// Now try to sniff.
	raw, err := SniffInitial(packet)
	if err != nil {
		t.Fatalf("SniffInitial error: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("no handshake data returned")
	}
	// First byte should be handshake type 0x01 (ClientHello).
	if raw[0] != 0x01 {
		t.Errorf("handshake type = %#x, want 0x01", raw[0])
	}
}

func TestSniffInitial_Empty(t *testing.T) {
	_, err := SniffInitial(nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSniffInitial_ShortHeader(t *testing.T) {
	_, err := SniffInitial([]byte{0x40, 0x01, 0x02, 0x03, 0x04})
	if err == nil {
		t.Fatal("expected error for short header")
	}
}

func TestSniffInitial_NonInitial(t *testing.T) {
	_, err := SniffInitial([]byte{0xc2, 0x00, 0x00, 0x00, 0x01, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	if err == nil {
		t.Fatal("expected error for non-Initial")
	}
}
