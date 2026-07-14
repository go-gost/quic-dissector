package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/hkdf"
)

const (
	quicVersion1       = 0x00000001
	quicVersionDraft29 = 0xff00001d
)

// QUIC v1 Initial salt per RFC 9001 §5.2.
var quicSaltV1 = [...]byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

var (
	ErrNotQUIC    = errors.New("not a QUIC packet")
	ErrNotInitial = errors.New("not a QUIC Initial packet")
)

type cryptoFragment struct {
	offset uint64
	data   []byte
}

// SniffInitial parses a single QUIC Initial datagram and returns the reassembled
// TLS ClientHello handshake bytes (including the 4-byte handshake header:
// type + length). Returns ErrNotInitial for non-Initial long-header packets
// and ErrNotQUIC when the datagram cannot be parsed at all.
//
// Only the first datagram is parsed; cross-datagram CRYPTO reassembly
// is out of scope — use SniffInitialMulti for that.
// ponytail: QUIC v2 (RFC 9369, version 0x6b3343cf) has a different salt
// and inverted type bits; add when observed in the wild.
func SniffInitial(dgram []byte) ([]byte, error) {
	return SniffInitialMulti(dgram)
}

// SniffInitialMulti merges CRYPTO frames from multiple QUIC Initial datagrams
// in the same connection. Uses the first datagram for key derivation (DCID).
// Datagrams that fail decryption (wrong DCID, corrupted) are silently skipped.
func SniffInitialMulti(dgrams ...[]byte) ([]byte, error) {
	if len(dgrams) == 0 {
		return nil, ErrNotQUIC
	}

	// --- Validate first datagram and derive keys ---
	b := dgrams[0]
	if len(b) < 7 {
		return nil, ErrNotQUIC
	}
	// Long header check: bit 7 set for long header, bit 6 fixed bit.
	if b[0]&0xc0 != 0xc0 {
		return nil, ErrNotQUIC
	}
	// Check Initial type: bits 5-4 must be 0.
	if b[0]&0x30 != 0 {
		return nil, ErrNotInitial
	}

	version := binary.BigEndian.Uint32(b[1:5])
	if version != quicVersion1 && version != quicVersionDraft29 {
		return nil, ErrNotQUIC
	}

	pos := 5 // after version

	dcidLen := int(b[pos]); pos++
	if dcidLen < 1 || dcidLen > 20 || len(b) < pos+dcidLen+1 {
		return nil, ErrNotQUIC
	}
	dcid := b[pos : pos+dcidLen]

	key, iv, hpKey, err := deriveInitialKeys(dcid)
	if err != nil {
		return nil, ErrNotQUIC
	}

	// --- Process each datagram ---
	var allFrags []cryptoFragment
	for _, d := range dgrams {
		frags, err := decryptDgram(d, hpKey, key, iv)
		if err != nil {
			continue // mismatched keys (Retry, different conn), skip
		}
		allFrags = append(allFrags, frags...)
	}

	if len(allFrags) == 0 {
		return nil, ErrNotQUIC
	}

	return buildCRYPTO(allFrags), nil
}

// aesECBEncrypt encrypts a single 16-byte block with AES-ECB.
func aesECBEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(plaintext) != aes.BlockSize {
		return nil, errors.New("aes ECB: block size mismatch")
	}
	out := make([]byte, aes.BlockSize)
	block.Encrypt(out, plaintext)
	return out, nil
}

// deriveInitialKeys computes the Initial encryption keys from a
// destination connection ID (RFC 9001 §5.2).
func deriveInitialKeys(dcid []byte) (key, iv, hpKey []byte, err error) {
	initialSecret := hkdf.Extract(sha256.New, dcid, quicSaltV1[:])
	clientSecret, err := hkdfExpandLabel(initialSecret, "client in", nil, 32)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err = hkdfExpandLabel(clientSecret, "quic key", nil, 16)
	if err != nil {
		return nil, nil, nil, err
	}
	iv, err = hkdfExpandLabel(clientSecret, "quic iv", nil, 12)
	if err != nil {
		return nil, nil, nil, err
	}
	hpKey, err = hkdfExpandLabel(clientSecret, "quic hp", nil, 16)
	if err != nil {
		return nil, nil, nil, err
	}
	return key, iv, hpKey, nil
}

// decryptDgram removes header protection and AEAD-decrypts one Initial packet,
// returning any CRYPTO frames found in the payload. Modifies d in place.
func decryptDgram(d []byte, hpKey, key, iv []byte) ([]cryptoFragment, error) {
	// Re-parse header for this datagram (DCID length may vary after Retry)
	pos := 5

	dcidLen := int(d[pos]); pos++
	if dcidLen < 1 || dcidLen > 20 || len(d) < pos+dcidLen+1 {
		return nil, ErrNotQUIC
	}
	pos += dcidLen

	scidLen := int(d[pos]); pos++
	if scidLen > 20 || len(d) < pos+scidLen {
		return nil, ErrNotQUIC
	}
	pos += scidLen

	tokenLen, n := ReadVarint(d[pos:])
	if n == 0 || len(d) < pos+n+int(tokenLen) {
		return nil, ErrNotQUIC
	}
	pos += n + int(tokenLen)

	remainingLen, n := ReadVarint(d[pos:])
	if n == 0 || len(d) < pos+n+int(remainingLen) {
		return nil, ErrNotQUIC
	}
	pnOffset := pos + n

	// --- Header protection removal ---
	sampleStart := pnOffset + 4
	if len(d) < sampleStart+16 {
		return nil, ErrNotQUIC
	}
	sample := d[sampleStart : sampleStart+16]

	mask, err := aesECBEncrypt(hpKey, sample)
	if err != nil {
		return nil, ErrNotQUIC
	}

	// Unmask first byte in-place (lower 4 bits are PN length + reserved).
	d[0] ^= (mask[0] & 0x0f)
	pnLen := int(d[0]&0x03) + 1 // 0→1, 1→2, 2→3, 3→4

	if len(d) < pnOffset+pnLen {
		return nil, ErrNotQUIC
	}

	// Unmask PN bytes in-place.
	for i := 0; i < pnLen; i++ {
		d[pnOffset+i] ^= mask[1+i]
	}
	pnBytes := make([]byte, 4)
	copy(pnBytes[4-pnLen:], d[pnOffset:pnOffset+pnLen])
	packetNumber := binary.BigEndian.Uint32(pnBytes)

	// AAD = fully unmasked header (matches sender's AEAD input).
	aad := d[:pnOffset+pnLen]

	// --- AEAD decryption ---
	payloadStart := pnOffset + pnLen
	if len(d) < payloadStart+16 {
		return nil, ErrNotQUIC
	}
	ct := d[payloadStart:]

	// Nonce = iv XOR truncated packet number (big-endian, zero-padded to 12).
	nonce := make([]byte, 12)
	copy(nonce, iv)
	var pnBuf [4]byte
	binary.BigEndian.PutUint32(pnBuf[:], packetNumber)
	for i := 0; i < 4; i++ {
		nonce[8+i] ^= pnBuf[i]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrNotQUIC
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrNotQUIC
	}

	plaintext, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, err
	}

	return collectCRYPTO(plaintext), nil
}

// collectCRYPTO iterates QUIC frames in a decrypted Initial payload
// and returns all CRYPTO frame fragments.
func collectCRYPTO(data []byte) []cryptoFragment {
	var frags []cryptoFragment

	for i := 0; i < len(data); {
		frameType, n := ReadVarint(data[i:])
		if n == 0 {
			break
		}
		i += n

		switch frameType {
		case 0x00: // PADDING
			for i < len(data) && data[i] == 0 {
				i++
			}

		case 0x01: // PING

		case 0x02, 0x03: // ACK
			_, n = ReadVarint(data[i:])
			if n == 0 {
				return frags
			}
			i += n
			_, n = ReadVarint(data[i:])
			if n == 0 {
				return frags
			}
			i += n
			rangeCount, n := ReadVarint(data[i:])
			if n == 0 {
				return frags
			}
			i += n
			_, n = ReadVarint(data[i:])
			if n == 0 {
				return frags
			}
			i += n
			for j := uint64(0); j < rangeCount; j++ {
				_, n = ReadVarint(data[i:])
				if n == 0 {
					return frags
				}
				i += n
				_, n = ReadVarint(data[i:])
				if n == 0 {
					return frags
				}
				i += n
			}
			if frameType == 0x03 {
				for k := 0; k < 3; k++ {
					_, n = ReadVarint(data[i:])
					if n == 0 {
						return frags
					}
					i += n
				}
			}

		case 0x06: // CRYPTO
			off, n := ReadVarint(data[i:])
			if n == 0 {
				return frags
			}
			i += n
			length, n := ReadVarint(data[i:])
			if n == 0 {
				return frags
			}
			i += n
			end := i + int(length)
			if end > len(data) {
				end = len(data)
			}
			frags = append(frags, cryptoFragment{offset: off, data: append([]byte(nil), data[i:end]...)})
			i = end

		case 0x1c, 0x1d: // CONNECTION_CLOSE
			return frags
		}
	}

	return frags
}

// buildCRYPTO merges CRYPTO fragments into a contiguous buffer by offset.
// The buffer is sized to include all fragment ranges; gaps remain zero.
func buildCRYPTO(frags []cryptoFragment) []byte {
	if len(frags) == 0 {
		return nil
	}
	size := uint64(0)
	for _, f := range frags {
		end := f.offset + uint64(len(f.data))
		if end > size {
			size = end
		}
	}
	buf := make([]byte, size)
	for _, f := range frags {
		copy(buf[f.offset:], f.data)
	}
	return buf
}
