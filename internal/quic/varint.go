package quic

// ReadVarint decodes a QUIC variable-length integer (RFC 9000 §16).
// Returns 0, 0 on truncated input.
func ReadVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	// ponytail: two-bit prefix encodes length
	switch b[0] >> 6 {
	case 0:
		return uint64(b[0]), 1
	case 1:
		if len(b) < 2 {
			return 0, 0
		}
		return uint64(b[0]&0x3f)<<8 | uint64(b[1]), 2
	case 2:
		if len(b) < 4 {
			return 0, 0
		}
		n := uint64(b[0]&0x3f)<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
		return n, 4
	default: // 3
		if len(b) < 8 {
			return 0, 0
		}
		n := uint64(b[0]&0x3f)<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
			uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
		return n, 8
	}
}

// AppendVarint encodes v as a QUIC variable-length integer
// using the minimal number of bytes (RFC 9000 §16).
func AppendVarint(b []byte, v uint64) []byte {
	switch {
	case v <= 63:
		return append(b, byte(v))
	case v <= 16383:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v <= 1073741823:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b, byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}
