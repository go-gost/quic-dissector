package quicdissector

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestSniffQUIC_RealTraffic(t *testing.T) {
	paths := []string{
		"/tmp/quic-pkt-0.hex",
		"/tmp/quic-pkt-1.hex",
		"/tmp/quic-pkt-2.hex",
		"/tmp/quic-pkt-3.hex",
	}

	var pkts [][]byte
	for _, path := range paths {
		hexData, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data, err := hex.DecodeString(strings.TrimSpace(string(hexData)))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: len=%d first=0x%02x", path, len(data), data[0])
		pkts = append(pkts, data)
	}

	// Pass all packets — SniffQUIC derives keys from the first, merges
	// CRYPTO frames from all decryptable packets, and parses the result.
	info, err := SniffQUIC(pkts...)
	if err != nil {
		t.Fatalf("SniffQUIC error: %v", err)
	}

	t.Logf("SNI=%q", info.ServerName)
	if info.ServerName != "cloudflare-quic.com" {
		t.Errorf("ServerName = %q, want %q", info.ServerName, "cloudflare-quic.com")
	}
	if len(info.SupportedProtos) > 0 {
		t.Logf("ALPN=%v", info.SupportedProtos)
	}
}
