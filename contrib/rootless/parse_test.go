package rootless

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ubo/internal/config"
)

const sampleWGConf = `[Interface]
PrivateKey = YIbRUuVmBNkRbWJAL0TaTRisBimNMRMkdHjHaJKR9Gs=
Address = 10.42.0.2/32

[Peer]
PublicKey = qGVoBkUNFByAaJqKPGjNBOCHqEfOmNJXLb2Sz3zMpEY=
Endpoint = 1.2.3.4:51820
AllowedIPs = 10.42.0.1/32
PersistentKeepalive = 25
`

func checkField(t *testing.T, field, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %q; want %q", field, got, want)
	}
}

func TestParseWGConfig_valid(t *testing.T) {
	p := filepath.Join(t.TempDir(), "client.conf")
	if err := os.WriteFile(p, []byte(sampleWGConf), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseWGConfig(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkField(t, "PrivateKey", cfg.PrivateKey, "YIbRUuVmBNkRbWJAL0TaTRisBimNMRMkdHjHaJKR9Gs=")
	checkField(t, "Address", cfg.Address, "10.42.0.2/32")
	checkField(t, "PeerPubKey", cfg.PeerPubKey, "qGVoBkUNFByAaJqKPGjNBOCHqEfOmNJXLb2Sz3zMpEY=")
	checkField(t, "Endpoint", cfg.Endpoint, "1.2.3.4:51820")
	checkField(t, "AllowedIPs", cfg.AllowedIPs, "10.42.0.1/32")
}

func TestParseWGConfig_missingField(t *testing.T) {
	conf := "[Interface]\nPrivateKey = YIbRUuVmBNkRbWJAL0TaTRisBimNMRMkdHjHaJKR9Gs=\nAddress = 10.42.0.2/32\n"
	p := filepath.Join(t.TempDir(), "client.conf")
	if err := os.WriteFile(p, []byte(conf), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseWGConfig(p); err == nil {
		t.Error("expected error for missing Peer fields")
	}
}

func TestParseWGConfig_notFound(t *testing.T) {
	if _, err := parseWGConfig("/nonexistent/path.conf"); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestB64ToHex_valid(t *testing.T) {
	// 32 bytes of zeros base64-encodes to "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	b64 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	got, err := b64ToHex(b64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "0000000000000000000000000000000000000000000000000000000000000000"
	if got != want {
		t.Errorf("b64ToHex = %q; want %q", got, want)
	}
}

func TestB64ToHex_badBase64(t *testing.T) {
	if _, err := b64ToHex("!!!not-base64"); err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestB64ToHex_wrongLength(t *testing.T) {
	// 16 bytes base64
	if _, err := b64ToHex("AAAAAAAAAAAAAAAAAAAAAA=="); err == nil {
		t.Error("expected error for non-32-byte key")
	}
}

// ── buildChangeLUKSCmd ────────────────────────────────────────────────────────

func TestBuildChangeLUKSCmd_deviceFromConfig(t *testing.T) {
	cfg := &config.Config{LUKS: config.LUKSConfig{Device: "/dev/sda3"}}
	cmd := buildChangeLUKSCmd(cfg)
	if cmd != `cryptsetup luksChangeKey "/dev/sda3"` {
		t.Errorf("unexpected cmd for explicit device: %q", cmd)
	}
}

func TestBuildChangeLUKSCmd_autoDetect_containsCrypttabFallback(t *testing.T) {
	cfg := &config.Config{}
	cmd := buildChangeLUKSCmd(cfg)
	if !strings.Contains(cmd, "/etc/crypttab") {
		t.Error("auto-detect cmd must try /etc/crypttab")
	}
	if !strings.Contains(cmd, "blkid -t TYPE=crypto_LUKS") {
		t.Error("auto-detect cmd must fall back to blkid")
	}
}
