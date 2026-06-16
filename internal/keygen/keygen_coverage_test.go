package keygen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedKeyFiles creates all six files loadExisting expects in dir.
func seedKeyFiles(t *testing.T, dir string) {
	t.Helper()
	files := map[string]string{
		"server_wg_private.key":   "spriv\n",
		"server_wg_public.key":    "spub\n",
		"client_wg_private.key":   "cpriv\n",
		"client_wg_public.key":    "cpub\n",
		"client_auth_ed25519":     "PRIVATE KEY\n",
		"client_auth_ed25519.pub": "ssh-ed25519 AAAA ubo-client\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
}

// --- loadExisting ---

func TestLoadExisting_success(t *testing.T) {
	dir := t.TempDir()
	seedKeyFiles(t, dir)

	keys, err := loadExisting(dir)
	if err != nil {
		t.Fatalf("loadExisting: %v", err)
	}

	want := []struct{ field, got, expect string }{
		{"ServerWGPrivate", keys.ServerWGPrivate, "spriv"},
		{"ServerWGPublic", keys.ServerWGPublic, "spub"},
		{"ClientWGPrivate", keys.ClientWGPrivate, "cpriv"},
		{"ClientWGPublic", keys.ClientWGPublic, "cpub"},
		{"ClientSSHKeyPath", keys.ClientSSHKeyPath, filepath.Join(dir, "client_auth_ed25519")},
		{"ClientSSHPubKey", keys.ClientSSHPubKey, "ssh-ed25519 AAAA ubo-client"},
	}
	for _, w := range want {
		if w.got != w.expect {
			t.Errorf("%s = %q; want %q", w.field, w.got, w.expect)
		}
	}
}

func TestLoadExisting_missingEach(t *testing.T) {
	// Each entry is the file to delete after seeding a complete set.
	missing := []string{
		"server_wg_private.key",
		"server_wg_public.key",
		"client_wg_private.key",
		"client_wg_public.key",
		"client_auth_ed25519", // exercises the os.Stat branch
		"client_auth_ed25519.pub",
	}
	for _, name := range missing {
		name := name
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			seedKeyFiles(t, dir)
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatalf("remove %s: %v", name, err)
			}
			if _, err := loadExisting(dir); err == nil {
				t.Fatalf("expected error when %s is missing", name)
			}
		})
	}
}

// --- deriveWGPublicKey ---

func TestDeriveWGPublicKey_badBase64(t *testing.T) {
	_, err := deriveWGPublicKey("not-valid-base64!!!")
	if err == nil || !strings.Contains(err.Error(), "decode private key") {
		t.Errorf("expected decode error, got %v", err)
	}
}

// --- GenerateWireGuardKeypair error branches ---

func TestGenerateWireGuard_writePrivFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: read-only dir perms not enforced")
	}
	outDir := t.TempDir()
	if err := os.Chmod(outDir, 0500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(outDir, 0700) })

	_, _, err := GenerateWireGuardKeypair("test_wg", outDir)
	if err == nil || !strings.Contains(err.Error(), "write") {
		t.Fatalf("want write error, got %v", err)
	}
}

func TestGenerateWireGuard_writePubFails(t *testing.T) {
	outDir := t.TempDir()
	// Pre-create the public key path as a directory so WriteFile fails on it.
	if err := os.Mkdir(filepath.Join(outDir, "test_wg_public.key"), 0700); err != nil {
		t.Fatalf("mkdir pub-as-dir: %v", err)
	}

	_, _, err := GenerateWireGuardKeypair("test_wg", outDir)
	if err == nil || !strings.Contains(err.Error(), "write") {
		t.Fatalf("want write error for pub, got %v", err)
	}
	// Private key should be cleaned up after pub write failure.
	if _, statErr := os.Stat(filepath.Join(outDir, "test_wg_private.key")); !os.IsNotExist(statErr) {
		t.Errorf("private key not removed after pub write failure: %v", statErr)
	}
}

// --- GenerateSSHKeypair error branches ---

func TestGenerateSSH_writePrivFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: read-only dir perms not enforced")
	}
	outDir := t.TempDir()
	if err := os.Chmod(outDir, 0500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(outDir, 0700) })

	_, _, err := GenerateSSHKeypair("client_auth", outDir)
	if err == nil || !strings.Contains(err.Error(), "write") {
		t.Fatalf("want write error, got %v", err)
	}
}

func TestGenerateSSH_writePubFails(t *testing.T) {
	outDir := t.TempDir()
	// Pre-create the public key path as a directory so WriteFile fails on it.
	if err := os.Mkdir(filepath.Join(outDir, "client_auth.pub"), 0700); err != nil {
		t.Fatalf("mkdir pub-as-dir: %v", err)
	}

	_, _, err := GenerateSSHKeypair("client_auth", outDir)
	if err == nil || !strings.Contains(err.Error(), "write") {
		t.Fatalf("want write error for pub, got %v", err)
	}
	// Private key should be cleaned up after pub write failure.
	if _, statErr := os.Stat(filepath.Join(outDir, "client_auth")); !os.IsNotExist(statErr) {
		t.Errorf("private key not removed after pub write failure: %v", statErr)
	}
}

// --- GenerateAll error-wrap branches ---

func TestGenerateAll_serverWGError(t *testing.T) {
	outDir := t.TempDir()
	// Pre-create server_wg_private.key as a directory to force write failure.
	if err := os.Mkdir(filepath.Join(outDir, "server_wg_private.key"), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	_, err := GenerateAll(outDir)
	if err == nil || !strings.Contains(err.Error(), "server WireGuard keypair") {
		t.Fatalf("want server WireGuard keypair error, got %v", err)
	}
}

func TestGenerateAll_clientWGError(t *testing.T) {
	outDir := t.TempDir()
	// Pre-create client_wg_private.key as a directory to force write failure;
	// server keypair write succeeds first.
	if err := os.Mkdir(filepath.Join(outDir, "client_wg_private.key"), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	_, err := GenerateAll(outDir)
	if err == nil || !strings.Contains(err.Error(), "client WireGuard keypair") {
		t.Fatalf("want client WireGuard keypair error, got %v", err)
	}
}

func TestGenerateAll_sshError(t *testing.T) {
	outDir := t.TempDir()
	// Pre-create client_auth_ed25519 as a directory to force SSH key write failure;
	// both WireGuard keypairs succeed first.
	if err := os.Mkdir(filepath.Join(outDir, "client_auth_ed25519"), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	_, err := GenerateAll(outDir)
	if err == nil || !strings.Contains(err.Error(), "client SSH keypair") {
		t.Fatalf("want client SSH keypair error, got %v", err)
	}
}

// --- GenerateAll: full fresh generate (no external tools needed) ---

func TestGenerateAll_freshGenerate(t *testing.T) {
	dir := t.TempDir()

	keys, err := GenerateAll(dir)
	if err != nil {
		t.Fatalf("GenerateAll fresh: %v", err)
	}
	if keys.ServerWGPrivate == "" || keys.ClientWGPrivate == "" || keys.ClientSSHKeyPath == "" {
		t.Errorf("expected all key fields set, got %+v", keys)
	}
}

// --- GenerateAll: loadExisting success (reuse path) ---

func TestGenerateAll_reuseExisting(t *testing.T) {
	dir := t.TempDir()
	seedKeyFiles(t, dir)

	keys, err := GenerateAll(dir)
	if err != nil {
		t.Fatalf("GenerateAll with existing keys: %v", err)
	}
	if keys.ServerWGPrivate != "spriv" {
		t.Errorf("ServerWGPrivate = %q; want spriv (reused)", keys.ServerWGPrivate)
	}
}
