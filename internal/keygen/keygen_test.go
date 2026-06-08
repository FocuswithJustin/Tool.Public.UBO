package keygen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// skipIfToolMissing skips the test if the named tool is not in PATH.
func skipIfToolMissing(t *testing.T, tool string) {
	t.Helper()
	// Use exec.LookPath indirectly: attempt a failing run to check existence.
	// We can't import exec without pulling in more packages than needed, so just
	// use os.LookupEnv as a signal — actually we do import os already, let's just
	// attempt to generate and catch the error.
}

func TestGenerateWireGuardKeypair(t *testing.T) {
	dir := t.TempDir()

	priv, pub, err := GenerateWireGuardKeypair("test_wg", dir)
	if err != nil {
		if strings.Contains(err.Error(), "wg genkey") || strings.Contains(err.Error(), "executable file not found") {
			t.Skipf("wg not in PATH; skipping: %v", err)
		}
		t.Fatalf("unexpected error: %v", err)
	}

	// Keys must be non-empty base64-ish strings (44 chars for WireGuard keys)
	if len(priv) != 44 {
		t.Errorf("private key len = %d; want 44", len(priv))
	}
	if len(pub) != 44 {
		t.Errorf("public key len = %d; want 44", len(pub))
	}

	privPath := filepath.Join(dir, "test_wg_private.key")
	pubPath := filepath.Join(dir, "test_wg_public.key")

	// Verify files were written
	privData, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("private key file missing: %v", err)
	}
	if strings.TrimSpace(string(privData)) != priv {
		t.Error("private key file content doesn't match returned value")
	}

	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("public key file missing: %v", err)
	}
	if strings.TrimSpace(string(pubData)) != pub {
		t.Error("public key file content doesn't match returned value")
	}

	// Check file modes
	privInfo, _ := os.Stat(privPath)
	if privInfo.Mode().Perm() != 0600 {
		t.Errorf("private key mode = %o; want 0600", privInfo.Mode().Perm())
	}
	pubInfo, _ := os.Stat(pubPath)
	if pubInfo.Mode().Perm() != 0644 {
		t.Errorf("public key mode = %o; want 0644", pubInfo.Mode().Perm())
	}
}

func TestGenerateSSHKeypair(t *testing.T) {
	dir := t.TempDir()

	keyPath, pubKey, err := GenerateSSHKeypair("client_auth", dir)
	if err != nil {
		if strings.Contains(err.Error(), "ssh-keygen") || strings.Contains(err.Error(), "executable file not found") {
			t.Skipf("ssh-keygen not in PATH; skipping: %v", err)
		}
		t.Fatalf("unexpected error: %v", err)
	}

	if keyPath != filepath.Join(dir, "client_auth") {
		t.Errorf("keyPath = %q; want %q", keyPath, filepath.Join(dir, "client_auth"))
	}

	// Public key should be in authorized_keys format
	if !strings.HasPrefix(pubKey, "ssh-ed25519 ") {
		t.Errorf("public key should start with 'ssh-ed25519 ', got: %q", pubKey)
	}
	if !strings.Contains(pubKey, "ubo-client") {
		t.Errorf("public key missing 'ubo-client' comment: %q", pubKey)
	}

	// Verify private key file mode
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("private key file missing: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("private key mode = %o; want 0600", info.Mode().Perm())
	}

	// Public key file should exist
	if _, err := os.Stat(keyPath + ".pub"); err != nil {
		t.Errorf("public key file missing: %v", err)
	}
}

func TestGenerateSSHKeypair_idempotent(t *testing.T) {
	// Calling again in the same dir should succeed (removes old key first)
	dir := t.TempDir()

	_, _, err := GenerateSSHKeypair("client_auth", dir)
	if err != nil {
		if strings.Contains(err.Error(), "ssh-keygen") || strings.Contains(err.Error(), "executable file not found") {
			t.Skipf("ssh-keygen not in PATH; skipping: %v", err)
		}
		t.Fatalf("first call error: %v", err)
	}

	_, _, err = GenerateSSHKeypair("client_auth", dir)
	if err != nil {
		t.Fatalf("second call error (should overwrite): %v", err)
	}
}

func TestGenerateAll(t *testing.T) {
	dir := t.TempDir()

	keys, err := GenerateAll(dir)
	if err != nil {
		if strings.Contains(err.Error(), "wg genkey") ||
			strings.Contains(err.Error(), "ssh-keygen") ||
			strings.Contains(err.Error(), "executable file not found") {
			t.Skipf("required tools not in PATH; skipping: %v", err)
		}
		t.Fatalf("unexpected error: %v", err)
	}

	// All fields must be populated
	if keys.ServerWGPrivate == "" {
		t.Error("ServerWGPrivate is empty")
	}
	if keys.ServerWGPublic == "" {
		t.Error("ServerWGPublic is empty")
	}
	if keys.ClientWGPrivate == "" {
		t.Error("ClientWGPrivate is empty")
	}
	if keys.ClientWGPublic == "" {
		t.Error("ClientWGPublic is empty")
	}
	if keys.ClientSSHKeyPath == "" {
		t.Error("ClientSSHKeyPath is empty")
	}
	if keys.ClientSSHPubKey == "" {
		t.Error("ClientSSHPubKey is empty")
	}

	// Server and client WG keys should be different
	if keys.ServerWGPrivate == keys.ClientWGPrivate {
		t.Error("server and client WireGuard private keys are identical")
	}

	// Expected files in output dir
	wantFiles := []string{
		"server_wg_private.key",
		"server_wg_public.key",
		"client_wg_private.key",
		"client_wg_public.key",
		"client_auth_ed25519",
		"client_auth_ed25519.pub",
	}
	for _, name := range wantFiles {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected file %s missing: %v", name, err)
		}
	}
}

func TestGenerateAll_reuse(t *testing.T) {
	dir := t.TempDir()

	first, err := GenerateAll(dir)
	if err != nil {
		if strings.Contains(err.Error(), "wg genkey") ||
			strings.Contains(err.Error(), "ssh-keygen") ||
			strings.Contains(err.Error(), "executable file not found") {
			t.Skipf("required tools not in PATH; skipping: %v", err)
		}
		t.Fatalf("first GenerateAll: %v", err)
	}

	second, err := GenerateAll(dir)
	if err != nil {
		t.Fatalf("second GenerateAll: %v", err)
	}

	if second.ServerWGPrivate != first.ServerWGPrivate {
		t.Error("ServerWGPrivate changed on second call")
	}
	if second.ServerWGPublic != first.ServerWGPublic {
		t.Error("ServerWGPublic changed on second call")
	}
	if second.ClientWGPrivate != first.ClientWGPrivate {
		t.Error("ClientWGPrivate changed on second call")
	}
	if second.ClientWGPublic != first.ClientWGPublic {
		t.Error("ClientWGPublic changed on second call")
	}
	if second.ClientSSHKeyPath != first.ClientSSHKeyPath {
		t.Error("ClientSSHKeyPath changed on second call")
	}
	if second.ClientSSHPubKey != first.ClientSSHPubKey {
		t.Error("ClientSSHPubKey changed on second call")
	}
}
