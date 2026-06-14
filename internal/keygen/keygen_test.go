package keygen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// skipIfToolMissing skips the test if the error indicates a required external
// tool (wg, ssh-keygen) is not available in PATH.
func skipIfToolMissing(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, sig := range []string{"wg genkey", "ssh-keygen", "executable file not found"} {
		if strings.Contains(err.Error(), sig) {
			t.Skipf("required tool not in PATH; skipping: %v", err)
		}
	}
}

// assertFileMode fails unless dir/name exists with the expected permission bits.
func assertFileMode(t *testing.T, dir, name string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("file %s missing: %v", name, err)
	}
	if info.Mode().Perm() != want {
		t.Errorf("%s mode = %o; want %o", name, info.Mode().Perm(), want)
	}
}

// assertFileContent fails unless dir/name exists with trimmed content equal to want.
func assertFileContent(t *testing.T, dir, name, want string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("file %s missing: %v", name, err)
	}
	if got := strings.TrimSpace(string(data)); got != want {
		t.Errorf("%s content = %q; want %q", name, got, want)
	}
}

func TestGenerateWireGuardKeypair(t *testing.T) {
	dir := t.TempDir()

	priv, pub, err := GenerateWireGuardKeypair("test_wg", dir)
	skipIfToolMissing(t, err)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("key lengths", func(t *testing.T) {
		// WireGuard keys are 44-char base64 strings.
		if len(priv) != 44 {
			t.Errorf("private key len = %d; want 44", len(priv))
		}
		if len(pub) != 44 {
			t.Errorf("public key len = %d; want 44", len(pub))
		}
	})

	t.Run("file contents", func(t *testing.T) {
		assertFileContent(t, dir, "test_wg_private.key", priv)
		assertFileContent(t, dir, "test_wg_public.key", pub)
	})

	t.Run("file modes", func(t *testing.T) {
		assertFileMode(t, dir, "test_wg_private.key", 0600)
		assertFileMode(t, dir, "test_wg_public.key", 0644)
	})
}

func TestGenerateSSHKeypair(t *testing.T) {
	dir := t.TempDir()

	keyPath, pubKey, err := GenerateSSHKeypair("client_auth", dir)
	skipIfToolMissing(t, err)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("key path", func(t *testing.T) {
		if keyPath != filepath.Join(dir, "client_auth") {
			t.Errorf("keyPath = %q; want %q", keyPath, filepath.Join(dir, "client_auth"))
		}
	})

	t.Run("public key format", func(t *testing.T) {
		if !strings.HasPrefix(pubKey, "ssh-ed25519 ") {
			t.Errorf("public key should start with 'ssh-ed25519 ', got: %q", pubKey)
		}
		if !strings.Contains(pubKey, "ubo-client") {
			t.Errorf("public key missing 'ubo-client' comment: %q", pubKey)
		}
	})

	t.Run("files", func(t *testing.T) {
		assertFileMode(t, dir, "client_auth", 0600)
		if _, err := os.Stat(keyPath + ".pub"); err != nil {
			t.Errorf("public key file missing: %v", err)
		}
	})
}

func TestGenerateSSHKeypair_idempotent(t *testing.T) {
	// Calling again in the same dir should succeed (removes old key first)
	dir := t.TempDir()

	_, _, err := GenerateSSHKeypair("client_auth", dir)
	skipIfToolMissing(t, err)
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}

	_, _, err = GenerateSSHKeypair("client_auth", dir)
	if err != nil {
		t.Fatalf("second call error (should overwrite): %v", err)
	}
}

// keyFields returns the Keys fields as named (label, value) pairs so tests can
// assert over them in a loop instead of one branch per field.
func keyFields(k *Keys) []struct{ name, val string } {
	return []struct{ name, val string }{
		{"ServerWGPrivate", k.ServerWGPrivate},
		{"ServerWGPublic", k.ServerWGPublic},
		{"ClientWGPrivate", k.ClientWGPrivate},
		{"ClientWGPublic", k.ClientWGPublic},
		{"ClientSSHKeyPath", k.ClientSSHKeyPath},
		{"ClientSSHPubKey", k.ClientSSHPubKey},
	}
}

// generatedKeyFiles are the files GenerateAll is expected to write.
var generatedKeyFiles = []string{
	"server_wg_private.key",
	"server_wg_public.key",
	"client_wg_private.key",
	"client_wg_public.key",
	"client_auth_ed25519",
	"client_auth_ed25519.pub",
}

func TestGenerateAll(t *testing.T) {
	dir := t.TempDir()

	keys, err := GenerateAll(dir)
	skipIfToolMissing(t, err)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("fields populated", func(t *testing.T) { assertFieldsPopulated(t, keys) })
	t.Run("server and client keys differ", func(t *testing.T) {
		if keys.ServerWGPrivate == keys.ClientWGPrivate {
			t.Error("server and client WireGuard private keys are identical")
		}
	})
	t.Run("files written", func(t *testing.T) { assertGeneratedFiles(t, dir) })
}

func assertFieldsPopulated(t *testing.T, keys *Keys) {
	t.Helper()
	for _, f := range keyFields(keys) {
		if f.val == "" {
			t.Errorf("%s is empty", f.name)
		}
	}
}

func assertGeneratedFiles(t *testing.T, dir string) {
	t.Helper()
	for _, name := range generatedKeyFiles {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected file %s missing: %v", name, err)
		}
	}
}

func TestGenerateAll_reuse(t *testing.T) {
	dir := t.TempDir()

	first, err := GenerateAll(dir)
	skipIfToolMissing(t, err)
	if err != nil {
		t.Fatalf("first GenerateAll: %v", err)
	}

	second, err := GenerateAll(dir)
	if err != nil {
		t.Fatalf("second GenerateAll: %v", err)
	}

	firstFields, secondFields := keyFields(first), keyFields(second)
	for i := range firstFields {
		if secondFields[i].val != firstFields[i].val {
			t.Errorf("%s changed on second call", firstFields[i].name)
		}
	}
}
