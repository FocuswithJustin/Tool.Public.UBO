package keygen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeScript writes an executable shell script at dir/name with the given body.
func writeScript(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0700); err != nil {
		t.Fatalf("write script %s: %v", p, err)
	}
}

// fakeToolDir returns a temp dir intended to be prepended to PATH. It does NOT
// chain to the real PATH, so any tool not provided as a script is "not found".
func fakeToolDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// --- loadExisting: each per-file-missing branch -----------------------------

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

// --- GenerateWireGuardKeypair error branches --------------------------------

func TestGenerateWireGuard_genkeyFails(t *testing.T) {
	bin := fakeToolDir(t)
	// wg exits non-zero for any subcommand -> genkey fails.
	writeScript(t, bin, "wg", "exit 1\n")
	t.Setenv("PATH", bin)

	_, _, err := GenerateWireGuardKeypair("test_wg", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "wg genkey") {
		t.Fatalf("want wg genkey error, got %v", err)
	}
}

func TestGenerateWireGuard_genkeyNotFound(t *testing.T) {
	bin := fakeToolDir(t) // empty: no wg at all
	t.Setenv("PATH", bin)

	_, _, err := GenerateWireGuardKeypair("test_wg", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "wg genkey") {
		t.Fatalf("want wg genkey error, got %v", err)
	}
}

func TestGenerateWireGuard_writePrivFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: read-only dir perms not enforced")
	}
	bin := fakeToolDir(t)
	// genkey prints a key; pubkey would too but we fail before then.
	writeScript(t, bin, "wg", `if [ "$1" = "genkey" ]; then echo "AAAAprivkeyAAAA"; else cat; fi`+"\n")
	t.Setenv("PATH", bin)

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

func TestGenerateWireGuard_pubkeyFails(t *testing.T) {
	bin := fakeToolDir(t)
	// genkey succeeds, pubkey fails.
	writeScript(t, bin, "wg", `if [ "$1" = "genkey" ]; then echo "AAAAprivkeyAAAA"; exit 0; else exit 1; fi`+"\n")
	t.Setenv("PATH", bin)

	outDir := t.TempDir()
	_, _, err := GenerateWireGuardKeypair("test_wg", outDir)
	if err == nil || !strings.Contains(err.Error(), "wg pubkey") {
		t.Fatalf("want wg pubkey error, got %v", err)
	}
	// On pubkey failure the private key file must be cleaned up.
	if _, statErr := os.Stat(filepath.Join(outDir, "test_wg_private.key")); !os.IsNotExist(statErr) {
		t.Errorf("private key not removed after pubkey failure: %v", statErr)
	}
}

func TestGenerateWireGuard_writePubFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: read-only dir perms not enforced")
	}
	bin := fakeToolDir(t)
	// Both genkey and pubkey succeed; the write of the pub file must fail.
	writeScript(t, bin, "wg", `if [ "$1" = "genkey" ]; then echo "AAAAprivkeyAAAA"; else echo "BBBBpubkeyBBBB"; fi`+"\n")
	t.Setenv("PATH", bin)

	outDir := t.TempDir()
	// Pre-create the private key path as a writable file via a normal run first
	// would be circular; instead make the pub path itself unwritable. We make
	// the directory read+exec only AFTER the private write — not possible
	// directly, so instead pre-create the pub path as a directory so WriteFile
	// to it fails while the private write (a different name) succeeds.
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

// --- GenerateSSHKeypair error branches --------------------------------------

func TestGenerateSSH_keygenFails(t *testing.T) {
	bin := fakeToolDir(t)
	writeScript(t, bin, "ssh-keygen", "echo 'boom' >&2; exit 1\n")
	t.Setenv("PATH", bin)

	_, _, err := GenerateSSHKeypair("client_auth", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "ssh-keygen") {
		t.Fatalf("want ssh-keygen error, got %v", err)
	}
}

func TestGenerateSSH_readPubFails(t *testing.T) {
	bin := fakeToolDir(t)
	// ssh-keygen "succeeds" but writes no .pub file, so the subsequent
	// os.ReadFile of the pub path fails.
	writeScript(t, bin, "ssh-keygen", "exit 0\n")
	t.Setenv("PATH", bin)

	outDir := t.TempDir()
	_, _, err := GenerateSSHKeypair("client_auth", outDir)
	if err == nil || !strings.Contains(err.Error(), "read") {
		t.Fatalf("want read .pub error, got %v", err)
	}
}

// --- GenerateAll error-wrap branches ----------------------------------------

func TestGenerateAll_serverWGError(t *testing.T) {
	bin := fakeToolDir(t)
	writeScript(t, bin, "wg", "exit 1\n")
	t.Setenv("PATH", bin)

	// Empty dir so loadExisting fails first, then server WG generation fails.
	_, err := GenerateAll(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "server WireGuard keypair") {
		t.Fatalf("want server WireGuard keypair error, got %v", err)
	}
}

func TestGenerateAll_clientWGError(t *testing.T) {
	bin := fakeToolDir(t)
	// Server keypair (name server_wg) succeeds; client keypair fails.
	// We distinguish by failing pubkey only for the client by counting calls is
	// hard in shell, so instead: succeed for server_wg by allowing the first two
	// invocations, fail later. Simpler: make genkey succeed always, pubkey
	// succeed always, but make the client private write fail by pre-creating
	// client_wg_private.key as a directory.
	writeScript(t, bin, "wg", `if [ "$1" = "genkey" ]; then echo "AAAAprivkeyAAAA"; else echo "BBBBpubkeyBBBB"; fi`+"\n")
	t.Setenv("PATH", bin)

	outDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(outDir, "client_wg_private.key"), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	_, err := GenerateAll(outDir)
	if err == nil || !strings.Contains(err.Error(), "client WireGuard keypair") {
		t.Fatalf("want client WireGuard keypair error, got %v", err)
	}
}

func TestGenerateAll_sshError(t *testing.T) {
	bin := fakeToolDir(t)
	// wg works for both server and client; ssh-keygen fails.
	writeScript(t, bin, "wg", `if [ "$1" = "genkey" ]; then echo "AAAAprivkeyAAAA"; else echo "BBBBpubkeyBBBB"; fi`+"\n")
	writeScript(t, bin, "ssh-keygen", "exit 1\n")
	t.Setenv("PATH", bin)

	_, err := GenerateAll(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "client SSH keypair") {
		t.Fatalf("want client SSH keypair error, got %v", err)
	}
}

// --- GenerateAll: full fresh generate (all three steps succeed → return &Keys{}) ---

func TestGenerateAll_freshGenerate(t *testing.T) {
	bin := fakeToolDir(t)
	// wg genkey prints a private key; wg pubkey (reads stdin) prints a public key.
	writeScript(t, bin, "wg", `if [ "$1" = "genkey" ]; then
  echo "YIbRUuVmBNkRbWJAL0TaTRisBimNMRMkdHjHaJKR9Gs="
else
  echo "qGVoBkUNFByAaJqKPGjNBOCHqEfOmNJXLb2Sz3zMpEY="
fi`)
	// ssh-keygen must create the private key and .pub files at the path given by -f.
	writeScript(t, bin, "ssh-keygen", `f=""
while [ $# -gt 0 ]; do
  if [ "$1" = "-f" ]; then f="$2"; shift 2; else shift; fi
done
printf "FAKE-PRIVATE-KEY" > "$f"
chmod 600 "$f"
printf "ssh-ed25519 AAAA fakekey ubo-client" > "${f}.pub"`)
	t.Setenv("PATH", bin)

	dir := t.TempDir()
	keys, err := GenerateAll(dir)
	if err != nil {
		t.Fatalf("GenerateAll fresh: %v", err)
	}
	if keys.ServerWGPrivate == "" || keys.ClientWGPrivate == "" || keys.ClientSSHKeyPath == "" {
		t.Errorf("expected all key fields set, got %+v", keys)
	}
}

// --- GenerateAll: loadExisting success (reuse path) -------------------------

func TestGenerateAll_reuseExisting(t *testing.T) {
	bin := fakeToolDir(t)
	// Provide wg and ssh-keygen so fresh generation would work if somehow triggered,
	// but since all files are pre-seeded, they should never be called.
	writeScript(t, bin, "wg", "exit 99\n")
	writeScript(t, bin, "ssh-keygen", "exit 99\n")
	t.Setenv("PATH", bin)

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
