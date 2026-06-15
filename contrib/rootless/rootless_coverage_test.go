package rootless

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ed25519"
	gossh "golang.org/x/crypto/ssh"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"ubo/internal/config"
	"ubo/internal/remote"
)

// ── sshPort ───────────────────────────────────────────────────────────────────

func TestSSHPort_default(t *testing.T) {
	cfg := &config.Config{}
	if got := sshPort(cfg); got != 22 {
		t.Errorf("sshPort(zero) = %d; want 22", got)
	}
}

func TestSSHPort_custom(t *testing.T) {
	cfg := &config.Config{SSH: config.SSHConfig{Port: 2222}}
	if got := sshPort(cfg); got != 2222 {
		t.Errorf("sshPort(2222) = %d; want 2222", got)
	}
}

// ── sshUser ───────────────────────────────────────────────────────────────────

func TestSSHUser_default(t *testing.T) {
	cfg := &config.Config{}
	if got := sshUser(cfg); got != "root" {
		t.Errorf("sshUser(empty) = %q; want root", got)
	}
}

func TestSSHUser_custom(t *testing.T) {
	cfg := &config.Config{SSH: config.SSHConfig{User: "admin"}}
	if got := sshUser(cfg); got != "admin" {
		t.Errorf("sshUser(admin) = %q; want admin", got)
	}
}

// ── parseFirstAddr ────────────────────────────────────────────────────────────

func TestParseFirstAddr_validCIDR(t *testing.T) {
	addr, err := parseFirstAddr("10.42.0.2/32")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr.String() != "10.42.0.2" {
		t.Errorf("parseFirstAddr(CIDR) = %q; want 10.42.0.2", addr.String())
	}
}

func TestParseFirstAddr_bareIP(t *testing.T) {
	addr, err := parseFirstAddr("10.42.0.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr.String() != "10.42.0.2" {
		t.Errorf("parseFirstAddr(bare IP) = %q; want 10.42.0.2", addr.String())
	}
}

func TestParseFirstAddr_invalid(t *testing.T) {
	if _, err := parseFirstAddr("not-an-ip"); err == nil {
		t.Error("expected error for invalid address")
	}
}

// ── loadSSHKey ────────────────────────────────────────────────────────────────

func TestLoadSSHKey_missingFile(t *testing.T) {
	if _, err := loadSSHKey(filepath.Join(t.TempDir(), "no_such_key")); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadSSHKey_invalidData(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad_key")
	if err := os.WriteFile(p, []byte("this is not a key"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSSHKey(p); err == nil {
		t.Error("expected error for invalid key data")
	}
}

func TestLoadSSHKey_validKey(t *testing.T) {
	keyPath, _ := genTestKey(t)
	if _, err := loadSSHKey(keyPath); err != nil {
		t.Fatalf("loadSSHKey valid key: %v", err)
	}
}

// ── loadPinnedKey ─────────────────────────────────────────────────────────────

func TestLoadPinnedKey_missingFile(t *testing.T) {
	if _, err := loadPinnedKey(filepath.Join(t.TempDir(), "no_such.pub")); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadPinnedKey_invalidData(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.pub")
	if err := os.WriteFile(p, []byte("not a public key"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPinnedKey(p); err == nil {
		t.Error("expected error for invalid pub key data")
	}
}

func TestLoadPinnedKey_validKey(t *testing.T) {
	_, pubPath := genTestKey(t)
	if _, err := loadPinnedKey(pubPath); err != nil {
		t.Fatalf("loadPinnedKey valid pub: %v", err)
	}
}

// ── buildIPC ──────────────────────────────────────────────────────────────────

func TestBuildIPC_valid(t *testing.T) {
	wgCfg := &wgClientConfig{
		PrivateKey: "YIbRUuVmBNkRbWJAL0TaTRisBimNMRMkdHjHaJKR9Gs=",
		PeerPubKey: "qGVoBkUNFByAaJqKPGjNBOCHqEfOmNJXLb2Sz3zMpEY=",
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: "10.42.0.1/32",
	}
	ipc, err := buildIPC(wgCfg)
	if err != nil {
		t.Fatalf("buildIPC: %v", err)
	}
	for _, want := range []string{"private_key=", "public_key=", "endpoint=1.2.3.4:51820", "allowed_ip=10.42.0.1/32"} {
		if !strings.Contains(ipc, want) {
			t.Errorf("buildIPC output missing %q\ngot:\n%s", want, ipc)
		}
	}
}

func TestBuildIPC_badPrivateKey(t *testing.T) {
	wgCfg := &wgClientConfig{
		PrivateKey: "!!!invalid-base64",
		PeerPubKey: "qGVoBkUNFByAaJqKPGjNBOCHqEfOmNJXLb2Sz3zMpEY=",
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: "10.42.0.1/32",
	}
	if _, err := buildIPC(wgCfg); err == nil {
		t.Error("expected error for invalid private key base64")
	}
}

func TestBuildIPC_badPeerPubKey(t *testing.T) {
	wgCfg := &wgClientConfig{
		PrivateKey: "YIbRUuVmBNkRbWJAL0TaTRisBimNMRMkdHjHaJKR9Gs=",
		PeerPubKey: "!!!invalid-base64",
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: "10.42.0.1/32",
	}
	if _, err := buildIPC(wgCfg); err == nil {
		t.Error("expected error for invalid peer public key base64")
	}
}

// ── handleTunnelFailure ───────────────────────────────────────────────────────

func TestHandleTunnelFailure_changeKeyFalse(t *testing.T) {
	sentinel := errors.New("tunnel down")
	err := handleTunnelFailure(context.Background(), &config.Config{}, "/tmp/out", false, sentinel)
	if err != sentinel {
		t.Errorf("handleTunnelFailure(changeKey=false) = %v; want sentinel error", err)
	}
}

func TestHandleTunnelFailure_changeKeyTrue(t *testing.T) {
	orig := changeKeyDirectSSHFn
	t.Cleanup(func() { changeKeyDirectSSHFn = orig })

	called := false
	changeKeyDirectSSHFn = func(_ context.Context, _ *config.Config, _ string) error {
		called = true
		return nil
	}

	err := handleTunnelFailure(context.Background(), &config.Config{}, "/tmp/out", true, errors.New("tunnel"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("changeKeyDirectSSHFn was not called when changeKey=true")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// genTestKey generates an ed25519 key pair in a temp dir and returns the
// private key path and public key path. Skips if ssh-keygen is unavailable.
func genTestKey(t *testing.T) (keyPath, pubPath string) {
	t.Helper()
	dir := t.TempDir()
	keyPath = filepath.Join(dir, "test_key")
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-C", "test")
	if err := cmd.Run(); err != nil {
		t.Skip("ssh-keygen not available")
	}
	return keyPath, keyPath + ".pub"
}

// newTestSSHSigner generates an ephemeral ed25519 host key and returns a Signer.
func newTestSSHSigner(t *testing.T) gossh.Signer {
	t.Helper()
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(privKey)
	if err != nil {
		t.Fatalf("make signer: %v", err)
	}
	return signer
}

// serveOneTestConn accepts one connection from ln, runs a minimal SSH server
// that accepts any auth and rejects all channel requests, then closes.
func serveOneTestConn(ln net.Listener, cfg *gossh.ServerConfig) {
	conn, err := ln.Accept()
	ln.Close() //nolint:errcheck
	if err != nil {
		return
	}
	sc, chans, reqs, err := gossh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	go gossh.DiscardRequests(reqs)
	for ch := range chans {
		ch.Reject(gossh.Prohibited, "test server rejects all channels") //nolint:errcheck
	}
	sc.Close() //nolint:errcheck
}

// makeTestClient starts a minimal in-process SSH server and returns a connected
// *gossh.Client. Uses a real TCP socket so SSH's concurrent writes don't deadlock.
// The server rejects all channel requests, so NewSession fails — but the client
// itself is valid for Close() and other non-session operations.
func makeTestClient(t *testing.T) *gossh.Client {
	t.Helper()
	serverCfg := &gossh.ServerConfig{NoClientAuth: true}
	serverCfg.AddHostKey(newTestSSHSigner(t))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go serveOneTestConn(ln, serverCfg)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial test server: %v", err)
	}
	sshConn, chans, reqs, err := gossh.NewClientConn(conn, ln.Addr().String(), &gossh.ClientConfig{
		User:            "test",
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Skipf("in-process SSH setup failed: %v", err)
	}
	c := gossh.NewClient(sshConn, chans, reqs)
	t.Cleanup(func() { c.Close() }) //nolint:errcheck
	return c
}

// ── runUnlock seam tests ──────────────────────────────────────────────────────

func TestRunUnlock_ptyError(t *testing.T) {
	orig := runPTYFn
	t.Cleanup(func() { runPTYFn = orig })
	runPTYFn = func(_ *gossh.Client, _ string) error { return errors.New("pty boom") }

	err := runUnlock(nil) // nil client: runPTYFn ignores it
	if err == nil || !strings.Contains(err.Error(), "cryptroot-unlock") {
		t.Errorf("want cryptroot-unlock error, got %v", err)
	}
}

// ── runChangeKey seam tests ───────────────────────────────────────────────────

func TestRunChangeKey_ptyError(t *testing.T) {
	orig := runPTYFn
	t.Cleanup(func() { runPTYFn = orig })
	runPTYFn = func(_ *gossh.Client, _ string) error { return errors.New("pty boom") }

	_, err := runChangeKey(nil, &config.Config{})
	if err == nil || !strings.Contains(err.Error(), "luksChangeKey") {
		t.Errorf("want luksChangeKey error, got %v", err)
	}
}

func TestRunChangeKey_answerNo(t *testing.T) {
	orig := runPTYFn
	t.Cleanup(func() { runPTYFn = orig })
	runPTYFn = func(_ *gossh.Client, _ string) error { return nil }

	origStdin := stdinReader
	t.Cleanup(func() { stdinReader = origStdin })
	stdinReader = strings.NewReader("n\n")

	proceed, err := runChangeKey(nil, &config.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proceed {
		t.Error("answer 'n' should return proceed=false")
	}
}

func TestRunChangeKey_answerEmpty(t *testing.T) {
	orig := runPTYFn
	t.Cleanup(func() { runPTYFn = orig })
	runPTYFn = func(_ *gossh.Client, _ string) error { return nil }

	origStdin := stdinReader
	t.Cleanup(func() { stdinReader = origStdin })
	stdinReader = strings.NewReader("\n")

	proceed, err := runChangeKey(nil, &config.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !proceed {
		t.Error("empty answer should return proceed=true (default yes)")
	}
}

// ── handleChangeAndUnlock seam tests ─────────────────────────────────────────

func TestHandleChangeAndUnlock_runChangeKeyError(t *testing.T) {
	origCK := runChangeKeyFn
	t.Cleanup(func() { runChangeKeyFn = origCK })
	runChangeKeyFn = func(_ *gossh.Client, _ *config.Config) (bool, error) {
		return false, errors.New("luksChangeKey boom")
	}

	client := makeTestClient(t)
	err := handleChangeAndUnlock(context.Background(), client, nil, netip.AddrPort{}, "", &config.Config{})
	if err == nil || !strings.Contains(err.Error(), "luksChangeKey boom") {
		t.Errorf("want luksChangeKey error, got %v", err)
	}
}

func TestHandleChangeAndUnlock_proceedFalse(t *testing.T) {
	origCK := runChangeKeyFn
	t.Cleanup(func() { runChangeKeyFn = origCK })
	runChangeKeyFn = func(_ *gossh.Client, _ *config.Config) (bool, error) {
		return false, nil
	}

	client := makeTestClient(t)
	err := handleChangeAndUnlock(context.Background(), client, nil, netip.AddrPort{}, "", &config.Config{})
	if err != nil {
		t.Errorf("proceed=false should return nil, got %v", err)
	}
}

func TestHandleChangeAndUnlock_reconnectError(t *testing.T) {
	origCK := runChangeKeyFn
	t.Cleanup(func() { runChangeKeyFn = origCK })
	runChangeKeyFn = func(_ *gossh.Client, _ *config.Config) (bool, error) { return true, nil }

	origDial := dialSSHFn
	t.Cleanup(func() { dialSSHFn = origDial })
	dialSSHFn = func(_ context.Context, _ *netstack.Net, _ netip.AddrPort, _ string, _ *config.Config) (*gossh.Client, error) {
		return nil, fmt.Errorf("reconnect dial boom")
	}

	client := makeTestClient(t)
	err := handleChangeAndUnlock(context.Background(), client, nil, netip.AddrPort{}, "", &config.Config{})
	if err == nil || !strings.Contains(err.Error(), "reconnect for unlock") {
		t.Errorf("want reconnect error, got %v", err)
	}
}

func TestHandleChangeAndUnlock_happyPath(t *testing.T) {
	origCK := runChangeKeyFn
	t.Cleanup(func() { runChangeKeyFn = origCK })
	runChangeKeyFn = func(_ *gossh.Client, _ *config.Config) (bool, error) { return true, nil }

	origDial := dialSSHFn
	t.Cleanup(func() { dialSSHFn = origDial })
	fakeNewClient := makeTestClient(t)
	dialSSHFn = func(_ context.Context, _ *netstack.Net, _ netip.AddrPort, _ string, _ *config.Config) (*gossh.Client, error) {
		return fakeNewClient, nil
	}

	origPTY := runPTYFn
	t.Cleanup(func() { runPTYFn = origPTY })
	runPTYFn = func(_ *gossh.Client, _ string) error { return nil }

	client := makeTestClient(t)
	err := handleChangeAndUnlock(context.Background(), client, nil, netip.AddrPort{}, "", &config.Config{})
	if err != nil {
		t.Errorf("happy path should return nil, got %v", err)
	}
}

// ── performUnlock seam tests ──────────────────────────────────────────────────

// ── changeKeyDirectSSH seam tests ────────────────────────────────────────────

func TestChangeKeyDirectSSH_connectError(t *testing.T) {
	origConn := remoteConnectFn
	t.Cleanup(func() { remoteConnectFn = origConn })
	remoteConnectFn = func(_ context.Context, _ *remote.ConnectOptions) (*remote.Client, error) {
		return nil, fmt.Errorf("connect boom")
	}

	err := changeKeyDirectSSH(context.Background(), &config.Config{}, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "connect boom") {
		t.Errorf("want connect error, got %v", err)
	}
}

func TestChangeKeyDirectSSH_happyPath(t *testing.T) {
	origConn := remoteConnectFn
	t.Cleanup(func() { remoteConnectFn = origConn })
	remoteConnectFn = func(_ context.Context, _ *remote.ConnectOptions) (*remote.Client, error) {
		return &remote.Client{}, nil
	}

	origInteract := remoteInteractFn
	t.Cleanup(func() { remoteInteractFn = origInteract })
	remoteInteractFn = func(_ *remote.Client, _ string) error { return nil }

	err := changeKeyDirectSSH(context.Background(), &config.Config{}, t.TempDir())
	if err != nil {
		t.Errorf("happy path should return nil, got %v", err)
	}
}

// ── performUnlock seam tests ──────────────────────────────────────────────────

func TestPerformUnlock_dialError(t *testing.T) {
	orig := dialSSHFn
	t.Cleanup(func() { dialSSHFn = orig })
	dialSSHFn = func(_ context.Context, _ *netstack.Net, _ netip.AddrPort, _ string, _ *config.Config) (*gossh.Client, error) {
		return nil, fmt.Errorf("dial boom")
	}

	err := performUnlock(context.Background(), nil, netip.AddrPort{}, "", &config.Config{}, false)
	if err == nil || !strings.Contains(err.Error(), "dial boom") {
		t.Errorf("want dial error, got %v", err)
	}
}
