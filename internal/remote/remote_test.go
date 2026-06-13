package remote

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// writeTemp writes data to a file named name under a fresh temp dir and returns
// the path.
func writeTemp(t *testing.T, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("write temp %s: %v", path, err)
	}
	return path
}

// authorizedKeyFile writes the public key of signer in authorized_keys format
// and returns the path.
func authorizedKeyFile(t *testing.T, signer ssh.Signer) string {
	t.Helper()
	line := ssh.MarshalAuthorizedKey(signer.PublicKey())
	return writeTemp(t, "host_key.pub", line, 0644)
}

// isolateEnv points HOME at an empty temp dir and clears SSH_AUTH_SOCK so that
// buildAuthMethods sees no agent and no default keys.
func isolateEnv(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSH_AUTH_SOCK", "")
}

// ----- buildAuthMethods -----

func TestBuildAuthMethods_ExplicitValidKey(t *testing.T) {
	_, keyPath := writeKeyPair(t)
	auths, err := buildAuthMethods(keyPath)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(auths) != 1 {
		t.Fatalf("expected 1 auth method, got %d", len(auths))
	}
}

func TestBuildAuthMethods_ExplicitMissingKey(t *testing.T) {
	_, err := buildAuthMethods(filepath.Join(t.TempDir(), "nope"))
	if err == nil || !strings.Contains(err.Error(), "read SSH key") {
		t.Fatalf("expected read error, got %v", err)
	}
}

func TestBuildAuthMethods_ExplicitUnparseableKey(t *testing.T) {
	bad := writeTemp(t, "bad", []byte("not a private key"), 0600)
	_, err := buildAuthMethods(bad)
	if err == nil || !strings.Contains(err.Error(), "parse SSH key") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestBuildAuthMethods_NoKeysNoAgent(t *testing.T) {
	isolateEnv(t)
	auths, err := buildAuthMethods("")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(auths) != 0 {
		t.Fatalf("expected 0 auth methods, got %d", len(auths))
	}
}

func TestBuildAuthMethods_DefaultKeyPicked(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	// Write a valid default key at ~/.ssh/id_ed25519.
	_, keyPath := writeKeyPair(t)
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519"), data, 0600); err != nil {
		t.Fatal(err)
	}
	auths, err := buildAuthMethods("")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(auths) != 1 {
		t.Fatalf("expected 1 default-key auth method, got %d", len(auths))
	}
}

func TestBuildAuthMethods_DefaultKeyUnparseableSkipped(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Corrupt default key file is silently skipped (continue branch).
	if err := os.WriteFile(filepath.Join(sshDir, "id_rsa"), []byte("garbage"), 0600); err != nil {
		t.Fatal(err)
	}
	auths, err := buildAuthMethods("")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(auths) != 0 {
		t.Fatalf("expected 0 auth methods (corrupt key skipped), got %d", len(auths))
	}
}

func TestBuildAuthMethods_AgentDialFailure(t *testing.T) {
	// SSH_AUTH_SOCK points at a non-existent socket: net.Dial fails, branch
	// taken but no method added.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(t.TempDir(), "agent.sock"))
	auths, err := buildAuthMethods("")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(auths) != 0 {
		t.Fatalf("expected 0 auth methods, got %d", len(auths))
	}
}

func TestBuildAuthMethods_AgentDialSuccess(t *testing.T) {
	// A live unix socket: net.Dial succeeds, so the agent callback method is
	// appended (covering the success branch of the agent block).
	// Use a short socket path: unix socket paths are limited to ~108 bytes,
	// and nix-shell's TMPDIR is too deep, so place it under os.TempDir() with a
	// minimal name and clean it up explicitly.
	sock := filepath.Join(os.TempDir(), "ubo-agent-test.sock")
	os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix socket unavailable: %v", err)
	}
	t.Cleanup(func() { os.Remove(sock) })
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSH_AUTH_SOCK", sock)
	auths, err := buildAuthMethods("")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(auths) != 1 {
		t.Fatalf("expected 1 agent auth method, got %d", len(auths))
	}
}

// ----- buildHostKeyCallback -----

func TestBuildHostKeyCallback_PinnedValid(t *testing.T) {
	signer := genSigner(t)
	pinned := authorizedKeyFile(t, signer)
	cb, err := buildHostKeyCallback(&ConnectOptions{PinnedKeyPath: pinned})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := cb("host", &net.TCPAddr{}, signer.PublicKey()); err != nil {
		t.Fatalf("matching pinned key should pass: %v", err)
	}
	// A different key must fail.
	other := genSigner(t)
	if err := cb("host", &net.TCPAddr{}, other.PublicKey()); err == nil {
		t.Fatalf("mismatched pinned key should fail")
	}
}

func TestBuildHostKeyCallback_PinnedMissing(t *testing.T) {
	_, err := buildHostKeyCallback(&ConnectOptions{PinnedKeyPath: filepath.Join(t.TempDir(), "nope")})
	if err == nil || !strings.Contains(err.Error(), "read pinned host key") {
		t.Fatalf("expected read error, got %v", err)
	}
}

func TestBuildHostKeyCallback_PinnedUnparseable(t *testing.T) {
	bad := writeTemp(t, "bad.pub", []byte("not-a-key"), 0644)
	_, err := buildHostKeyCallback(&ConnectOptions{PinnedKeyPath: bad})
	if err == nil || !strings.Contains(err.Error(), "parse pinned host key") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestBuildHostKeyCallback_KnownHostsTOFU(t *testing.T) {
	khPath := filepath.Join(t.TempDir(), "known_hosts")
	cb, err := buildHostKeyCallback(&ConnectOptions{KnownHostsPath: khPath})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if cb == nil {
		t.Fatalf("expected non-nil callback")
	}
}

func TestBuildHostKeyCallback_InsecureFallback(t *testing.T) {
	cb, err := buildHostKeyCallback(&ConnectOptions{})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	// Fallback accepts any key.
	if err := cb("host", &net.TCPAddr{}, genSigner(t).PublicKey()); err != nil {
		t.Fatalf("insecure fallback should accept any key: %v", err)
	}
}

// ----- toFUCallback -----

func TestTOFUCallback_FirstConnectionSaves(t *testing.T) {
	savePath := filepath.Join(t.TempDir(), "known_hosts")
	cb := toFUCallback(savePath)
	signer := genSigner(t)
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}
	if err := cb("127.0.0.1:22", addr, signer.PublicKey()); err != nil {
		t.Fatalf("first connection should save and pass: %v", err)
	}
	if _, err := os.Stat(savePath); err != nil {
		t.Fatalf("known_hosts not saved: %v", err)
	}
	// Second connection with the SAME key passes.
	if err := cb("127.0.0.1:22", addr, signer.PublicKey()); err != nil {
		t.Fatalf("second connection same key should pass: %v", err)
	}
}

func TestTOFUCallback_MismatchFails(t *testing.T) {
	savePath := filepath.Join(t.TempDir(), "known_hosts")
	cb := toFUCallback(savePath)
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}
	first := genSigner(t)
	if err := cb("127.0.0.1:22", addr, first.PublicKey()); err != nil {
		t.Fatalf("first connection should pass: %v", err)
	}
	// A different key on the same host must fail.
	second := genSigner(t)
	if err := cb("127.0.0.1:22", addr, second.PublicKey()); err == nil {
		t.Fatalf("mismatched key should fail")
	}
}

func TestTOFUCallback_CorruptKnownHosts(t *testing.T) {
	// An existing but unparseable known_hosts file makes knownhosts.New error.
	savePath := writeTemp(t, "known_hosts", []byte("@@@ totally broken line\n"), 0600)
	cb := toFUCallback(savePath)
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}
	err := cb("127.0.0.1:22", addr, genSigner(t).PublicKey())
	if err == nil {
		t.Fatalf("expected error from corrupt known_hosts")
	}
}

func TestTOFUCallback_SaveFailure(t *testing.T) {
	// savePath whose parent does not exist -> os.WriteFile fails.
	savePath := filepath.Join(t.TempDir(), "missing-dir", "known_hosts")
	cb := toFUCallback(savePath)
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}
	err := cb("127.0.0.1:22", addr, genSigner(t).PublicKey())
	if err == nil || !strings.Contains(err.Error(), "save host key") {
		t.Fatalf("expected save host key error, got %v", err)
	}
}

// ----- Connect / RunCommand / WriteFile / ReadFile / InteractiveSession -----

// newConnectedClient starts a server authorizing clientSigner and returns a
// connected *ssh.Client plus the server.
func newConnectedClient(t *testing.T) (*ssh.Client, *testServer) {
	t.Helper()
	clientSigner, clientKeyPath := writeKeyPair(t)
	rootDir := t.TempDir()
	srv := newTestServer(t, clientSigner.PublicKey(), rootDir)
	pinned := authorizedKeyFile(t, srv.hostSigner)

	ctx := context.Background()
	client, err := Connect(ctx, &ConnectOptions{
		Host:          srv.host(),
		Port:          srv.port(),
		User:          "tester",
		KeyPath:       clientKeyPath,
		PinnedKeyPath: pinned,
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client, srv
}

func TestConnect_SuccessPinned(t *testing.T) {
	client, _ := newConnectedClient(t)
	if client == nil {
		t.Fatalf("expected client")
	}
}

func TestConnect_SuccessTOFU(t *testing.T) {
	clientSigner, clientKeyPath := writeKeyPair(t)
	srv := newTestServer(t, clientSigner.PublicKey(), t.TempDir())
	khPath := filepath.Join(t.TempDir(), "known_hosts")

	client, err := Connect(context.Background(), &ConnectOptions{
		Host:           srv.host(),
		Port:           srv.port(),
		User:           "tester",
		KeyPath:        clientKeyPath,
		KnownHostsPath: khPath,
	})
	if err != nil {
		t.Fatalf("connect TOFU: %v", err)
	}
	defer client.Close()
	if _, err := os.Stat(khPath); err != nil {
		t.Fatalf("TOFU did not save known_hosts: %v", err)
	}
}

func TestConnect_AuthMethodError(t *testing.T) {
	// An unparseable KeyPath makes buildAuthMethods return an error, covering
	// the first error branch of Connect.
	bad := writeTemp(t, "bad", []byte("not a key"), 0600)
	_, err := Connect(context.Background(), &ConnectOptions{
		Host: "127.0.0.1", Port: 1, User: "x", KeyPath: bad,
	})
	if err == nil || !strings.Contains(err.Error(), "parse SSH key") {
		t.Fatalf("expected parse SSH key error, got %v", err)
	}
}

func TestConnect_NoAuthMethods(t *testing.T) {
	isolateEnv(t)
	_, err := Connect(context.Background(), &ConnectOptions{
		Host: "127.0.0.1", Port: 1, User: "x",
	})
	if err == nil || !strings.Contains(err.Error(), "no SSH auth methods") {
		t.Fatalf("expected no-auth error, got %v", err)
	}
}

func TestConnect_BadHostKeyCallback(t *testing.T) {
	_, clientKeyPath := writeKeyPair(t)
	_, err := Connect(context.Background(), &ConnectOptions{
		Host: "127.0.0.1", Port: 1, User: "x",
		KeyPath:       clientKeyPath,
		PinnedKeyPath: filepath.Join(t.TempDir(), "nope"),
	})
	if err == nil || !strings.Contains(err.Error(), "read pinned host key") {
		t.Fatalf("expected host key callback error, got %v", err)
	}
}

func TestConnect_DialFailure(t *testing.T) {
	_, clientKeyPath := writeKeyPair(t)
	// Reserve a port then close it so the dial is refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	_, err = Connect(context.Background(), &ConnectOptions{
		Host: "127.0.0.1", Port: port, User: "x",
		KeyPath: clientKeyPath,
	})
	if err == nil || !strings.Contains(err.Error(), "connect to") {
		t.Fatalf("expected dial error, got %v", err)
	}
}

func TestConnect_HandshakeFailureWrongKey(t *testing.T) {
	// Server authorizes a DIFFERENT key than the client presents.
	authorizedSigner := genSigner(t)
	srv := newTestServer(t, authorizedSigner.PublicKey(), t.TempDir())
	_, wrongKeyPath := writeKeyPair(t)
	pinned := authorizedKeyFile(t, srv.hostSigner)

	_, err := Connect(context.Background(), &ConnectOptions{
		Host: srv.host(), Port: srv.port(), User: "tester",
		KeyPath:       wrongKeyPath,
		PinnedKeyPath: pinned,
	})
	if err == nil || !strings.Contains(err.Error(), "SSH handshake") {
		t.Fatalf("expected handshake error, got %v", err)
	}
}

func TestRunCommand_Success(t *testing.T) {
	client, _ := newConnectedClient(t)
	out, err := RunCommand(context.Background(), client, "echo hello world")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out != "hello world" {
		t.Fatalf("unexpected output %q", out)
	}
}

func TestRunCommand_FailureReturnsOutput(t *testing.T) {
	client, _ := newConnectedClient(t)
	out, err := RunCommand(context.Background(), client, "echo boom >&2; exit 3")
	if err == nil {
		t.Fatalf("expected command failure")
	}
	if !strings.Contains(err.Error(), "remote command failed") {
		t.Fatalf("unexpected error %v", err)
	}
	if out != "boom" {
		t.Fatalf("expected captured stderr 'boom', got %q", out)
	}
}

func TestRunCommand_ContextCancel(t *testing.T) {
	client, _ := newConnectedClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel almost immediately while a long command runs; the goroutine should
	// close the session and the command should error out.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_, err := RunCommand(ctx, client, "sleep 5")
	if err == nil {
		t.Fatalf("expected error from cancelled context")
	}
}

func TestRunCommand_NewSessionFailure(t *testing.T) {
	client, _ := newConnectedClient(t)
	client.Close() // closing underlying conn makes NewSession fail
	_, err := RunCommand(context.Background(), client, "echo hi")
	if err == nil || !strings.Contains(err.Error(), "new SSH session") {
		t.Fatalf("expected new session error, got %v", err)
	}
}

func TestWriteReadFile_RoundTrip(t *testing.T) {
	client, srv := newConnectedClient(t)
	remotePath := filepath.Join(srv.rootDir, "sub", "dir", "file.txt")
	content := "the quick brown fox"

	if err := WriteFile(client, remotePath, content, 0640); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Parent dirs created, content present, mode applied.
	info, err := os.Stat(remotePath)
	if err != nil {
		t.Fatalf("stat written file: %v", err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("expected mode 0640, got %o", info.Mode().Perm())
	}
	got, err := ReadFile(client, remotePath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != content {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestWriteFileExec_Mode0755(t *testing.T) {
	client, srv := newConnectedClient(t)
	remotePath := filepath.Join(srv.rootDir, "script.sh")
	if err := WriteFileExec(client, remotePath, "#!/bin/sh\ntrue\n"); err != nil {
		t.Fatalf("write exec: %v", err)
	}
	info, err := os.Stat(remotePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("expected 0755, got %o", info.Mode().Perm())
	}
}

func TestWriteFile_MkdirFailure(t *testing.T) {
	client, srv := newConnectedClient(t)
	// Create a regular file, then try to write under it as if it were a dir.
	blocker := filepath.Join(srv.rootDir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	remotePath := filepath.Join(blocker, "child", "file.txt")
	err := WriteFile(client, remotePath, "data", 0644)
	if err == nil {
		t.Fatalf("expected mkdir failure under a file")
	}
	if !strings.Contains(err.Error(), "mkdir") && !strings.Contains(err.Error(), "open") {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestWriteFile_OpenFailure(t *testing.T) {
	client, srv := newConnectedClient(t)
	// Make remotePath an existing directory; MkdirAll(parent) succeeds but
	// OpenFile(O_WRONLY) on a directory fails, covering the open error branch.
	remotePath := filepath.Join(srv.rootDir, "iam-a-dir")
	if err := os.Mkdir(remotePath, 0755); err != nil {
		t.Fatal(err)
	}
	err := WriteFile(client, remotePath, "data", 0644)
	if err == nil || !strings.Contains(err.Error(), "open") {
		t.Fatalf("expected open error writing to a directory, got %v", err)
	}
}

func TestReadFile_OpenFailure(t *testing.T) {
	client, srv := newConnectedClient(t)
	_, err := ReadFile(client, filepath.Join(srv.rootDir, "does-not-exist"))
	if err == nil || !strings.Contains(err.Error(), "open") {
		t.Fatalf("expected open error, got %v", err)
	}
}

func TestWriteFile_SFTPDenied(t *testing.T) {
	clientSigner, clientKeyPath := writeKeyPair(t)
	srv := newTestServer(t, clientSigner.PublicKey(), t.TempDir())
	srv.denySFTP = true
	pinned := authorizedKeyFile(t, srv.hostSigner)
	client, err := Connect(context.Background(), &ConnectOptions{
		Host: srv.host(), Port: srv.port(), User: "tester",
		KeyPath: clientKeyPath, PinnedKeyPath: pinned,
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()
	err = WriteFile(client, filepath.Join(srv.rootDir, "f"), "x", 0644)
	if err == nil || !strings.Contains(err.Error(), "SFTP open") {
		t.Fatalf("expected SFTP open error, got %v", err)
	}
	if _, err := ReadFile(client, filepath.Join(srv.rootDir, "f")); err == nil ||
		!strings.Contains(err.Error(), "SFTP open") {
		t.Fatalf("expected SFTP open error on ReadFile, got %v", err)
	}
}

// connectFaultySFTP connects a client to a server whose SFTP subsystem injects
// the named fault.
func connectFaultySFTP(t *testing.T, fault string) (*ssh.Client, *testServer) {
	t.Helper()
	clientSigner, clientKeyPath := writeKeyPair(t)
	srv := newTestServer(t, clientSigner.PublicKey(), t.TempDir())
	srv.sftpFault = fault
	pinned := authorizedKeyFile(t, srv.hostSigner)
	client, err := Connect(context.Background(), &ConnectOptions{
		Host: srv.host(), Port: srv.port(), User: "tester",
		KeyPath: clientKeyPath, PinnedKeyPath: pinned,
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client, srv
}

func TestWriteFile_WriteFailure(t *testing.T) {
	client, srv := connectFaultySFTP(t, "write")
	err := WriteFile(client, filepath.Join(srv.rootDir, "f.txt"), "data", 0644)
	if err == nil || !strings.Contains(err.Error(), "write") {
		t.Fatalf("expected write error, got %v", err)
	}
}

func TestWriteFile_ChmodFailure(t *testing.T) {
	client, srv := connectFaultySFTP(t, "setstat")
	err := WriteFile(client, filepath.Join(srv.rootDir, "f.txt"), "data", 0644)
	if err == nil || !strings.Contains(err.Error(), "chmod") {
		t.Fatalf("expected chmod error, got %v", err)
	}
}

func TestReadFile_ReadFailure(t *testing.T) {
	client, srv := connectFaultySFTP(t, "read")
	_, err := ReadFile(client, filepath.Join(srv.rootDir, "f.txt"))
	if err == nil || !strings.Contains(err.Error(), "read") {
		t.Fatalf("expected read error, got %v", err)
	}
}

func TestInteractiveSession_Success(t *testing.T) {
	client, _ := newConnectedClient(t)
	if err := InteractiveSession(client, "true"); err != nil {
		t.Fatalf("interactive 'true' should succeed: %v", err)
	}
}

func TestInteractiveSession_CommandFails(t *testing.T) {
	client, _ := newConnectedClient(t)
	if err := InteractiveSession(client, "exit 1"); err == nil {
		t.Fatalf("expected non-zero exit to error")
	}
}

func TestInteractiveSession_NewSessionFailure(t *testing.T) {
	client, _ := newConnectedClient(t)
	client.Close()
	if err := InteractiveSession(client, "true"); err == nil ||
		!strings.Contains(err.Error(), "new SSH session") {
		t.Fatalf("expected new session error, got %v", err)
	}
}

func TestInteractiveSession_RequestPtyFails(t *testing.T) {
	clientSigner, clientKeyPath := writeKeyPair(t)
	srv := newTestServer(t, clientSigner.PublicKey(), t.TempDir())
	srv.denyPTY = true
	pinned := authorizedKeyFile(t, srv.hostSigner)
	client, err := Connect(context.Background(), &ConnectOptions{
		Host: srv.host(), Port: srv.port(), User: "tester",
		KeyPath: clientKeyPath, PinnedKeyPath: pinned,
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()
	// NewSession succeeds but RequestPty is rejected by the server.
	if err := InteractiveSession(client, "true"); err == nil ||
		!strings.Contains(err.Error(), "request PTY") {
		t.Fatalf("expected request PTY error, got %v", err)
	}
}

func TestInteractiveSession_PTYDenied(t *testing.T) {
	clientSigner, clientKeyPath := writeKeyPair(t)
	srv := newTestServer(t, clientSigner.PublicKey(), t.TempDir())
	srv.denySession = true
	pinned := authorizedKeyFile(t, srv.hostSigner)
	client, err := Connect(context.Background(), &ConnectOptions{
		Host: srv.host(), Port: srv.port(), User: "tester",
		KeyPath: clientKeyPath, PinnedKeyPath: pinned,
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()
	// Session channels are rejected, so NewSession itself fails.
	if err := InteractiveSession(client, "true"); err == nil {
		t.Fatalf("expected error when sessions are denied")
	}
}
