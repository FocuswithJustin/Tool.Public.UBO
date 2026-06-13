package remote

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ----- fake ssh harness -----
//
// The package invokes the system ssh binary via exec.Command("ssh", ...). To
// test without a real server, each test installs a FAKE `ssh` executable as the
// first entry on PATH (via t.Setenv, which auto-restores). The fake is a small
// shell script whose behavior is driven by environment variables the test sets:
//
//	FAKE_SSH_ARGV   - file the fake appends each argv element to (one per line),
//	                  so tests can assert the ssh options/remote command used.
//	FAKE_SSH_STDIN  - file the fake copies its stdin to (used by WriteFile to
//	                  prove content was piped through).
//	FAKE_SSH_STDOUT - text the fake prints to stdout.
//	FAKE_SSH_STDERR - text the fake prints to stderr.
//	FAKE_SSH_EXIT   - exit status the fake returns (default 0).
//
// installFakeSSH writes the script into a temp dir, prepends it to PATH, and
// returns the argv-record path so the test can read back the exact arguments.
func installFakeSSH(t *testing.T) (argvFile string) {
	t.Helper()
	dir := t.TempDir()
	argvFile = filepath.Join(dir, "argv")
	script := `#!/bin/sh
for a in "$@"; do
  printf '%s\n' "$a" >> "$FAKE_SSH_ARGV"
done
if [ -n "$FAKE_SSH_STDIN" ]; then
  cat > "$FAKE_SSH_STDIN"
fi
if [ -n "$FAKE_SSH_STDOUT" ]; then
  printf '%s' "$FAKE_SSH_STDOUT"
fi
if [ -n "$FAKE_SSH_STDERR" ]; then
  printf '%s' "$FAKE_SSH_STDERR" >&2
fi
exit ${FAKE_SSH_EXIT:-0}
`
	sshPath := filepath.Join(dir, "ssh")
	if err := os.WriteFile(sshPath, []byte(script), 0755); err != nil {
		t.Fatalf("write fake ssh: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_SSH_ARGV", argvFile)
	// Clear any leftover controls so each test starts clean.
	t.Setenv("FAKE_SSH_STDIN", "")
	t.Setenv("FAKE_SSH_STDOUT", "")
	t.Setenv("FAKE_SSH_STDERR", "")
	t.Setenv("FAKE_SSH_EXIT", "")
	return argvFile
}

// readArgv returns the recorded argv elements (one per line).
func readArgv(t *testing.T, argvFile string) []string {
	t.Helper()
	data, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("read argv file: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	return lines
}

// argvContainsPair asserts that the argv slice contains the adjacent pair
// flag,value (e.g. "-p","2222").
func argvContainsPair(argv []string, flag, value string) bool {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == flag && argv[i+1] == value {
			return true
		}
	}
	return false
}

func argvContains(argv []string, want string) bool {
	for _, a := range argv {
		if a == want {
			return true
		}
	}
	return false
}

// writeTemp writes data under a fresh temp dir and returns the path.
func writeTemp(t *testing.T, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("write temp %s: %v", path, err)
	}
	return path
}

// validPinned writes a syntactically valid authorized_keys-format file.
func validPinned(t *testing.T) string {
	t.Helper()
	return writeTemp(t, "host_key.pub",
		[]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdefg comment here\n"), 0644)
}

// ----- knownHostsHostname -----

func TestKnownHostsHostname_Port22(t *testing.T) {
	if got := knownHostsHostname("example.com", 22); got != "example.com" {
		t.Fatalf("port 22 should be bare host, got %q", got)
	}
}

func TestKnownHostsHostname_NonDefaultPort(t *testing.T) {
	if got := knownHostsHostname("example.com", 2222); got != "[example.com]:2222" {
		t.Fatalf("non-22 port should be [host]:port, got %q", got)
	}
}

// ----- parseAuthorizedKey -----

func TestParseAuthorizedKey_Valid(t *testing.T) {
	kt, kd, err := parseAuthorizedKey([]byte("# a comment\n\nssh-ed25519 AAAAdata trailing comment\n"))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if kt != "ssh-ed25519" || kd != "AAAAdata" {
		t.Fatalf("got type=%q data=%q", kt, kd)
	}
}

func TestParseAuthorizedKey_Empty(t *testing.T) {
	if _, _, err := parseAuthorizedKey([]byte("\n   \n# only comments\n")); err == nil {
		t.Fatalf("expected error for no key")
	}
}

func TestParseAuthorizedKey_TooFewFields(t *testing.T) {
	if _, _, err := parseAuthorizedKey([]byte("ssh-ed25519\n")); err == nil ||
		!strings.Contains(err.Error(), "malformed") {
		t.Fatalf("expected malformed error, got %v", err)
	}
}

func TestParseAuthorizedKey_UnknownType(t *testing.T) {
	if _, _, err := parseAuthorizedKey([]byte("totally-bogus AAAAdata\n")); err == nil ||
		!strings.Contains(err.Error(), "unrecognized key type") {
		t.Fatalf("expected unrecognized type error, got %v", err)
	}
}

func TestParseAuthorizedKey_AcceptsEcdsaAndSk(t *testing.T) {
	if _, _, err := parseAuthorizedKey([]byte("ecdsa-sha2-nistp256 AAAAdata\n")); err != nil {
		t.Fatalf("ecdsa- prefix should be accepted: %v", err)
	}
	if _, _, err := parseAuthorizedKey([]byte("sk-ssh-ed25519@openssh.com AAAAdata\n")); err != nil {
		t.Fatalf("sk- prefix should be accepted: %v", err)
	}
}

// ----- Connect: validation -----

func TestConnect_NilOptions(t *testing.T) {
	if _, err := Connect(context.Background(), nil); err == nil {
		t.Fatalf("expected error for nil options")
	}
}

func TestConnect_MissingHost(t *testing.T) {
	_, err := Connect(context.Background(), &ConnectOptions{User: "u", Port: 22, KnownHostsPath: "/tmp/kh"})
	if err == nil || !strings.Contains(err.Error(), "host is required") {
		t.Fatalf("expected host required, got %v", err)
	}
}

func TestConnect_MissingUser(t *testing.T) {
	_, err := Connect(context.Background(), &ConnectOptions{Host: "h", Port: 22, KnownHostsPath: "/tmp/kh"})
	if err == nil || !strings.Contains(err.Error(), "user is required") {
		t.Fatalf("expected user required, got %v", err)
	}
}

func TestConnect_InvalidPort(t *testing.T) {
	_, err := Connect(context.Background(), &ConnectOptions{Host: "h", User: "u", Port: 0, KnownHostsPath: "/tmp/kh"})
	if err == nil || !strings.Contains(err.Error(), "invalid port") {
		t.Fatalf("expected invalid port, got %v", err)
	}
}

func TestConnect_BothModesSet(t *testing.T) {
	_, err := Connect(context.Background(), &ConnectOptions{
		Host: "h", User: "u", Port: 22,
		KnownHostsPath: "/tmp/kh", PinnedKeyPath: validPinned(t),
	})
	if err == nil || !strings.Contains(err.Error(), "only one of") {
		t.Fatalf("expected only-one error, got %v", err)
	}
}

func TestConnect_NoMode(t *testing.T) {
	_, err := Connect(context.Background(), &ConnectOptions{Host: "h", User: "u", Port: 22})
	if err == nil || !strings.Contains(err.Error(), "set one of") {
		t.Fatalf("expected set-one-of error, got %v", err)
	}
}

// ----- Connect: TOFU mode -----

func TestConnect_TOFU(t *testing.T) {
	kh := filepath.Join(t.TempDir(), "known_hosts")
	c, err := Connect(context.Background(), &ConnectOptions{
		Host: "h", User: "u", Port: 22, KnownHostsPath: kh,
	})
	if err != nil {
		t.Fatalf("connect TOFU: %v", err)
	}
	if c.strictMode != "accept-new" {
		t.Fatalf("expected accept-new, got %q", c.strictMode)
	}
	if c.knownHostsFile != kh {
		t.Fatalf("expected known hosts %q, got %q", kh, c.knownHostsFile)
	}
	if c.tempKnownHosts != "" {
		t.Fatalf("TOFU must not create a temp known_hosts file")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// ----- Connect: pinned mode -----

func TestConnect_PinnedMaterializesKnownHosts(t *testing.T) {
	pinned := validPinned(t)
	c, err := Connect(context.Background(), &ConnectOptions{
		Host: "h", User: "u", Port: 2222, PinnedKeyPath: pinned,
	})
	if err != nil {
		t.Fatalf("connect pinned: %v", err)
	}
	if c.strictMode != "yes" {
		t.Fatalf("expected strict yes, got %q", c.strictMode)
	}
	want := pinned + ".known_hosts"
	if c.knownHostsFile != want || c.tempKnownHosts != want {
		t.Fatalf("expected known hosts %q, got file=%q temp=%q", want, c.knownHostsFile, c.tempKnownHosts)
	}
	data, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("read materialized known_hosts: %v", err)
	}
	// Non-default port -> [host]:port format.
	if !strings.HasPrefix(string(data), "[h]:2222 ssh-ed25519 AAAAC3") {
		t.Fatalf("unexpected known_hosts line: %q", string(data))
	}
}

func TestConnect_PinnedPort22Format(t *testing.T) {
	pinned := validPinned(t)
	c, err := Connect(context.Background(), &ConnectOptions{
		Host: "h", User: "u", Port: 22, PinnedKeyPath: pinned,
	})
	if err != nil {
		t.Fatalf("connect pinned: %v", err)
	}
	defer c.Close()
	data, err := os.ReadFile(c.knownHostsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "h ssh-ed25519 ") {
		t.Fatalf("port 22 should use bare host, got %q", string(data))
	}
}

func TestConnect_PinnedMissing(t *testing.T) {
	_, err := Connect(context.Background(), &ConnectOptions{
		Host: "h", User: "u", Port: 22, PinnedKeyPath: filepath.Join(t.TempDir(), "nope"),
	})
	if err == nil || !strings.Contains(err.Error(), "read pinned host key") {
		t.Fatalf("expected read error, got %v", err)
	}
}

func TestConnect_PinnedUnparseable(t *testing.T) {
	bad := writeTemp(t, "bad.pub", []byte("not-a-key\n"), 0644)
	_, err := Connect(context.Background(), &ConnectOptions{
		Host: "h", User: "u", Port: 22, PinnedKeyPath: bad,
	})
	if err == nil || !strings.Contains(err.Error(), "parse pinned host key") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestConnect_PinnedWriteFailure(t *testing.T) {
	// Place the pinned file inside a directory we then make read-only so the
	// sibling ".known_hosts" cannot be written.
	dir := t.TempDir()
	pinned := filepath.Join(dir, "host_key.pub")
	if err := os.WriteFile(pinned, []byte("ssh-ed25519 AAAAdata\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })
	_, err := Connect(context.Background(), &ConnectOptions{
		Host: "h", User: "u", Port: 22, PinnedKeyPath: pinned,
	})
	if err == nil || !strings.Contains(err.Error(), "write known_hosts") {
		// On some filesystems/uid-0 the chmod won't deny writes; skip then.
		if os.Geteuid() == 0 {
			t.Skip("running as root: directory permissions do not deny writes")
		}
		t.Fatalf("expected write known_hosts error, got %v", err)
	}
}

// ----- sshArgs -----

func TestSSHArgs_TOFUWithKey(t *testing.T) {
	kh := filepath.Join(t.TempDir(), "kh")
	key := writeTemp(t, "id", []byte("k"), 0600)
	c, err := Connect(context.Background(), &ConnectOptions{
		Host: "host", User: "bob", Port: 2222, KeyPath: key, KnownHostsPath: kh,
	})
	if err != nil {
		t.Fatal(err)
	}
	args := c.sshArgs()
	if !argvContainsPair(args, "-p", "2222") {
		t.Fatalf("missing -p 2222 in %v", args)
	}
	if !argvContainsPair(args, "-i", key) {
		t.Fatalf("missing -i key in %v", args)
	}
	if !argvContains(args, "BatchMode=yes") || !argvContains(args, "ConnectTimeout=30") {
		t.Fatalf("missing batch/timeout opts in %v", args)
	}
	if !argvContains(args, "UserKnownHostsFile="+kh) {
		t.Fatalf("missing UserKnownHostsFile in %v", args)
	}
	if !argvContains(args, "StrictHostKeyChecking=accept-new") {
		t.Fatalf("missing accept-new in %v", args)
	}
	if args[len(args)-1] != "bob@host" {
		t.Fatalf("expected user@host last, got %q", args[len(args)-1])
	}
}

func TestSSHArgs_PinnedStrictYesNoKey(t *testing.T) {
	pinned := validPinned(t)
	c, err := Connect(context.Background(), &ConnectOptions{
		Host: "host", User: "root", Port: 22, PinnedKeyPath: pinned,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	args := c.sshArgs()
	if !argvContains(args, "StrictHostKeyChecking=yes") {
		t.Fatalf("expected strict yes in %v", args)
	}
	if argvContains(args, "-i") {
		t.Fatalf("no key was set; -i should be absent in %v", args)
	}
}

// ----- RunCommand -----

func newTOFUClient(t *testing.T) *Client {
	t.Helper()
	kh := filepath.Join(t.TempDir(), "kh")
	c, err := Connect(context.Background(), &ConnectOptions{
		Host: "host", User: "u", Port: 22, KnownHostsPath: kh,
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return c
}

func TestRunCommand_Success(t *testing.T) {
	argv := installFakeSSH(t)
	t.Setenv("FAKE_SSH_STDOUT", "hello world\n")
	c := newTOFUClient(t)
	out, err := RunCommand(context.Background(), c, "echo hi")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out != "hello world" {
		t.Fatalf("expected trimmed output, got %q", out)
	}
	args := readArgv(t, argv)
	if args[len(args)-1] != "echo hi" {
		t.Fatalf("remote command should be last arg, got %q", args[len(args)-1])
	}
}

func TestRunCommand_NonZeroExit(t *testing.T) {
	installFakeSSH(t)
	t.Setenv("FAKE_SSH_STDERR", "boom\n")
	t.Setenv("FAKE_SSH_EXIT", "3")
	c := newTOFUClient(t)
	out, err := RunCommand(context.Background(), c, "false")
	if err == nil || !strings.Contains(err.Error(), "remote command failed") {
		t.Fatalf("expected failure, got %v", err)
	}
	if out != "boom" {
		t.Fatalf("expected captured 'boom', got %q", out)
	}
}

// ----- WriteFile / WriteFileExec -----

func TestWriteFile_PipesStdinAndChmod(t *testing.T) {
	argv := installFakeSSH(t)
	stdinFile := filepath.Join(t.TempDir(), "stdin")
	t.Setenv("FAKE_SSH_STDIN", stdinFile)
	c := newTOFUClient(t)

	content := "the quick brown fox"
	if err := WriteFile(c, "/etc/dropbear/file", content, 0640); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(stdinFile)
	if err != nil {
		t.Fatalf("read piped stdin: %v", err)
	}
	if string(got) != content {
		t.Fatalf("stdin content mismatch: %q", string(got))
	}
	args := readArgv(t, argv)
	remoteCmd := args[len(args)-1]
	if !strings.Contains(remoteCmd, "mkdir -p '/etc/dropbear'") {
		t.Fatalf("missing mkdir in remote cmd: %q", remoteCmd)
	}
	if !strings.Contains(remoteCmd, "cat > '/etc/dropbear/file'") {
		t.Fatalf("missing cat redirect in remote cmd: %q", remoteCmd)
	}
	if !strings.Contains(remoteCmd, "chmod 640 '/etc/dropbear/file'") {
		t.Fatalf("expected octal mode 640 in remote cmd: %q", remoteCmd)
	}
}

func TestWriteFile_NonZeroExit(t *testing.T) {
	installFakeSSH(t)
	t.Setenv("FAKE_SSH_STDIN", filepath.Join(t.TempDir(), "stdin"))
	t.Setenv("FAKE_SSH_STDERR", "permission denied\n")
	t.Setenv("FAKE_SSH_EXIT", "1")
	c := newTOFUClient(t)
	err := WriteFile(c, "/root/x", "data", 0644)
	if err == nil || !strings.Contains(err.Error(), "write /root/x") {
		t.Fatalf("expected write error, got %v", err)
	}
}

func TestWriteFileExec_Mode0755(t *testing.T) {
	argv := installFakeSSH(t)
	t.Setenv("FAKE_SSH_STDIN", filepath.Join(t.TempDir(), "stdin"))
	c := newTOFUClient(t)
	if err := WriteFileExec(c, "/usr/local/bin/x", "#!/bin/sh\n"); err != nil {
		t.Fatalf("write exec: %v", err)
	}
	args := readArgv(t, argv)
	if !strings.Contains(args[len(args)-1], "chmod 755 ") {
		t.Fatalf("expected chmod 755, got %q", args[len(args)-1])
	}
}

// ----- ReadFile -----

func TestReadFile_Success(t *testing.T) {
	argv := installFakeSSH(t)
	// Content with trailing newline must be returned faithfully (no trimming).
	t.Setenv("FAKE_SSH_STDOUT", "line1\nline2\n")
	c := newTOFUClient(t)
	got, err := ReadFile(c, "/etc/hostname")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != "line1\nline2\n" {
		t.Fatalf("ReadFile must not trim, got %q", got)
	}
	args := readArgv(t, argv)
	if args[len(args)-1] != "cat '/etc/hostname'" {
		t.Fatalf("unexpected remote cmd %q", args[len(args)-1])
	}
}

func TestReadFile_Error(t *testing.T) {
	installFakeSSH(t)
	t.Setenv("FAKE_SSH_STDERR", "No such file\n")
	t.Setenv("FAKE_SSH_EXIT", "1")
	c := newTOFUClient(t)
	_, err := ReadFile(c, "/nope")
	if err == nil || !strings.Contains(err.Error(), "open /nope") {
		t.Fatalf("expected open error, got %v", err)
	}
	if !strings.Contains(err.Error(), "No such file") {
		t.Fatalf("expected stderr captured, got %v", err)
	}
}

// ----- InteractiveSession -----

func TestInteractiveSession_Success(t *testing.T) {
	argv := installFakeSSH(t)
	c := newTOFUClient(t)
	if err := InteractiveSession(c, "cryptroot-unlock"); err != nil {
		t.Fatalf("interactive success: %v", err)
	}
	args := readArgv(t, argv)
	if !argvContains(args, "-t") {
		t.Fatalf("expected -t (force PTY) in %v", args)
	}
	if !argvContains(args, "LogLevel=ERROR") {
		t.Fatalf("expected LogLevel=ERROR in %v", args)
	}
	if args[len(args)-1] != "cryptroot-unlock" {
		t.Fatalf("expected remote cmd last, got %q", args[len(args)-1])
	}
}

func TestInteractiveSession_Failure(t *testing.T) {
	installFakeSSH(t)
	t.Setenv("FAKE_SSH_EXIT", "1")
	c := newTOFUClient(t)
	if err := InteractiveSession(c, "exit 1"); err == nil ||
		!strings.Contains(err.Error(), "remote session") {
		t.Fatalf("expected remote session error, got %v", err)
	}
}

// ----- Close -----

func TestClose_RemovesTempKnownHosts(t *testing.T) {
	pinned := validPinned(t)
	c, err := Connect(context.Background(), &ConnectOptions{
		Host: "h", User: "u", Port: 22, PinnedKeyPath: pinned,
	})
	if err != nil {
		t.Fatal(err)
	}
	kh := c.knownHostsFile
	if _, err := os.Stat(kh); err != nil {
		t.Fatalf("known_hosts should exist before close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := os.Stat(kh); !os.IsNotExist(err) {
		t.Fatalf("known_hosts should be removed after close, stat err=%v", err)
	}
	// Second Close is a no-op.
	if err := c.Close(); err != nil {
		t.Fatalf("second close should be no-op: %v", err)
	}
}

func TestClose_RemoveError(t *testing.T) {
	// Point tempKnownHosts at a non-empty directory: os.Remove returns a
	// non-IsNotExist error, exercising the error branch of Close.
	c := &Client{tempKnownHosts: t.TempDir()}
	if err := os.WriteFile(filepath.Join(c.tempKnownHosts, "child"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err == nil || !strings.Contains(err.Error(), "remove temp known_hosts") {
		t.Fatalf("expected remove error, got %v", err)
	}
}

func TestClose_TOFUNoOp(t *testing.T) {
	c := newTOFUClient(t)
	if err := c.Close(); err != nil {
		t.Fatalf("TOFU close should be no-op: %v", err)
	}
}

func TestClose_RemoveErrorWhenAlreadyGone(t *testing.T) {
	// If the temp file was already removed externally, Close treats IsNotExist
	// as success (covered) — remove manually then Close.
	pinned := validPinned(t)
	c, err := Connect(context.Background(), &ConnectOptions{
		Host: "h", User: "u", Port: 22, PinnedKeyPath: pinned,
	})
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(c.knownHostsFile)
	if err := c.Close(); err != nil {
		t.Fatalf("close should ignore already-removed file: %v", err)
	}
}
