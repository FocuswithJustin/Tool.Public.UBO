package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ubo/internal/config"
	"ubo/internal/keygen"
	"ubo/internal/remote"
)

// errBoom is a generic failure used to drive seamed error branches.
var errBoom = errors.New("boom")

// captureStdout swaps os.Stdout for a pipe, runs fn, and returns everything
// written to stdout. It always restores os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- sb.String()
	}()
	fn()
	w.Close()
	os.Stdout = orig
	out := <-done
	r.Close()
	return out
}

// writeValidConfig writes a config that passes Validate() with the given output
// directory and returns its path.
func writeValidConfig(t *testing.T, dir, outDir string) string {
	t.Helper()
	cfg := `host = "192.168.1.100"

[ssh]
user = "root"
port = 22

[wireguard]
port = 51820
server_ip = "10.42.0.1/24"
client_ip = "10.42.0.2/32"

[dropbear]
port = 22

[output]
dir = "` + outDir + `"
`
	p := filepath.Join(dir, "ubo.toml")
	if err := os.WriteFile(p, []byte(cfg), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

// --- isFlag -----------------------------------------------------------------

func TestIsFlag(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"-h", true},
		{"--config", true},
		{"", false},
		{"run", false},
		{"unlock", false},
	}
	for _, c := range cases {
		if got := isFlag(c.in); got != c.want {
			t.Errorf("isFlag(%q) = %v; want %v", c.in, got, c.want)
		}
	}
}

// --- dispatch ---------------------------------------------------------------

func TestDispatch_help(t *testing.T) {
	for _, arg := range []string{"help", "--help", "-h"} {
		out := captureStdout(t, func() {
			if err := dispatch([]string{arg}); err != nil {
				t.Errorf("dispatch(%q) error = %v; want nil", arg, err)
			}
		})
		if !strings.Contains(out, "Unlock Before Operation") {
			t.Errorf("dispatch(%q) did not print usage; got %q", arg, out)
		}
	}
}

func TestDispatch_unknownSubcommand(t *testing.T) {
	err := dispatch([]string{"bogus-subcommand"})
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
	if !strings.Contains(err.Error(), "unknown subcommand") {
		t.Errorf("error = %v; want 'unknown subcommand'", err)
	}
}

// flag.ErrHelp path: the flagset's built-in --help returns flag.ErrHelp, which
// dispatch swallows and returns nil. We use "status --help" so that the flagset
// (not the "help" subcommand branch) handles it.
func TestDispatch_flagErrHelp(t *testing.T) {
	// Suppress flag package's usage output to stderr by capturing stdout too;
	// the flagset's Usage prints the program usage to stdout.
	_ = captureStdout(t, func() {
		if err := dispatch([]string{"status", "--help"}); err != nil {
			t.Errorf("dispatch(status --help) error = %v; want nil", err)
		}
	})
}

func TestDispatch_flagParseError(t *testing.T) {
	// An unknown flag triggers a parse error that is not flag.ErrHelp.
	err := dispatch([]string{"status", "--nonexistent-flag"})
	if err == nil {
		t.Fatal("expected flag parse error")
	}
}

// "unlock change" maps to cmdUnlock with changeKey=true.
func TestDispatch_unlockChangeRouting(t *testing.T) {
	setUnlockSeams(t)
	var gotChangeKey bool
	osGetuid = func() int { return 1000 }
	userspaceUnlock = func(_ context.Context, _ *config.Config, _ string, changeKey bool) error {
		gotChangeKey = changeKey
		return nil
	}
	cfgPath := writeUnlockReady(t, "")
	if err := dispatch([]string{"unlock", "change", "--config", cfgPath}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !gotChangeKey {
		t.Error("dispatch 'unlock change' did not set changeKey=true")
	}
}

// default (no args) routes to run; point --config at a missing file so cmdRun
// fails fast at loadConfig before any network activity.
func TestDispatch_defaultRoutesToRun(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.toml")
	err := dispatch([]string{"--config", missing})
	if err == nil {
		t.Fatal("expected error from cmdRun via default route")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %v; want 'not found'", err)
	}
}

// explicit "init" subcommand routes through dispatch to cmdInit.
func TestDispatch_init(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ubo.toml")
	out := captureStdout(t, func() {
		if err := dispatch([]string{"init", "--config", cfgPath}); err != nil {
			t.Errorf("dispatch(init) error = %v", err)
		}
	})
	if !strings.Contains(out, "Created") {
		t.Errorf("init output = %q; want 'Created'", out)
	}
	if _, err := os.Stat(cfgPath); err != nil {
		t.Errorf("init did not create config: %v", err)
	}
}

// "status" subcommand routes through dispatch to cmdStatus.
func TestDispatch_status(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeValidConfig(t, dir, filepath.Join(dir, "out"))
	_ = captureStdout(t, func() {
		if err := dispatch([]string{"status", "--config", cfgPath}); err != nil {
			t.Errorf("dispatch(status) error = %v", err)
		}
	})
}

// --- cmdInit ----------------------------------------------------------------

func TestCmdInit_createsFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ubo.toml")
	out := captureStdout(t, func() {
		if err := cmdInit(cfgPath); err != nil {
			t.Fatalf("cmdInit error = %v", err)
		}
	})
	if !strings.Contains(out, "Created") {
		t.Errorf("output = %q; want 'Created'", out)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read created file: %v", err)
	}
	if string(data) != config.DefaultTemplate {
		t.Errorf("file contents != DefaultTemplate")
	}
}

func TestCmdInit_alreadyExists(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ubo.toml")
	if err := os.WriteFile(cfgPath, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	err := cmdInit(cfgPath)
	if err == nil {
		t.Fatal("expected 'already exists' error")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %v; want 'already exists'", err)
	}
}

func TestCmdInit_unwritableDir(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	dir := t.TempDir()
	sub := filepath.Join(dir, "ro")
	if err := os.Mkdir(sub, 0500); err != nil {
		t.Fatal(err)
	}
	err := cmdInit(filepath.Join(sub, "ubo.toml"))
	if err == nil {
		t.Fatal("expected write error in unwritable dir")
	}
	if !strings.Contains(err.Error(), "write") {
		t.Errorf("error = %v; want 'write'", err)
	}
}

// --- loadConfig -------------------------------------------------------------

func TestLoadConfig_missing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.toml")
	_, err := loadConfig(missing)
	if err == nil {
		t.Fatal("expected error for missing config")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %v; want 'not found'", err)
	}
}

func TestLoadConfig_malformed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(p, []byte("this is = = not valid toml ["), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := loadConfig(p)
	if err == nil {
		t.Fatal("expected parse error for malformed TOML")
	}
	if strings.Contains(err.Error(), "not found") {
		t.Errorf("malformed file should not be reported as 'not found': %v", err)
	}
}

func TestLoadConfig_valid(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeValidConfig(t, dir, filepath.Join(dir, "out"))
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Host != "192.168.1.100" {
		t.Errorf("Host = %q; want 192.168.1.100", cfg.Host)
	}
}

// --- statusReport -----------------------------------------------------------

// requiredArtifacts are the files statusReport treats as required for unlock.
var requiredArtifacts = []string{
	"client_auth_ed25519",
	"dropbear_host_key.pub",
	"client_wg.conf",
}

func touch(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0644); err != nil {
		t.Fatalf("touch %s: %v", name, err)
	}
}

func TestStatusReport_ready(t *testing.T) {
	dir := t.TempDir()
	for _, n := range requiredArtifacts {
		touch(t, dir, n)
	}
	ready, present := statusReport(dir)
	if !ready {
		t.Errorf("ready = false; want true")
	}
	for _, n := range requiredArtifacts {
		if !present[n] {
			t.Errorf("present[%q] = false; want true", n)
		}
	}
	// A non-required artifact that was not created should be marked absent.
	if present["README.txt"] {
		t.Errorf("present[README.txt] = true; want false")
	}
}

func TestStatusReport_missingRequired(t *testing.T) {
	// Create every required artifact except one, so ready must be false.
	for _, omit := range requiredArtifacts {
		dir := t.TempDir()
		for _, n := range requiredArtifacts {
			if n == omit {
				continue
			}
			touch(t, dir, n)
		}
		ready, present := statusReport(dir)
		if ready {
			t.Errorf("omitting %q: ready = true; want false", omit)
		}
		if present[omit] {
			t.Errorf("omitting %q: present[%q] = true; want false", omit, omit)
		}
	}
}

func TestStatusReport_nonRequiredPresent(t *testing.T) {
	// All required present plus a non-required one present: still ready, and the
	// non-required file is reported present.
	dir := t.TempDir()
	for _, n := range requiredArtifacts {
		touch(t, dir, n)
	}
	touch(t, dir, "README.txt")
	ready, present := statusReport(dir)
	if !ready {
		t.Errorf("ready = false; want true")
	}
	if !present["README.txt"] {
		t.Errorf("present[README.txt] = false; want true")
	}
}

// --- cmdStatus --------------------------------------------------------------

func TestCmdStatus_outputDirMissing(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "no-such-out")
	cfgPath := writeValidConfig(t, dir, outDir)
	out := captureStdout(t, func() {
		if err := cmdStatus(cfgPath); err != nil {
			t.Errorf("cmdStatus error = %v; want nil", err)
		}
	})
	if !strings.Contains(out, "not configured") {
		t.Errorf("output = %q; want 'not configured'", out)
	}
}

func TestCmdStatus_notReady(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")
	if err := os.Mkdir(outDir, 0755); err != nil {
		t.Fatal(err)
	}
	// outDir exists but contains no artifacts -> not ready.
	cfgPath := writeValidConfig(t, dir, outDir)
	out := captureStdout(t, func() {
		if err := cmdStatus(cfgPath); err != nil {
			t.Errorf("cmdStatus error = %v; want nil", err)
		}
	})
	if !strings.Contains(out, "not ready to unlock") {
		t.Errorf("output = %q; want 'not ready to unlock'", out)
	}
}

func TestCmdStatus_ready(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")
	if err := os.Mkdir(outDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, n := range requiredArtifacts {
		touch(t, outDir, n)
	}
	cfgPath := writeValidConfig(t, dir, outDir)
	out := captureStdout(t, func() {
		if err := cmdStatus(cfgPath); err != nil {
			t.Errorf("cmdStatus error = %v; want nil", err)
		}
	})
	if !strings.Contains(out, "ready to unlock") {
		t.Errorf("output = %q; want 'ready to unlock'", out)
	}
	if strings.Contains(out, "not ready to unlock") {
		t.Errorf("output marked not ready; want ready: %q", out)
	}
}

func TestCmdStatus_missingConfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.toml")
	err := cmdStatus(missing)
	if err == nil {
		t.Fatal("expected error for missing config")
	}
}

// --- cmdRun (error paths only) ----------------------------------------------

func TestCmdRun_missingConfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.toml")
	err := cmdRun(context.Background(), missing)
	if err == nil {
		t.Fatal("expected error for missing config")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %v; want 'not found'", err)
	}
}

func TestCmdRun_invalidConfig(t *testing.T) {
	dir := t.TempDir()
	// Missing host fails Validate().
	p := filepath.Join(dir, "ubo.toml")
	if err := os.WriteFile(p, []byte("[ssh]\nuser=\"root\"\nport=22\n"), 0644); err != nil {
		t.Fatal(err)
	}
	err := cmdRun(context.Background(), p)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "config:") {
		t.Errorf("error = %v; want 'config:'", err)
	}
}

// --- dispatch routing for configure / unlock -------------------------------

// dispatch("configure") routes to tuiRun; we seam it to avoid opening a real
// interactive editor.
func TestDispatch_configure(t *testing.T) {
	orig := tuiRun
	t.Cleanup(func() { tuiRun = orig })
	called := ""
	tuiRun = func(path string) error { called = path; return nil }
	if err := dispatch([]string{"configure", "--config", "/tmp/x.toml"}); err != nil {
		t.Fatalf("dispatch(configure) error = %v", err)
	}
	if called != "/tmp/x.toml" {
		t.Errorf("tuiRun got %q; want /tmp/x.toml", called)
	}
}

// dispatch("unlock") routes to cmdUnlock with changeKey=false.
func TestDispatch_unlock(t *testing.T) {
	setUnlockSeams(t)
	var gotChangeKey = true // init to true; expect it to be set false
	osGetuid = func() int { return 1000 }
	userspaceUnlock = func(_ context.Context, _ *config.Config, _ string, changeKey bool) error {
		gotChangeKey = changeKey
		return nil
	}
	cfgPath := writeUnlockReady(t, "")
	if err := dispatch([]string{"unlock", "--config", cfgPath}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotChangeKey {
		t.Error("dispatch 'unlock' set changeKey=true; want false")
	}
}

// --- cmdRun (full flow via seams) -------------------------------------------

// setRunSeams snapshots and restores the cmdRun external-call seams.
func setRunSeams(t *testing.T) {
	t.Helper()
	o1, o2, o3 := keygenGenerateAll, remoteConnect, setupConfigure
	o4 := checkTools
	t.Cleanup(func() {
		keygenGenerateAll, remoteConnect, setupConfigure = o1, o2, o3
		checkTools = o4
	})
}

// happyRunSeams installs seams for a successful cmdRun: keys generated,
// connection established, all setup steps succeeding.
func happyRunSeams(t *testing.T) {
	t.Helper()
	setRunSeams(t)
	checkTools = func(string) error { return nil }
	keygenGenerateAll = func(outDir string) (*keygen.Keys, error) {
		return &keygen.Keys{
			ServerWGPublic:  "serverpubkey",
			ClientWGPrivate: "clientprivkey",
		}, nil
	}
	remoteConnect = func(ctx context.Context, opts *remote.ConnectOptions) (*remote.Client, error) {
		return &remote.Client{}, nil
	}
	setupConfigure = func(ctx context.Context, c *remote.Client, cfg *config.Config, k *keygen.Keys, outDir string) error {
		return nil
	}
}

func TestCmdRun_success(t *testing.T) {
	happyRunSeams(t)
	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")
	cfgPath := writeValidConfig(t, dir, outDir)
	out := captureStdout(t, func() {
		if err := cmdRun(context.Background(), cfgPath); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "configuration complete") {
		t.Errorf("output = %q; want 'configuration complete'", out)
	}
	// The two local artifacts must have been written.
	for _, n := range []string{"client_wg.conf", "README.txt"} {
		if _, err := os.Stat(filepath.Join(outDir, n)); err != nil {
			t.Errorf("expected %s written: %v", n, err)
		}
	}
}

func TestCmdRun_keygenFails(t *testing.T) {
	happyRunSeams(t)
	keygenGenerateAll = func(outDir string) (*keygen.Keys, error) { return nil, errBoom }
	dir := t.TempDir()
	cfgPath := writeValidConfig(t, dir, filepath.Join(dir, "out"))
	_ = captureStdout(t, func() {
		if err := cmdRun(context.Background(), cfgPath); err != errBoom {
			t.Fatalf("error = %v; want errBoom", err)
		}
	})
}

func TestCmdRun_connectFails(t *testing.T) {
	happyRunSeams(t)
	remoteConnect = func(ctx context.Context, opts *remote.ConnectOptions) (*remote.Client, error) {
		return nil, errBoom
	}
	dir := t.TempDir()
	cfgPath := writeValidConfig(t, dir, filepath.Join(dir, "out"))
	_ = captureStdout(t, func() {
		if err := cmdRun(context.Background(), cfgPath); err != errBoom {
			t.Fatalf("error = %v; want errBoom", err)
		}
	})
}

func TestCmdRun_setupFails(t *testing.T) {
	happyRunSeams(t)
	setupConfigure = func(ctx context.Context, c *remote.Client, cfg *config.Config, k *keygen.Keys, outDir string) error {
		return errBoom
	}
	dir := t.TempDir()
	cfgPath := writeValidConfig(t, dir, filepath.Join(dir, "out"))
	_ = captureStdout(t, func() {
		if err := cmdRun(context.Background(), cfgPath); err != errBoom {
			t.Fatalf("error = %v; want errBoom", err)
		}
	})
}

func TestCmdRun_checkToolsFails(t *testing.T) {
	happyRunSeams(t)
	orig := checkTools
	t.Cleanup(func() { checkTools = orig })
	checkTools = func(sub string) error { return errBoom }
	dir := t.TempDir()
	cfgPath := writeValidConfig(t, dir, filepath.Join(dir, "out"))
	if err := cmdRun(context.Background(), cfgPath); err != errBoom {
		t.Fatalf("error = %v; want errBoom", err)
	}
}

func TestCmdRun_mkdirFails(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	happyRunSeams(t)
	// Output dir lives inside a read-only parent so MkdirAll fails.
	dir := t.TempDir()
	ro := filepath.Join(dir, "ro")
	if err := os.Mkdir(ro, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(ro, 0700) })
	cfgPath := writeValidConfig(t, dir, filepath.Join(ro, "sub", "out"))
	_ = captureStdout(t, func() {
		err := cmdRun(context.Background(), cfgPath)
		if err == nil || !strings.Contains(err.Error(), "create output dir") {
			t.Fatalf("error = %v; want 'create output dir'", err)
		}
	})
}

func TestCmdRun_writeClientConfigFails(t *testing.T) {
	happyRunSeams(t)
	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Pre-create client_wg.conf as a DIRECTORY so os.WriteFile to that path fails.
	if err := os.Mkdir(filepath.Join(outDir, "client_wg.conf"), 0700); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeValidConfig(t, dir, outDir)
	_ = captureStdout(t, func() {
		err := cmdRun(context.Background(), cfgPath)
		if err == nil || !strings.Contains(err.Error(), "client_wg.conf") {
			t.Fatalf("error = %v; want client_wg.conf write failure", err)
		}
	})
}

func TestCmdRun_writeReadmeFails(t *testing.T) {
	happyRunSeams(t)
	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0700); err != nil {
		t.Fatal(err)
	}
	// README.txt as a directory: client_wg.conf write succeeds, README fails.
	if err := os.Mkdir(filepath.Join(outDir, "README.txt"), 0700); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeValidConfig(t, dir, outDir)
	_ = captureStdout(t, func() {
		err := cmdRun(context.Background(), cfgPath)
		if err == nil || !strings.Contains(err.Error(), "README.txt") {
			t.Fatalf("error = %v; want README.txt write failure", err)
		}
	})
}

func TestCmdUnlock_checkToolsFails(t *testing.T) {
	happyUnlockSeams(t)
	orig := checkTools
	t.Cleanup(func() { checkTools = orig })
	checkTools = func(sub string) error { return errBoom }
	cfgPath := writeUnlockReady(t, "")
	if err := cmdUnlock(context.Background(), cfgPath, false); err != errBoom {
		t.Fatalf("error = %v; want errBoom", err)
	}
}

func TestCmdRun_marshalINIFails(t *testing.T) {
	happyRunSeams(t)
	// Empty key material makes WireGuardClientConfig.MarshalINI fail its
	// required-field validation, exercising the render error branch.
	keygenGenerateAll = func(outDir string) (*keygen.Keys, error) { return &keygen.Keys{}, nil }
	dir := t.TempDir()
	cfgPath := writeValidConfig(t, dir, filepath.Join(dir, "out"))
	_ = captureStdout(t, func() {
		err := cmdRun(context.Background(), cfgPath)
		if err == nil || !strings.Contains(err.Error(), "render client WireGuard config") {
			t.Fatalf("error = %v; want 'render client WireGuard config'", err)
		}
	})
}

// --- ensureSudo --------------------------------------------------------------

// setSudoSeams saves and restores the sudoProbe and readSudoPassword seams.
func setSudoSeams(t *testing.T) {
	t.Helper()
	op, or_ := sudoProbe, readSudoPassword
	t.Cleanup(func() { sudoProbe, readSudoPassword = op, or_ })
}

func writeSudoConfig(t *testing.T, dir, outDir string) string {
	t.Helper()
	cfg := `host = "192.168.1.100"

[ssh]
user = "justin"
port = 22
sudo = true

[wireguard]
port = 51820
server_ip = "10.42.0.1/24"
client_ip = "10.42.0.2/32"

[dropbear]
port = 22

[output]
dir = "` + outDir + `"
`
	p := filepath.Join(dir, "ubo.toml")
	if err := os.WriteFile(p, []byte(cfg), 0644); err != nil {
		t.Fatalf("write sudo config: %v", err)
	}
	return p
}

func TestEnsureSudo_disabled(t *testing.T) {
	setSudoSeams(t)
	probed := false
	sudoProbe = func(ctx context.Context, c *remote.Client) error {
		probed = true
		return nil
	}
	// Load a config with sudo=false (the default writeValidConfig).
	dir := t.TempDir()
	cfg, err := config.Load(writeSudoConfig(t, dir, filepath.Join(dir, "out")))
	if err != nil {
		t.Fatal(err)
	}
	cfg.SSH.Sudo = false
	if err := ensureSudo(context.Background(), &remote.Client{}, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if probed {
		t.Error("probe should not be called when sudo is disabled")
	}
}

func TestEnsureSudo_nopassword_succeeds(t *testing.T) {
	setSudoSeams(t)
	sudoProbe = func(ctx context.Context, c *remote.Client) error { return nil }
	prompted := false
	readSudoPassword = func(prompt string) (string, error) {
		prompted = true
		return "", nil
	}
	dir := t.TempDir()
	cfg, err := config.Load(writeSudoConfig(t, dir, filepath.Join(dir, "out")))
	if err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := ensureSudo(context.Background(), &remote.Client{}, cfg); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if prompted {
		t.Error("password should not be prompted when passwordless sudo works")
	}
	if !strings.Contains(out, "passwordless") {
		t.Errorf("output = %q; want passwordless confirmation", out)
	}
}

func TestEnsureSudo_password_succeeds(t *testing.T) {
	setSudoSeams(t)
	probeCount := 0
	sudoProbe = func(ctx context.Context, c *remote.Client) error {
		probeCount++
		if probeCount == 1 {
			return fmt.Errorf("no NOPASSWD")
		}
		return nil
	}
	readSudoPassword = func(prompt string) (string, error) { return "s3cr3t", nil }
	dir := t.TempDir()
	cfg, err := config.Load(writeSudoConfig(t, dir, filepath.Join(dir, "out")))
	if err != nil {
		t.Fatal(err)
	}
	client := &remote.Client{}
	out := captureStdout(t, func() {
		if err := ensureSudo(context.Background(), client, cfg); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if probeCount != 2 {
		t.Errorf("probeCount = %d; want 2", probeCount)
	}
	if !strings.Contains(out, "accepted") {
		t.Errorf("output = %q; want password accepted confirmation", out)
	}
}

func TestEnsureSudo_wrongPassword(t *testing.T) {
	setSudoSeams(t)
	sudoProbe = func(ctx context.Context, c *remote.Client) error {
		return fmt.Errorf("authentication failure")
	}
	readSudoPassword = func(prompt string) (string, error) { return "wrong", nil }
	dir := t.TempDir()
	cfg, err := config.Load(writeSudoConfig(t, dir, filepath.Join(dir, "out")))
	if err != nil {
		t.Fatal(err)
	}
	_ = captureStdout(t, func() {
		err := ensureSudo(context.Background(), &remote.Client{}, cfg)
		if err == nil || !strings.Contains(err.Error(), "authentication failed") {
			t.Fatalf("error = %v; want 'authentication failed'", err)
		}
	})
}

func TestEnsureSudo_readPasswordFails(t *testing.T) {
	setSudoSeams(t)
	sudoProbe = func(ctx context.Context, c *remote.Client) error {
		return fmt.Errorf("no NOPASSWD")
	}
	readSudoPassword = func(prompt string) (string, error) { return "", errBoom }
	dir := t.TempDir()
	cfg, err := config.Load(writeSudoConfig(t, dir, filepath.Join(dir, "out")))
	if err != nil {
		t.Fatal(err)
	}
	_ = captureStdout(t, func() {
		err := ensureSudo(context.Background(), &remote.Client{}, cfg)
		if err == nil || !strings.Contains(err.Error(), "read sudo password") {
			t.Fatalf("error = %v; want 'read sudo password'", err)
		}
	})
}

// --- cmdUnlock (error paths only) -------------------------------------------

func TestCmdUnlock_missingConfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.toml")
	err := cmdUnlock(context.Background(), missing, false)
	if err == nil {
		t.Fatal("expected error for missing config")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %v; want 'not found'", err)
	}
}

func TestCmdUnlock_invalidConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ubo.toml")
	// Missing host fails Validate().
	if err := os.WriteFile(p, []byte("[ssh]\nuser=\"root\"\nport=22\n"), 0644); err != nil {
		t.Fatal(err)
	}
	err := cmdUnlock(context.Background(), p, false)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "config:") {
		t.Errorf("error = %v; want 'config:'", err)
	}
}

func TestCmdUnlock_nonRootUsesUserspace(t *testing.T) {
	setUnlockSeams(t)
	called := false
	osGetuid = func() int { return 1000 }
	userspaceUnlock = func(_ context.Context, _ *config.Config, _ string, changeKey bool) error {
		called = true
		if changeKey {
			t.Error("changeKey should be false")
		}
		return nil
	}
	cfgPath := writeUnlockReady(t, "")
	if err := cmdUnlock(context.Background(), cfgPath, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("userspaceUnlock was not called for non-root uid")
	}
}

func TestCmdUnlock_nonRootChangeKeyUsesUserspace(t *testing.T) {
	setUnlockSeams(t)
	called := false
	osGetuid = func() int { return 1000 }
	userspaceUnlock = func(_ context.Context, _ *config.Config, _ string, changeKey bool) error {
		called = true
		if !changeKey {
			t.Error("changeKey should be true")
		}
		return nil
	}
	cfgPath := writeUnlockReady(t, "")
	if err := cmdUnlock(context.Background(), cfgPath, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("userspaceUnlock was not called for non-root uid with changeKey")
	}
}

// --- cmdUnlock (full flow via seams) ----------------------------------------

// unlockRecorder captures which seamed operations cmdUnlock invoked.
type unlockRecorder struct {
	upCalled, downCalled bool
	sessions             []string // remote commands passed to interactiveSession, in order
}

// setUnlockSeams snapshots every unlock seam and restores it on cleanup, so a
// test may freely reassign them.
func setUnlockSeams(t *testing.T) {
	t.Helper()
	o1, o2, o3 := osGetuid, remoteConnect, interactiveSession
	o4, o5 := waitForTunnelFn, unlockStdin
	o6, o7 := wgQuickUp, wgQuickDown
	o8, o9 := kernelUnlock, userspaceUnlock
	o10 := checkTools
	t.Cleanup(func() {
		osGetuid, remoteConnect, interactiveSession = o1, o2, o3
		waitForTunnelFn, unlockStdin = o4, o5
		wgQuickUp, wgQuickDown = o6, o7
		kernelUnlock, userspaceUnlock = o8, o9
		checkTools = o10
	})
}

// happyUnlockSeams installs seams that simulate a fully successful unlock:
// running as root, tunnel up/reachable, connect ok, every interactive session
// succeeding. Tests override individual seams to exercise failure branches.
func happyUnlockSeams(t *testing.T) *unlockRecorder {
	setUnlockSeams(t)
	rec := &unlockRecorder{}
	osGetuid = func() int { return 0 }
	checkTools = func(string) error { return nil }
	wgQuickUp = func(ctx context.Context, p string) error { rec.upCalled = true; return nil }
	wgQuickDown = func(p string) error { rec.downCalled = true; return nil }
	waitForTunnelFn = func(ip string, n int) error { return nil }
	remoteConnect = func(ctx context.Context, opts *remote.ConnectOptions) (*remote.Client, error) {
		return &remote.Client{}, nil
	}
	interactiveSession = func(c *remote.Client, cmd string) error {
		rec.sessions = append(rec.sessions, cmd)
		return nil
	}
	unlockStdin = strings.NewReader("")
	return rec
}

// writeUnlockReady creates an output dir containing the three artifacts
// cmdUnlock requires, plus a valid config pointing at it. If luksDevice is
// non-empty it is written under [luks].
func writeUnlockReady(t *testing.T, luksDevice string) string {
	t.Helper()
	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"client_wg.conf", "client_auth_ed25519", "dropbear_host_key.pub"} {
		touch(t, outDir, n)
	}
	cfg := `host = "192.168.1.100"

[ssh]
user = "root"
port = 22

[wireguard]
port = 51820
server_ip = "10.42.0.1/24"
client_ip = "10.42.0.2/32"

[dropbear]
port = 22

[output]
dir = "` + outDir + `"
`
	if luksDevice != "" {
		cfg += "\n[luks]\ndevice = \"" + luksDevice + "\"\n"
	}
	p := filepath.Join(dir, "ubo.toml")
	if err := os.WriteFile(p, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCmdUnlock_missingFiles(t *testing.T) {
	setUnlockSeams(t)
	osGetuid = func() int { return 0 }
	// Valid config but the output dir has no artifacts.
	dir := t.TempDir()
	cfgPath := writeValidConfig(t, dir, filepath.Join(dir, "out"))
	err := cmdUnlock(context.Background(), cfgPath, false)
	if err == nil || !strings.Contains(err.Error(), "missing file") {
		t.Fatalf("error = %v; want 'missing file'", err)
	}
}

func TestCmdUnlock_wgUpFails(t *testing.T) {
	rec := happyUnlockSeams(t)
	wgQuickUp = func(ctx context.Context, p string) error { return errBoom }
	cfgPath := writeUnlockReady(t, "")
	out := captureStdout(t, func() {
		err := cmdUnlock(context.Background(), cfgPath, false)
		if err == nil || !strings.Contains(err.Error(), "wg-quick up") {
			t.Fatalf("error = %v; want 'wg-quick up'", err)
		}
	})
	_ = out
	// Tunnel-down must NOT run when bring-up failed (defer registered after).
	if rec.downCalled {
		t.Errorf("wgQuickDown should not run when wg-quick up failed")
	}
}

func TestCmdUnlock_tunnelTimeout(t *testing.T) {
	rec := happyUnlockSeams(t)
	waitForTunnelFn = func(ip string, n int) error { return errBoom }
	cfgPath := writeUnlockReady(t, "")
	_ = captureStdout(t, func() {
		err := cmdUnlock(context.Background(), cfgPath, false)
		if err == nil {
			t.Fatal("expected tunnel timeout error")
		}
	})
	if !rec.upCalled || !rec.downCalled {
		t.Errorf("up=%v down=%v; both should run (down via defer)", rec.upCalled, rec.downCalled)
	}
}

func TestCmdUnlock_connectFails(t *testing.T) {
	happyUnlockSeams(t)
	remoteConnect = func(ctx context.Context, opts *remote.ConnectOptions) (*remote.Client, error) {
		return nil, errBoom
	}
	cfgPath := writeUnlockReady(t, "")
	_ = captureStdout(t, func() {
		err := cmdUnlock(context.Background(), cfgPath, false)
		if err == nil || !strings.Contains(err.Error(), "connect to Dropbear") {
			t.Fatalf("error = %v; want 'connect to Dropbear'", err)
		}
	})
}

func TestCmdUnlock_success(t *testing.T) {
	rec := happyUnlockSeams(t)
	cfgPath := writeUnlockReady(t, "")
	out := captureStdout(t, func() {
		if err := cmdUnlock(context.Background(), cfgPath, false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "unlock complete") {
		t.Errorf("output = %q; want 'unlock complete'", out)
	}
	if len(rec.sessions) != 1 || rec.sessions[0] != "cryptroot-unlock" {
		t.Errorf("sessions = %v; want exactly [cryptroot-unlock]", rec.sessions)
	}
	if !rec.downCalled {
		t.Errorf("wgQuickDown should run on success")
	}
}

func TestCmdUnlock_unlockFails(t *testing.T) {
	happyUnlockSeams(t)
	interactiveSession = func(c *remote.Client, cmd string) error { return errBoom }
	cfgPath := writeUnlockReady(t, "")
	_ = captureStdout(t, func() {
		err := cmdUnlock(context.Background(), cfgPath, false)
		if err == nil || !strings.Contains(err.Error(), "cryptroot-unlock") {
			t.Fatalf("error = %v; want 'cryptroot-unlock'", err)
		}
	})
}

func TestCmdUnlock_changeKey_deviceSet_unlocks(t *testing.T) {
	rec := happyUnlockSeams(t)
	unlockStdin = strings.NewReader("y\n")
	cfgPath := writeUnlockReady(t, "/dev/sda3")
	_ = captureStdout(t, func() {
		if err := cmdUnlock(context.Background(), cfgPath, true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	// First session is the change-key command with the explicit device; second is unlock.
	if len(rec.sessions) != 2 {
		t.Fatalf("sessions = %v; want 2 (change then unlock)", rec.sessions)
	}
	if !strings.Contains(rec.sessions[0], `luksChangeKey "/dev/sda3"`) {
		t.Errorf("change cmd = %q; want explicit device", rec.sessions[0])
	}
	if rec.sessions[1] != "cryptroot-unlock" {
		t.Errorf("second session = %q; want cryptroot-unlock", rec.sessions[1])
	}
}

func TestCmdUnlock_changeKey_noDevice_emptyAnswerUnlocks(t *testing.T) {
	rec := happyUnlockSeams(t)
	unlockStdin = strings.NewReader("\n") // empty -> defaults to yes
	cfgPath := writeUnlockReady(t, "")    // no device -> awk /etc/crypttab path
	_ = captureStdout(t, func() {
		if err := cmdUnlock(context.Background(), cfgPath, true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if len(rec.sessions) != 2 {
		t.Fatalf("sessions = %v; want 2", rec.sessions)
	}
	if !strings.Contains(rec.sessions[0], "/etc/crypttab") {
		t.Errorf("change cmd = %q; want crypttab-derived device", rec.sessions[0])
	}
}

func TestCmdUnlock_changeKey_declined(t *testing.T) {
	rec := happyUnlockSeams(t)
	unlockStdin = strings.NewReader("n\n")
	cfgPath := writeUnlockReady(t, "/dev/sda3")
	out := captureStdout(t, func() {
		if err := cmdUnlock(context.Background(), cfgPath, true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "not unlocking") {
		t.Errorf("output = %q; want 'not unlocking'", out)
	}
	// Only the change session ran; no unlock.
	if len(rec.sessions) != 1 {
		t.Errorf("sessions = %v; want only the change session", rec.sessions)
	}
	if !rec.downCalled {
		t.Errorf("tunnel should still be torn down after declining")
	}
}

// When teardown fails, cmdUnlock still returns the primary result (here
// success) but emits a warning. We exercise the warning branch of the defer.
func TestCmdUnlock_downFailureWarns(t *testing.T) {
	happyUnlockSeams(t)
	wgQuickDown = func(p string) error { return errBoom }
	cfgPath := writeUnlockReady(t, "")
	// Warning goes to stderr; success result to stdout. The call must still
	// succeed despite teardown failing.
	_ = captureStdout(t, func() {
		if err := cmdUnlock(context.Background(), cfgPath, false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestCmdUnlock_changeKey_changeFails(t *testing.T) {
	happyUnlockSeams(t)
	interactiveSession = func(c *remote.Client, cmd string) error { return errBoom }
	cfgPath := writeUnlockReady(t, "/dev/sda3")
	_ = captureStdout(t, func() {
		err := cmdUnlock(context.Background(), cfgPath, true)
		if err == nil || !strings.Contains(err.Error(), "luksChangeKey") {
			t.Fatalf("error = %v; want 'luksChangeKey'", err)
		}
	})
}

// --- waitForTunnel ----------------------------------------------------------

// waitForTunnel against an unroutable address must time out and return an error
// quickly. We use a TEST-NET-3 (RFC 5737) documentation address that is not
// routable, with maxSec=1 to keep it fast.
func TestWaitForTunnel_timeout(t *testing.T) {
	err := waitForTunnel("203.0.113.1", 1)
	if err == nil {
		t.Fatal("expected timeout error for unreachable host")
	}
	if !strings.Contains(err.Error(), "did not become reachable") {
		t.Errorf("error = %v; want 'did not become reachable'", err)
	}
}

// waitForTunnel against loopback may succeed if ping is permitted; either branch
// is acceptable. This exercises the loop body and (best-effort) the success
// path. It must not hang: maxSec=1.
func TestWaitForTunnel_loopback(t *testing.T) {
	// Result intentionally unchecked: success returns nil, failure returns the
	// timeout error. Both are valid depending on environment ping permissions.
	_ = waitForTunnel("127.0.0.1", 1)
}

// --- wgEndpoint -------------------------------------------------------------

func TestWgEndpoint_ipv4(t *testing.T) {
	got := wgEndpoint("1.2.3.4", 51820)
	if got != "1.2.3.4:51820" {
		t.Errorf("wgEndpoint(ipv4) = %q; want 1.2.3.4:51820", got)
	}
}

func TestWgEndpoint_ipv6(t *testing.T) {
	got := wgEndpoint("2001:db8::1", 51820)
	if got != "[2001:db8::1]:51820" {
		t.Errorf("wgEndpoint(ipv6) = %q; want [2001:db8::1]:51820", got)
	}
}

// --- connectForRun ----------------------------------------------------------

func TestConnectForRun_ensureSudoFails(t *testing.T) {
	setSudoSeams(t)
	setRunSeams(t)
	remoteConnect = func(ctx context.Context, opts *remote.ConnectOptions) (*remote.Client, error) {
		return &remote.Client{}, nil
	}
	// sudo=true + probe fails + readSudoPassword fails -> ensureSudo returns error
	sudoProbe = func(ctx context.Context, c *remote.Client) error { return errBoom }
	readSudoPassword = func(prompt string) (string, error) { return "", errBoom }

	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0700); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeSudoConfig(t, dir, outDir)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	_, err = connectForRun(context.Background(), cfg, outDir)
	if err == nil {
		t.Fatal("expected error when ensureSudo fails")
	}
}
