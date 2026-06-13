package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ubo/internal/config"
)

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

// "unlock change" maps to unlock-change. As a non-root user, cmdUnlock returns
// the root-required error after passing validation — confirming the two-word
// subcommand routed to cmdUnlock.
func TestDispatch_unlockChangeRouting(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test assumes non-root execution")
	}
	dir := t.TempDir()
	cfgPath := writeValidConfig(t, dir, filepath.Join(dir, "out"))
	err := dispatch([]string{"unlock", "change", "--config", cfgPath})
	if err == nil {
		t.Fatal("expected error from cmdUnlock")
	}
	if !strings.Contains(err.Error(), "requires root") {
		t.Errorf("error = %v; want 'requires root'", err)
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

func TestCmdUnlock_requiresRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test assumes non-root execution; root would pass the guard")
	}
	dir := t.TempDir()
	cfgPath := writeValidConfig(t, dir, filepath.Join(dir, "out"))
	err := cmdUnlock(context.Background(), cfgPath, false)
	if err == nil {
		t.Fatal("expected root-required error")
	}
	if !strings.Contains(err.Error(), "requires root") {
		t.Errorf("error = %v; want 'requires root'", err)
	}
}

func TestCmdUnlock_changeRequiresRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test assumes non-root execution")
	}
	dir := t.TempDir()
	cfgPath := writeValidConfig(t, dir, filepath.Join(dir, "out"))
	err := cmdUnlock(context.Background(), cfgPath, true)
	if err == nil {
		t.Fatal("expected root-required error")
	}
	if !strings.Contains(err.Error(), "requires root") {
		t.Errorf("error = %v; want 'requires root'", err)
	}
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
