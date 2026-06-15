package tui

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ubo/internal/config"
)

// validTOML is a complete, valid config that round-trips through config.Load.
const validTOML = `host = "192.168.1.100"

[ssh]
user = "root"
port = 22
key = ""

[wireguard]
port = 51820
server_ip = "10.42.0.1/24"
client_ip = "10.42.0.2/32"

[dropbear]
port = 22

[output]
dir = ""

[network]
interface = ""
ip = ""

[luks]
device = ""
`

func writeFile(t *testing.T, dir, name, contents string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// TestEdit_FullScript covers: keeping a value (empty line), changing a string
// field, changing an int field, an invalid int that re-prompts before a valid
// value, and reaching EOF before all fields (remaining kept).
func TestEdit_FullScript(t *testing.T) {
	cfg := config.Default()
	cfg.Host = "192.168.1.100"

	// Field order: Host, SSH User, SSH Port, SSH Key Path, SSH ProxyJump,
	// WireGuard Port, WG Server IP, WG Client IP, Dropbear Port, Output Dir,
	// Network Interface, Network IP, LUKS Device.
	script := strings.Join([]string{
		"",         // Host: keep 192.168.1.100
		"admin",    // SSH User: change
		"abc",      // SSH Port: invalid -> re-prompt
		"2222",     // SSH Port: valid
		"",         // SSH Key Path: keep
		"",         // SSH ProxyJump: keep
		"51999",    // WireGuard Port: change
		"",         // WG Server IP: keep
		"",         // WG Client IP: keep
		"",         // Dropbear Port: keep
		"/tmp/out", // Output Dir: change
		// EOF here: Network Interface, Network IP, LUKS Device kept.
	}, "\n") + "\n"

	var out bytes.Buffer
	got, err := edit(strings.NewReader(script), &out, cfg)
	if err != nil {
		t.Fatalf("edit: %v", err)
	}

	// Each case names a field and its expected stringified value after editing.
	// Covers kept (empty line), changed string/int, re-prompted int, and
	// EOF-kept (Network/LUKS) fields.
	checkStringFields(t, []stringCheck{
		{"Host", got.Host, "192.168.1.100"},
		{"SSH.User", got.SSH.User, "admin"},
		{"SSH.Key", got.SSH.Key, ""},
		{"WireGuard.ServerIP", got.WireGuard.ServerIP, "10.42.0.1/24"},
		{"Output.Dir", got.Output.Dir, "/tmp/out"},
		{"Network.Interface", got.Network.Interface, ""},
		{"Network.IP", got.Network.IP, ""},
		{"LUKS.Device", got.LUKS.Device, ""},
	})
	checkIntFields(t, []intCheck{
		{"SSH.Port", got.SSH.Port, 2222},
		{"WireGuard.Port", got.WireGuard.Port, 51999},
	})

	checkOutputContains(t, out.String(), []string{
		"UBO Configuration Editor",
		"Host [192.168.1.100]: ",
		"SSH User [root]: ",
		"SSH Port [22]: ",
		"invalid number \"abc\"",
		"Output Dir []: ",
	})
}

// stringCheck and intCheck describe a single expected field value.
type stringCheck struct {
	name, got, want string
}

type intCheck struct {
	name      string
	got, want int
}

func checkStringFields(t *testing.T, checks []stringCheck) {
	t.Helper()
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

func checkIntFields(t *testing.T, checks []intCheck) {
	t.Helper()
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func checkOutputContains(t *testing.T, out string, wants []string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestEdit_InvalidIntThenEOFKeeps verifies that an invalid integer answer that
// is immediately followed by EOF keeps the current value instead of looping.
func TestEdit_InvalidIntThenEOFKeeps(t *testing.T) {
	cfg := config.Default()
	cfg.Host = "h"
	// Host kept, then SSH User kept, then SSH Port gets a bad value with no
	// trailing newline / no further input -> EOF, keep current (22).
	script := "\n\nnotanumber"

	var out bytes.Buffer
	got, err := edit(strings.NewReader(script), &out, cfg)
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	if got.SSH.Port != 22 {
		t.Errorf("SSH.Port = %d, want kept 22 after invalid+EOF", got.SSH.Port)
	}
	if !strings.Contains(out.String(), "invalid number \"notanumber\"") {
		t.Errorf("expected invalid-number message, got:\n%s", out.String())
	}
}

// TestEdit_ImmediateEOFKeepsAll verifies an empty reader keeps every value.
func TestEdit_ImmediateEOFKeepsAll(t *testing.T) {
	cfg := config.Default()
	cfg.Host = "keepme"

	var out bytes.Buffer
	got, err := edit(strings.NewReader(""), &out, cfg)
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	if got.Host != "keepme" || got.SSH.Port != 22 {
		t.Errorf("expected all kept, got host=%q port=%d", got.Host, got.SSH.Port)
	}
}

// TestRun_ExistingConfigUpdated writes a config file, scripts stdin to change a
// field, runs Run, and verifies the file was updated and Run returned nil.
func TestRun_ExistingConfigUpdated(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "ubo.toml", validTOML)

	// Change Host, keep everything else.
	restore := withStdin(t, "10.0.0.9\n")
	defer restore()

	if err := Run(p); err != nil {
		t.Fatalf("Run: %v", err)
	}

	loaded, err := config.Load(p)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if loaded.Host != "10.0.0.9" {
		t.Errorf("Host = %q, want 10.0.0.9", loaded.Host)
	}
}

// TestRun_NonexistentStartsFromDefaults verifies Run on a missing path starts
// from defaults and writes a valid file.
func TestRun_NonexistentStartsFromDefaults(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "new.toml")

	// Only Host is required beyond defaults; supply it and keep the rest.
	restore := withStdin(t, "192.168.50.50\n")
	defer restore()

	if err := Run(p); err != nil {
		t.Fatalf("Run: %v", err)
	}

	loaded, err := config.Load(p)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if loaded.Host != "192.168.50.50" {
		t.Errorf("Host = %q, want 192.168.50.50", loaded.Host)
	}
	if loaded.SSH.Port != 22 || loaded.WireGuard.Port != 51820 {
		t.Errorf("expected default ports, got ssh=%d wg=%d", loaded.SSH.Port, loaded.WireGuard.Port)
	}
}

// TestRun_ValidationFailureNoOverwrite starts from a config whose stored value
// is invalid; the user keeps it (empty input), so Validate fails and the file
// is not overwritten with the invalid data passing — Run returns an error.
func TestRun_ValidationFailureNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	// server_ip is not a valid CIDR; user keeps it -> Validate fails.
	badTOML := strings.Replace(validTOML, `server_ip = "10.42.0.1/24"`, `server_ip = "not-a-cidr"`, 1)
	p := writeFile(t, dir, "bad.toml", badTOML)

	restore := withStdin(t, "") // keep everything, including the bad server_ip
	defer restore()

	err := Run(p)
	if err == nil {
		t.Fatal("expected validation error from invalid server_ip")
	}
	if !strings.Contains(err.Error(), "server_ip") {
		t.Errorf("unexpected error: %v", err)
	}
	// The original (bad) file content must be untouched.
	data, rerr := os.ReadFile(p)
	if rerr != nil {
		t.Fatalf("read back: %v", rerr)
	}
	if !strings.Contains(string(data), "not-a-cidr") {
		t.Errorf("file should be unchanged on validation failure, got:\n%s", string(data))
	}
}

// TestRun_LoadErrorOnMalformedFile verifies a malformed existing config is
// surfaced as an error before any prompting/saving.
func TestRun_LoadErrorOnMalformedFile(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "broken.toml", "host = \"unterminated")

	restore := withStdin(t, "")
	defer restore()

	if err := Run(p); err == nil {
		t.Fatal("expected load error for malformed config")
	}
}

// TestEdit_AllFieldsSet provides a non-empty answer for every field, so each
// field's setValue closure runs (covering all of them).
func TestEdit_AllFieldsSet(t *testing.T) {
	cfg := config.Default()
	script := strings.Join([]string{
		"1.2.3.4",         // Host
		"admin",           // SSH User
		"2200",            // SSH Port
		"/k",              // SSH Key Path
		"user@bastion:22", // SSH ProxyJump
		"51000",           // WireGuard Port
		"10.9.0.1/24",     // WG Server IP
		"10.9.0.2/32",     // WG Client IP
		"2201",            // Dropbear Port
		"/out",            // Output Dir
		"eth9",            // Network Interface
		"10.9.0.3/24",     // Network IP
		"/dev/sdz1",       // LUKS Device
	}, "\n") + "\n"

	var out bytes.Buffer
	got, err := edit(strings.NewReader(script), &out, cfg)
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	checkStringFields(t, []stringCheck{
		{"Host", got.Host, "1.2.3.4"},
		{"SSH.User", got.SSH.User, "admin"},
		{"SSH.Key", got.SSH.Key, "/k"},
		{"SSH.ProxyJump", got.SSH.ProxyJump, "user@bastion:22"},
		{"WireGuard.ServerIP", got.WireGuard.ServerIP, "10.9.0.1/24"},
		{"WireGuard.ClientIP", got.WireGuard.ClientIP, "10.9.0.2/32"},
		{"Output.Dir", got.Output.Dir, "/out"},
		{"Network.Interface", got.Network.Interface, "eth9"},
		{"Network.IP", got.Network.IP, "10.9.0.3/24"},
		{"LUKS.Device", got.LUKS.Device, "/dev/sdz1"},
	})
	checkIntFields(t, []intCheck{
		{"SSH.Port", got.SSH.Port, 2200},
		{"WireGuard.Port", got.WireGuard.Port, 51000},
		{"Dropbear.Port", got.Dropbear.Port, 2201},
	})
}

// errReader returns a non-EOF error on the first Read, exercising edit's
// "unexpected read error" branch.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestEdit_ReadError(t *testing.T) {
	var out bytes.Buffer
	_, err := edit(errReader{}, &out, config.Default())
	if err == nil {
		t.Fatal("expected read error")
	}
}

// TestRun_EditError makes os.Stdin a write-only file so the editor's first read
// fails with a non-EOF error, covering Run's edit-error return.
func TestRun_EditError(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "ubo.toml", validTOML)

	wo, err := os.OpenFile(filepath.Join(dir, "wo"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = wo
	t.Cleanup(func() { os.Stdin = old; wo.Close() })

	if err := Run(p); err == nil {
		t.Fatal("expected edit error from unreadable stdin")
	}
}

// TestRun_SaveError starts from a valid config but places it in a read-only
// directory so the atomic save (temp file + rename in that dir) fails.
func TestRun_SaveError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	dir := t.TempDir()
	p := writeFile(t, dir, "ubo.toml", validTOML)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	restore := withStdin(t, "") // keep all values; valid config -> Validate passes
	defer restore()

	if err := Run(p); err == nil {
		t.Fatal("expected save error in read-only directory")
	}
}

// withStdin replaces os.Stdin with a temp file containing input and returns a
// restore function (call via defer). This lets Run() be exercised end-to-end.
func withStdin(t *testing.T, input string) func() {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdin-*.txt")
	if err != nil {
		t.Fatalf("create stdin temp: %v", err)
	}
	if _, err := f.WriteString(input); err != nil {
		t.Fatalf("write stdin temp: %v", err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatalf("seek stdin temp: %v", err)
	}
	old := os.Stdin
	os.Stdin = f
	return func() {
		os.Stdin = old
		f.Close()
	}
}
