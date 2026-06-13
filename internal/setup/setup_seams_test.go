package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ubo/internal/config"
	"ubo/internal/keygen"
	"ubo/internal/remote"
)

// ── seam fakes ────────────────────────────────────────────────────────────────

// fakeRemote records calls and returns canned output/errors keyed by command or
// path. It replaces the package-level runCommand/readFile/writeFile/writeFileExec
// seams for the duration of a test.
type fakeRemote struct {
	// runResponses maps an exact command string to its result.
	runResponses map[string]cmdResult
	// runDefault is returned for commands not present in runResponses.
	runDefault cmdResult
	// readResponses maps a path to its result.
	readResponses map[string]readResult
	// writeErrs maps a path to an error to return on write (nil = success).
	writeErrs map[string]error

	runCalls   []string
	writeCalls []string
}

type cmdResult struct {
	out string
	err error
}

type readResult struct {
	content string
	err     error
}

func (f *fakeRemote) run(_ context.Context, _ *remote.Client, cmd string) (string, error) {
	f.runCalls = append(f.runCalls, cmd)
	if r, ok := f.runResponses[cmd]; ok {
		return r.out, r.err
	}
	return f.runDefault.out, f.runDefault.err
}

func (f *fakeRemote) read(_ *remote.Client, path string) (string, error) {
	if r, ok := f.readResponses[path]; ok {
		return r.content, r.err
	}
	return "", nil
}

func (f *fakeRemote) write(_ *remote.Client, path, _ string, _ os.FileMode) error {
	f.writeCalls = append(f.writeCalls, path)
	if f.writeErrs != nil {
		if err, ok := f.writeErrs[path]; ok {
			return err
		}
	}
	return nil
}

func (f *fakeRemote) writeExec(_ *remote.Client, path, _ string) error {
	return f.write(nil, path, "", 0755)
}

// install swaps in the fake's methods for the package seams and returns a
// restore func to be deferred.
func (f *fakeRemote) install() func() {
	origRun, origRead, origWrite, origWriteExec := runCommand, readFile, writeFile, writeFileExec
	runCommand = f.run
	readFile = f.read
	writeFile = f.write
	writeFileExec = f.writeExec
	return func() {
		runCommand = origRun
		readFile = origRead
		writeFile = origWrite
		writeFileExec = origWriteExec
	}
}

var errBoom = errors.New("boom")

// ── detectNetwork ─────────────────────────────────────────────────────────────

func TestDetectNetwork_configIPProvided(t *testing.T) {
	f := &fakeRemote{runResponses: map[string]cmdResult{
		"ip route show default": {out: "default via 192.168.1.1 dev eth0 proto dhcp src 9.9.9.9"},
		"hostname":              {out: "myhost"},
	}}
	defer f.install()()

	cfg := &config.Config{Network: config.NetConfig{IP: "10.0.0.5/26"}}
	info, err := detectNetwork(context.Background(), nil, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.IP != "10.0.0.5" {
		t.Errorf("IP = %q; want 10.0.0.5", info.IP)
	}
	if info.Prefix != 26 {
		t.Errorf("Prefix = %d; want 26 (from config CIDR)", info.Prefix)
	}
	if info.Interface != "eth0" || info.Gateway != "192.168.1.1" {
		t.Errorf("iface/gw = %q/%q; want eth0/192.168.1.1", info.Interface, info.Gateway)
	}
	if info.Hostname != "myhost" {
		t.Errorf("Hostname = %q; want myhost", info.Hostname)
	}
}

func TestDetectNetwork_invalidConfigCIDR(t *testing.T) {
	f := &fakeRemote{}
	defer f.install()()
	cfg := &config.Config{Network: config.NetConfig{IP: "not-a-cidr"}}
	if _, err := detectNetwork(context.Background(), nil, cfg); err == nil {
		t.Fatal("expected error for invalid network.ip CIDR")
	}
}

func TestDetectNetwork_routeError(t *testing.T) {
	f := &fakeRemote{runResponses: map[string]cmdResult{
		"ip route show default": {err: errBoom},
	}}
	defer f.install()()
	cfg := &config.Config{}
	if _, err := detectNetwork(context.Background(), nil, cfg); err == nil || !strings.Contains(err.Error(), "ip route") {
		t.Fatalf("expected ip route error, got %v", err)
	}
}

func TestDetectNetwork_interfaceEmptyError(t *testing.T) {
	// No dev in route, no interface in config -> interface empty -> error.
	f := &fakeRemote{runResponses: map[string]cmdResult{
		"ip route show default": {out: "default via 192.168.1.1 src 9.9.9.9"},
	}}
	defer f.install()()
	cfg := &config.Config{}
	if _, err := detectNetwork(context.Background(), nil, cfg); err == nil ||
		!strings.Contains(err.Error(), "network interface") {
		t.Fatalf("expected interface error, got %v", err)
	}
}

func TestDetectNetwork_invalidInterfaceName(t *testing.T) {
	f := &fakeRemote{}
	defer f.install()()
	cfg := &config.Config{Network: config.NetConfig{Interface: "eth0; rm -rf /"}}
	if _, err := detectNetwork(context.Background(), nil, cfg); err == nil ||
		!strings.Contains(err.Error(), "unexpected characters") {
		t.Fatalf("expected invalid interface name error, got %v", err)
	}
}

func TestDetectNetwork_prefixFromIPAddrMatch(t *testing.T) {
	// IP from route src; prefix detected from `ip addr` matched-IP line.
	f := &fakeRemote{runResponses: map[string]cmdResult{
		"ip route show default": {out: "default via 192.168.1.1 dev eth0 src 192.168.1.50"},
		"ip addr show dev eth0": {out: "    inet 10.0.0.1/8 scope global\n    inet 192.168.1.50/25 scope global eth0"},
		"hostname":              {out: "host1"},
	}}
	defer f.install()()
	cfg := &config.Config{}
	info, err := detectNetwork(context.Background(), nil, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Prefix != 25 {
		t.Errorf("Prefix = %d; want 25 (matched IP line)", info.Prefix)
	}
}

func TestDetectNetwork_prefixFallback24(t *testing.T) {
	// ip addr returns no matching inet line -> /24 fallback warning path.
	f := &fakeRemote{runResponses: map[string]cmdResult{
		"ip route show default": {out: "default via 192.168.1.1 dev eth0 src 192.168.1.50"},
		"ip addr show dev eth0": {out: "    inet 10.0.0.1/8 scope global"},
		"hostname":              {out: "host1"},
	}}
	defer f.install()()
	cfg := &config.Config{}
	info, err := detectNetwork(context.Background(), nil, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Prefix != 24 {
		t.Errorf("Prefix = %d; want 24 fallback", info.Prefix)
	}
}

func TestDetectNetwork_prefixIPAddrError(t *testing.T) {
	// ip addr command errors -> addrErr != nil path -> /24 fallback.
	f := &fakeRemote{runResponses: map[string]cmdResult{
		"ip route show default": {out: "default via 192.168.1.1 dev eth0 src 192.168.1.50"},
		"ip addr show dev eth0": {err: errBoom},
		"hostname":              {out: "host1"},
	}}
	defer f.install()()
	cfg := &config.Config{}
	info, err := detectNetwork(context.Background(), nil, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Prefix != 24 {
		t.Errorf("Prefix = %d; want 24 fallback after ip addr error", info.Prefix)
	}
}

func TestDetectNetwork_hostnameFailureFallback(t *testing.T) {
	// hostname command errors AND returns empty -> "server" fallback.
	f := &fakeRemote{runResponses: map[string]cmdResult{
		"ip route show default": {out: "default via 192.168.1.1 dev eth0 src 192.168.1.50"},
		"ip addr show dev eth0": {out: "    inet 192.168.1.50/24 scope global eth0"},
		"hostname":              {out: "", err: errBoom},
	}}
	defer f.install()()
	cfg := &config.Config{}
	info, err := detectNetwork(context.Background(), nil, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Hostname != "server" {
		t.Errorf("Hostname = %q; want server fallback", info.Hostname)
	}
}

func TestDetectNetwork_hostnameEmptyNoError(t *testing.T) {
	// hostname returns empty without error -> still "server".
	f := &fakeRemote{runResponses: map[string]cmdResult{
		"ip route show default": {out: "default via 192.168.1.1 dev eth0 src 192.168.1.50"},
		"ip addr show dev eth0": {out: "    inet 192.168.1.50/24 scope global eth0"},
		"hostname":              {out: "   "},
	}}
	defer f.install()()
	cfg := &config.Config{}
	info, err := detectNetwork(context.Background(), nil, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Hostname != "server" {
		t.Errorf("Hostname = %q; want server (empty trimmed)", info.Hostname)
	}
}

func TestDetectNetwork_ipEmptyError(t *testing.T) {
	// Interface present, but no IP anywhere -> IP empty error.
	f := &fakeRemote{runResponses: map[string]cmdResult{
		"ip route show default": {out: "default via 192.168.1.1 dev eth0"},
		"hostname":              {out: "h"},
	}}
	defer f.install()()
	cfg := &config.Config{}
	if _, err := detectNetwork(context.Background(), nil, cfg); err == nil ||
		!strings.Contains(err.Error(), "IP address") {
		t.Fatalf("expected IP empty error, got %v", err)
	}
}

func TestDetectNetwork_gatewayEmptyError(t *testing.T) {
	// IP present (via config), interface via config, but no gateway -> error.
	f := &fakeRemote{runResponses: map[string]cmdResult{
		"ip route show default": {out: "nothing useful here"},
		"ip addr show dev eth0": {out: "    inet 10.0.0.5/24 scope global eth0"},
		"hostname":              {out: "h"},
	}}
	defer f.install()()
	cfg := &config.Config{Network: config.NetConfig{Interface: "eth0", IP: "10.0.0.5/24"}}
	if _, err := detectNetwork(context.Background(), nil, cfg); err == nil ||
		!strings.Contains(err.Error(), "gateway") {
		t.Fatalf("expected gateway empty error, got %v", err)
	}
}

// ── detectDropbearPaths ───────────────────────────────────────────────────────

const dbDetectCmd = `if [ -d /etc/dropbear/initramfs ]; then echo /etc/dropbear/initramfs; ` +
	`elif [ -d /etc/dropbear-initramfs ]; then echo /etc/dropbear-initramfs; ` +
	`else echo NOTFOUND; fi`

func TestDetectDropbearPaths_initramfsSubdir(t *testing.T) {
	f := &fakeRemote{runResponses: map[string]cmdResult{
		dbDetectCmd: {out: "/etc/dropbear/initramfs\n"},
	}}
	defer f.install()()
	p, err := detectDropbearPaths(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.ConfigDir != "/etc/dropbear/initramfs" {
		t.Errorf("ConfigDir = %q", p.ConfigDir)
	}
	if p.HostKeyFile != "/etc/dropbear/initramfs/dropbear_ed25519_host_key" {
		t.Errorf("HostKeyFile = %q", p.HostKeyFile)
	}
}

func TestDetectDropbearPaths_flatDir(t *testing.T) {
	f := &fakeRemote{runResponses: map[string]cmdResult{
		dbDetectCmd: {out: "/etc/dropbear-initramfs"},
	}}
	defer f.install()()
	p, err := detectDropbearPaths(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.ConfigDir != "/etc/dropbear-initramfs" {
		t.Errorf("ConfigDir = %q", p.ConfigDir)
	}
}

func TestDetectDropbearPaths_notFound(t *testing.T) {
	f := &fakeRemote{runResponses: map[string]cmdResult{
		dbDetectCmd: {out: "NOTFOUND"},
	}}
	defer f.install()()
	if _, err := detectDropbearPaths(context.Background(), nil); err == nil ||
		!strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected NOTFOUND error, got %v", err)
	}
}

func TestDetectDropbearPaths_runError(t *testing.T) {
	f := &fakeRemote{runResponses: map[string]cmdResult{
		dbDetectCmd: {err: errBoom},
	}}
	defer f.install()()
	if _, err := detectDropbearPaths(context.Background(), nil); !errors.Is(err, errBoom) {
		t.Fatalf("expected wrapped boom error, got %v", err)
	}
}

// ── generateDropbearHostKey ───────────────────────────────────────────────────

func TestGenerateDropbearHostKey_success(t *testing.T) {
	key := "/etc/dropbear/initramfs/dropbear_ed25519_host_key"
	f := &fakeRemote{runResponses: map[string]cmdResult{
		"dropbearkey -t ed25519 -f " + key:          {out: "Generating key"},
		"dropbearkey -y -f " + key + " 2>/dev/null": {out: "Public key portion is:\nssh-ed25519 AAAAC3Nz comment\nFingerprint: ..."},
	}}
	defer f.install()()
	pub, err := generateDropbearHostKey(context.Background(), nil, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(pub, "ssh-ed25519 ") {
		t.Errorf("pub = %q; want ssh-ed25519 line", pub)
	}
}

func TestGenerateDropbearHostKey_genError(t *testing.T) {
	key := "/k"
	f := &fakeRemote{runResponses: map[string]cmdResult{
		"dropbearkey -t ed25519 -f " + key: {err: errBoom},
	}}
	defer f.install()()
	if _, err := generateDropbearHostKey(context.Background(), nil, key); err == nil ||
		!strings.Contains(err.Error(), "dropbearkey:") {
		t.Fatalf("expected dropbearkey gen error, got %v", err)
	}
}

func TestGenerateDropbearHostKey_yError(t *testing.T) {
	key := "/k"
	f := &fakeRemote{runResponses: map[string]cmdResult{
		"dropbearkey -t ed25519 -f " + key:          {out: "ok"},
		"dropbearkey -y -f " + key + " 2>/dev/null": {err: errBoom},
	}}
	defer f.install()()
	if _, err := generateDropbearHostKey(context.Background(), nil, key); err == nil ||
		!strings.Contains(err.Error(), "dropbearkey -y:") {
		t.Fatalf("expected dropbearkey -y error, got %v", err)
	}
}

func TestGenerateDropbearHostKey_noPubKey(t *testing.T) {
	key := "/k"
	f := &fakeRemote{runResponses: map[string]cmdResult{
		"dropbearkey -t ed25519 -f " + key:          {out: "ok"},
		"dropbearkey -y -f " + key + " 2>/dev/null": {out: "no key here\njust noise"},
	}}
	defer f.install()()
	if _, err := generateDropbearHostKey(context.Background(), nil, key); err == nil ||
		!strings.Contains(err.Error(), "could not extract public key") {
		t.Fatalf("expected extract error, got %v", err)
	}
}

// ── configureGrub ─────────────────────────────────────────────────────────────

func grubNetInfo() *NetworkInfo {
	return &NetworkInfo{
		Interface: "eth0",
		IP:        "192.168.1.50",
		Prefix:    24,
		Gateway:   "192.168.1.1",
		Hostname:  "host1",
	}
}

func TestConfigureGrub_readError(t *testing.T) {
	f := &fakeRemote{readResponses: map[string]readResult{
		"/etc/default/grub": {err: errBoom},
	}}
	defer f.install()()
	if err := configureGrub(context.Background(), nil, grubNetInfo()); err == nil ||
		!strings.Contains(err.Error(), "read /etc/default/grub") {
		t.Fatalf("expected read error, got %v", err)
	}
}

func TestConfigureGrub_alreadyContainsIP(t *testing.T) {
	f := &fakeRemote{readResponses: map[string]readResult{
		"/etc/default/grub": {content: `GRUB_CMDLINE_LINUX="ip=1.2.3.4::5.6.7.8:255.255.255.0:h:eth0:none"`},
	}}
	defer f.install()()
	if err := configureGrub(context.Background(), nil, grubNetInfo()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(f.writeCalls) != 0 {
		t.Errorf("expected no write when ip= already present, got %v", f.writeCalls)
	}
}

func TestConfigureGrub_appendSuccess(t *testing.T) {
	f := &fakeRemote{
		readResponses: map[string]readResult{
			"/etc/default/grub": {content: `GRUB_CMDLINE_LINUX=""` + "\n"},
		},
		runResponses: map[string]cmdResult{
			"update-grub 2>&1": {out: "Generating grub configuration"},
		},
	}
	defer f.install()()
	if err := configureGrub(context.Background(), nil, grubNetInfo()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(f.writeCalls) != 1 || f.writeCalls[0] != "/etc/default/grub" {
		t.Errorf("expected write to grub, got %v", f.writeCalls)
	}
}

func TestConfigureGrub_writeError(t *testing.T) {
	f := &fakeRemote{
		readResponses: map[string]readResult{
			"/etc/default/grub": {content: `GRUB_CMDLINE_LINUX=""` + "\n"},
		},
		writeErrs: map[string]error{"/etc/default/grub": errBoom},
	}
	defer f.install()()
	if err := configureGrub(context.Background(), nil, grubNetInfo()); err == nil ||
		!strings.Contains(err.Error(), "write /etc/default/grub") {
		t.Fatalf("expected write error, got %v", err)
	}
}

func TestConfigureGrub_updateGrubError(t *testing.T) {
	f := &fakeRemote{
		readResponses: map[string]readResult{
			"/etc/default/grub": {content: `GRUB_CMDLINE_LINUX=""` + "\n"},
		},
		runResponses: map[string]cmdResult{
			"update-grub 2>&1": {err: errBoom},
		},
	}
	defer f.install()()
	if err := configureGrub(context.Background(), nil, grubNetInfo()); err == nil ||
		!strings.Contains(err.Error(), "update-grub") {
		t.Fatalf("expected update-grub error, got %v", err)
	}
}

// ── Configure (end-to-end with seams) ─────────────────────────────────────────

func fullCfg() *config.Config {
	return &config.Config{
		WireGuard: config.WGConfig{Port: 51820, ServerIP: "10.42.0.1/24", ClientIP: "10.42.0.2/32"},
		Dropbear:  config.DBConfig{Port: 22},
	}
}

func fullKeys() *keygen.Keys {
	return &keygen.Keys{
		ServerWGPrivate: "serverpriv",
		ClientWGPublic:  "clientpub",
		ClientSSHPubKey: "ssh-ed25519 AAAAclient",
	}
}

// happyRemote returns a fakeRemote wired for a successful Configure run.
func happyRemote() *fakeRemote {
	key := "/etc/dropbear/initramfs/dropbear_ed25519_host_key"
	return &fakeRemote{
		runResponses: map[string]cmdResult{
			"ip route show default":                     {out: "default via 192.168.1.1 dev eth0 src 192.168.1.50"},
			"ip addr show dev eth0":                     {out: "    inet 192.168.1.50/24 scope global eth0"},
			"hostname":                                  {out: "host1"},
			dbDetectCmd:                                 {out: "/etc/dropbear/initramfs"},
			"dropbearkey -t ed25519 -f " + key:          {out: "ok"},
			"dropbearkey -y -f " + key + " 2>/dev/null": {out: "ssh-ed25519 AAAAhostkey"},
			"update-grub 2>&1":                          {out: "ok"},
		},
		readResponses: map[string]readResult{
			"/etc/default/grub": {content: `GRUB_CMDLINE_LINUX=""` + "\n"},
		},
	}
}

func TestConfigure_happyPath(t *testing.T) {
	f := happyRemote()
	defer f.install()()

	outDir := t.TempDir()
	err := Configure(context.Background(), nil, fullCfg(), fullKeys(), outDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pinned := filepath.Join(outDir, "dropbear_host_key.pub")
	data, readErr := os.ReadFile(pinned)
	if readErr != nil {
		t.Fatalf("pinned key file not written: %v", readErr)
	}
	if got := strings.TrimSpace(string(data)); got != "ssh-ed25519 AAAAhostkey" {
		t.Errorf("pinned key = %q", got)
	}
}

func TestConfigure_step1Error(t *testing.T) {
	f := &fakeRemote{runResponses: map[string]cmdResult{
		"ip route show default": {err: errBoom},
	}}
	defer f.install()()
	if err := Configure(context.Background(), nil, fullCfg(), fullKeys(), t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "step 1") {
		t.Fatalf("expected step 1 error, got %v", err)
	}
}

func TestConfigure_step2InstallError(t *testing.T) {
	f := happyRemote()
	f.runResponses["DEBIAN_FRONTEND=noninteractive apt-get update -qq && "+
		"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dropbear-initramfs wireguard-tools"] = cmdResult{err: errBoom}
	defer f.install()()
	if err := Configure(context.Background(), nil, fullCfg(), fullKeys(), t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "step 2 install packages") {
		t.Fatalf("expected step 2 error, got %v", err)
	}
}

func TestConfigure_step3DetectError(t *testing.T) {
	f := happyRemote()
	f.runResponses[dbDetectCmd] = cmdResult{out: "NOTFOUND"}
	defer f.install()()
	if err := Configure(context.Background(), nil, fullCfg(), fullKeys(), t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "step 3 detect dropbear paths") {
		t.Fatalf("expected step 3 detect error, got %v", err)
	}
}

func TestConfigure_step3GenKeyError(t *testing.T) {
	f := happyRemote()
	key := "/etc/dropbear/initramfs/dropbear_ed25519_host_key"
	f.runResponses["dropbearkey -t ed25519 -f "+key] = cmdResult{err: errBoom}
	defer f.install()()
	if err := Configure(context.Background(), nil, fullCfg(), fullKeys(), t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "step 3 generate dropbear host key") {
		t.Fatalf("expected step 3 gen key error, got %v", err)
	}
}

func TestConfigure_pinnedKeyWriteError(t *testing.T) {
	f := happyRemote()
	defer f.install()()
	// Point outputDir at a path whose parent forbids creating the file.
	roDir := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(roDir, 0500); err != nil {
		t.Fatal(err)
	}
	if err := Configure(context.Background(), nil, fullCfg(), fullKeys(), roDir); err == nil ||
		!strings.Contains(err.Error(), "save dropbear host key") {
		t.Fatalf("expected save key error, got %v", err)
	}
}

func TestConfigure_step5RenderWGError(t *testing.T) {
	// Empty WireGuard.ServerIP makes MarshalINI fail (Address required).
	f := happyRemote()
	defer f.install()()
	cfg := fullCfg()
	cfg.WireGuard.ServerIP = ""
	if err := Configure(context.Background(), nil, cfg, fullKeys(), t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "step 5 render WireGuard config") {
		t.Fatalf("expected step 5 render error, got %v", err)
	}
}

func TestConfigure_step9RenderDropbearError(t *testing.T) {
	// DropbearPort == 0 makes RenderDropbearConfig fail (DropbearPort required).
	f := happyRemote()
	defer f.install()()
	cfg := fullCfg()
	cfg.Dropbear.Port = 0
	if err := Configure(context.Background(), nil, cfg, fullKeys(), t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "step 9 render dropbear config") {
		t.Fatalf("expected step 9 render error, got %v", err)
	}
}

func TestConfigure_step5WriteWGError(t *testing.T) {
	f := happyRemote()
	f.writeErrs = map[string]error{"/etc/wireguard/wg-initramfs.conf": errBoom}
	defer f.install()()
	if err := Configure(context.Background(), nil, fullCfg(), fullKeys(), t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "step 5 write WireGuard config") {
		t.Fatalf("expected step 5 error, got %v", err)
	}
}

func TestConfigure_step6HookError(t *testing.T) {
	f := happyRemote()
	f.writeErrs = map[string]error{"/etc/initramfs-tools/hooks/wireguard": errBoom}
	defer f.install()()
	if err := Configure(context.Background(), nil, fullCfg(), fullKeys(), t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "step 6 write initramfs hook") {
		t.Fatalf("expected step 6 error, got %v", err)
	}
}

func TestConfigure_step7ScriptError(t *testing.T) {
	f := happyRemote()
	f.writeErrs = map[string]error{"/etc/initramfs-tools/scripts/init-premount/wireguard": errBoom}
	defer f.install()()
	if err := Configure(context.Background(), nil, fullCfg(), fullKeys(), t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "step 7 write initramfs script") {
		t.Fatalf("expected step 7 error, got %v", err)
	}
}

func TestConfigure_step8AuthKeysError(t *testing.T) {
	f := happyRemote()
	f.writeErrs = map[string]error{"/etc/dropbear/initramfs/authorized_keys": errBoom}
	defer f.install()()
	if err := Configure(context.Background(), nil, fullCfg(), fullKeys(), t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "step 8 write authorized_keys") {
		t.Fatalf("expected step 8 error, got %v", err)
	}
}

func TestConfigure_step9DropbearConfError(t *testing.T) {
	f := happyRemote()
	f.writeErrs = map[string]error{"/etc/dropbear/initramfs/dropbear.conf": errBoom}
	defer f.install()()
	if err := Configure(context.Background(), nil, fullCfg(), fullKeys(), t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "step 9 write dropbear config") {
		t.Fatalf("expected step 9 error, got %v", err)
	}
}

func TestConfigure_step10GrubError(t *testing.T) {
	f := happyRemote()
	f.readResponses["/etc/default/grub"] = readResult{err: errBoom}
	defer f.install()()
	if err := Configure(context.Background(), nil, fullCfg(), fullKeys(), t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "step 10 configure GRUB") {
		t.Fatalf("expected step 10 error, got %v", err)
	}
}

func TestConfigure_step11UpdateInitramfsError(t *testing.T) {
	f := happyRemote()
	f.runResponses["update-initramfs -u -k all"] = cmdResult{err: errBoom}
	defer f.install()()
	if err := Configure(context.Background(), nil, fullCfg(), fullKeys(), t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "step 11 update-initramfs") {
		t.Fatalf("expected step 11 error, got %v", err)
	}
}
