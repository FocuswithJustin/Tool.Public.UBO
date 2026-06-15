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
	checks := []struct {
		field string
		got   string
		want  string
	}{
		{"IP", info.IP, "10.0.0.5"},
		{"Interface", info.Interface, "eth0"},
		{"Gateway", info.Gateway, "192.168.1.1"},
		{"Hostname", info.Hostname, "myhost"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q; want %q", c.field, c.got, c.want)
		}
	}
	if info.Prefix != 26 {
		t.Errorf("Prefix = %d; want 26 (from config CIDR)", info.Prefix)
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
		"ip route show default":    {out: "default via 192.168.1.1 dev eth0 src 192.168.1.50"},
		"ip -4 addr show dev eth0": {out: "    inet 10.0.0.1/8 scope global\n    inet 192.168.1.50/25 scope global eth0"},
		"hostname":                 {out: "host1"},
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
		"ip route show default":    {out: "default via 192.168.1.1 dev eth0 src 192.168.1.50"},
		"ip -4 addr show dev eth0": {out: "    inet 10.0.0.1/8 scope global"},
		"hostname":                 {out: "host1"},
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
		"ip route show default":    {out: "default via 192.168.1.1 dev eth0 src 192.168.1.50"},
		"ip -4 addr show dev eth0": {err: errBoom},
		"hostname":                 {out: "host1"},
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
		"ip route show default":    {out: "default via 192.168.1.1 dev eth0 src 192.168.1.50"},
		"ip -4 addr show dev eth0": {out: "    inet 192.168.1.50/24 scope global eth0"},
		"hostname":                 {out: "", err: errBoom},
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
		"ip route show default":    {out: "default via 192.168.1.1 dev eth0 src 192.168.1.50"},
		"ip -4 addr show dev eth0": {out: "    inet 192.168.1.50/24 scope global eth0"},
		"hostname":                 {out: "   "},
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

func TestDetectNetwork_ipFromAddr_noSrcInRoute(t *testing.T) {
	// Default route has no src token (e.g. static/in-subnet gateway).
	// fillIPFromAddr should fall back to ip -4 addr to provide both IP and prefix.
	// This matches the 192.254.68.234/29 real-world target.
	f := &fakeRemote{runResponses: map[string]cmdResult{
		"ip route show default":    {out: "default via 192.254.68.233 dev ens3"},
		"ip -4 addr show dev ens3": {out: "    inet 192.254.68.234/29 brd 192.254.68.239 scope global ens3"},
		"hostname":                 {out: "target"},
	}}
	defer f.install()()
	cfg := &config.Config{}
	info, err := detectNetwork(context.Background(), nil, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.IP != "192.254.68.234" {
		t.Errorf("IP = %q; want 192.254.68.234", info.IP)
	}
	if info.Prefix != 29 {
		t.Errorf("Prefix = %d; want 29", info.Prefix)
	}
	if info.Gateway != "192.254.68.233" {
		t.Errorf("Gateway = %q; want 192.254.68.233", info.Gateway)
	}
}

func TestDetectNetwork_ipEmptyError(t *testing.T) {
	// Interface present, but no IP anywhere (ip -4 addr also returns nothing).
	f := &fakeRemote{runResponses: map[string]cmdResult{
		"ip route show default":    {out: "default via 192.168.1.1 dev eth0"},
		"ip -4 addr show dev eth0": {out: "link/ether 52:54:00:01 brd ff:ff:ff:ff:ff:ff"},
		"hostname":                 {out: "h"},
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
		"ip route show default":    {out: "nothing useful here"},
		"ip -4 addr show dev eth0": {out: "    inet 10.0.0.5/24 scope global eth0"},
		"hostname":                 {out: "h"},
	}}
	defer f.install()()
	cfg := &config.Config{Network: config.NetConfig{Interface: "eth0", IP: "10.0.0.5/24"}}
	if _, err := detectNetwork(context.Background(), nil, cfg); err == nil ||
		!strings.Contains(err.Error(), "gateway") {
		t.Fatalf("expected gateway empty error, got %v", err)
	}
}

// ── detectInterfaceTopology ───────────────────────────────────────────────────

func TestDetectNetwork_VLAN(t *testing.T) {
	f := &fakeRemote{runResponses: map[string]cmdResult{
		"ip route show default":                {out: "default via 192.168.1.1 dev eth0.10 src 192.168.1.50"},
		"ip -4 addr show dev eth0.10":          {out: "    inet 192.168.1.50/24 scope global eth0.10"},
		"ip -d link show eth0.10 2>/dev/null":  {out: "2: eth0.10@eth0: <BROADCAST>\n    vlan protocol 802.1Q id 10 <REORDER_HDR>"},
		"hostname":                              {out: "myhost"},
	}}
	defer f.install()()
	info, err := detectNetwork(context.Background(), nil, &config.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.VLANPhysdev != "eth0" {
		t.Errorf("VLANPhysdev = %q; want eth0", info.VLANPhysdev)
	}
	if info.VLANID != 10 {
		t.Errorf("VLANID = %d; want 10", info.VLANID)
	}
}

func TestDetectNetwork_Bond(t *testing.T) {
	f := &fakeRemote{runResponses: map[string]cmdResult{
		"ip route show default":                             {out: "default via 192.168.1.1 dev bond0 src 192.168.1.50"},
		"ip -4 addr show dev bond0":                        {out: "    inet 192.168.1.50/24 scope global bond0"},
		"ip -d link show bond0 2>/dev/null":                {out: "3: bond0: <BROADCAST,MULTICAST,MASTER,UP>"},
		"cat /sys/class/net/bond0/bonding/slaves 2>/dev/null": {out: "eth0 eth1"},
		"hostname":                                          {out: "myhost"},
	}}
	defer f.install()()
	info, err := detectNetwork(context.Background(), nil, &config.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(info.BondSlaves) != 2 || info.BondSlaves[0] != "eth0" || info.BondSlaves[1] != "eth1" {
		t.Errorf("BondSlaves = %v; want [eth0 eth1]", info.BondSlaves)
	}
}

func TestDetectNetwork_Bridge(t *testing.T) {
	f := &fakeRemote{runResponses: map[string]cmdResult{
		"ip route show default":                    {out: "default via 192.168.1.1 dev br0 src 192.168.1.50"},
		"ip -4 addr show dev br0":                  {out: "    inet 192.168.1.50/24 scope global br0"},
		"ip -d link show br0 2>/dev/null":          {out: "4: br0: <BROADCAST,MULTICAST,UP>"},
		"ls /sys/class/net/br0/brif/ 2>/dev/null":  {out: "eth0"},
		"hostname":                                  {out: "myhost"},
	}}
	defer f.install()()
	info, err := detectNetwork(context.Background(), nil, &config.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(info.BridgePorts) != 1 || info.BridgePorts[0] != "eth0" {
		t.Errorf("BridgePorts = %v; want [eth0]", info.BridgePorts)
	}
}

func TestParseVLANLink(t *testing.T) {
	out := "2: eth0.100@eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>\n    link/ether 52:54:00:ab:cd:ef\n    vlan protocol 802.1Q id 100 <REORDER_HDR>"
	physdev, id := parseVLANLink(out)
	if physdev != "eth0" {
		t.Errorf("physdev = %q; want eth0", physdev)
	}
	if id != 100 {
		t.Errorf("id = %d; want 100", id)
	}
}

func TestParseVLANLink_notVLAN(t *testing.T) {
	out := "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>\n    link/ether 52:54:00:ab:cd:ef"
	physdev, id := parseVLANLink(out)
	if physdev != "" || id != 0 {
		t.Errorf("expected empty physdev and 0 id for plain NIC, got %q/%d", physdev, id)
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
		"dropbearkey -t ed25519 -f " + key + " >/dev/null 2>&1": {out: "Generating key"},
		"dropbearkey -y -f " + key + " 2>/dev/null":             {out: "Public key portion is:\nssh-ed25519 AAAAC3Nz comment\nFingerprint: ..."},
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
		"dropbearkey -t ed25519 -f " + key + " >/dev/null 2>&1": {err: errBoom},
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
		"dropbearkey -t ed25519 -f " + key + " >/dev/null 2>&1": {out: "ok"},
		"dropbearkey -y -f " + key + " 2>/dev/null":             {err: errBoom},
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
		"dropbearkey -t ed25519 -f " + key + " >/dev/null 2>&1": {out: "ok"},
		"dropbearkey -y -f " + key + " 2>/dev/null":             {out: "no key here\njust noise"},
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

const happySetupJSON = `{"dropbear_pub_key":"ssh-ed25519 AAAAhostkey"}`

// networkRemote returns a fakeRemote wired for successful network detection.
func networkRemote() *fakeRemote {
	return &fakeRemote{
		runResponses: map[string]cmdResult{
			"ip route show default":    {out: "default via 192.168.1.1 dev eth0 src 192.168.1.50"},
			"ip -4 addr show dev eth0": {out: "    inet 192.168.1.50/24 scope global eth0"},
			"hostname":                 {out: "host1"},
		},
	}
}

// installSetupScript swaps in fn for the runSetupScript seam and returns a
// restore func to be deferred.
func installSetupScript(fn func(context.Context, *remote.Client, string) (string, error)) func() {
	orig := runSetupScript
	runSetupScript = fn
	return func() { runSetupScript = orig }
}

func TestConfigure_happyPath(t *testing.T) {
	f := networkRemote()
	defer f.install()()
	defer installSetupScript(func(_ context.Context, _ *remote.Client, _ string) (string, error) {
		return happySetupJSON, nil
	})()

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

func TestConfigure_renderWGError(t *testing.T) {
	// Empty WireGuard.ServerIP makes MarshalINI fail (Address required).
	f := networkRemote()
	defer f.install()()
	defer installSetupScript(func(_ context.Context, _ *remote.Client, _ string) (string, error) {
		return happySetupJSON, nil
	})()
	cfg := fullCfg()
	cfg.WireGuard.ServerIP = ""
	if err := Configure(context.Background(), nil, cfg, fullKeys(), t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "step 5 render WireGuard config") {
		t.Fatalf("expected WG render error, got %v", err)
	}
}

func TestConfigure_renderDropbearError(t *testing.T) {
	// DropbearPort == 0 makes RenderDropbearConfig fail.
	f := networkRemote()
	defer f.install()()
	defer installSetupScript(func(_ context.Context, _ *remote.Client, _ string) (string, error) {
		return happySetupJSON, nil
	})()
	cfg := fullCfg()
	cfg.Dropbear.Port = 0
	if err := Configure(context.Background(), nil, cfg, fullKeys(), t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "render dropbear config") {
		t.Fatalf("expected dropbear render error, got %v", err)
	}
}

func TestConfigure_setupScriptError(t *testing.T) {
	f := networkRemote()
	defer f.install()()
	defer installSetupScript(func(_ context.Context, _ *remote.Client, _ string) (string, error) {
		return "", errBoom
	})()
	if err := Configure(context.Background(), nil, fullCfg(), fullKeys(), t.TempDir()); err == nil ||
		!errors.Is(err, errBoom) {
		t.Fatalf("expected setup script error, got %v", err)
	}
}

func TestConfigure_setupScriptBadJSON(t *testing.T) {
	f := networkRemote()
	defer f.install()()
	defer installSetupScript(func(_ context.Context, _ *remote.Client, _ string) (string, error) {
		return "not json at all", nil
	})()
	if err := Configure(context.Background(), nil, fullCfg(), fullKeys(), t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "no JSON output") {
		t.Fatalf("expected no JSON output error, got %v", err)
	}
}

func TestConfigure_setupScriptMalformedJSON(t *testing.T) {
	f := networkRemote()
	defer f.install()()
	defer installSetupScript(func(_ context.Context, _ *remote.Client, _ string) (string, error) {
		return "{invalid json}", nil
	})()
	if err := Configure(context.Background(), nil, fullCfg(), fullKeys(), t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "parse setup script JSON") {
		t.Fatalf("expected JSON parse error, got %v", err)
	}
}

func TestConfigure_setupScriptMissingKey(t *testing.T) {
	f := networkRemote()
	defer f.install()()
	defer installSetupScript(func(_ context.Context, _ *remote.Client, _ string) (string, error) {
		return `{"other_field":"value"}`, nil
	})()
	if err := Configure(context.Background(), nil, fullCfg(), fullKeys(), t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "missing dropbear_pub_key") {
		t.Fatalf("expected missing key error, got %v", err)
	}
}

func TestConfigure_pinnedKeyWriteError(t *testing.T) {
	f := networkRemote()
	defer f.install()()
	defer installSetupScript(func(_ context.Context, _ *remote.Client, _ string) (string, error) {
		return happySetupJSON, nil
	})()
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
