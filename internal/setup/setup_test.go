package setup

import (
	"strings"
	"testing"

	"ubo/internal/config"
	"ubo/internal/keygen"
)

// ── isValidInterfaceName ──────────────────────────────────────────────────────

func TestIsValidInterfaceName(t *testing.T) {
	valid := []string{
		"eth0", "ens3", "ens192", "wlan0", "lo",
		"br-lan", "veth0", "bond0", "enp3s0", "wg0",
		"veth.1", "eth_0",
	}
	for _, name := range valid {
		if !isValidInterfaceName(name) {
			t.Errorf("isValidInterfaceName(%q) = false; want true", name)
		}
	}

	invalid := []string{
		"",                      // empty
		strings.Repeat("a", 16), // too long (>15)
		"eth0; rm -rf /",        // shell injection
		"eth0\neth1",            // newline
		"eth0$HOME",             // shell variable
		"eth0`id`",              // backtick
		"eth0 eth1",             // space
		"eth0|cat",              // pipe
	}
	for _, name := range invalid {
		if isValidInterfaceName(name) {
			t.Errorf("isValidInterfaceName(%q) = true; want false", name)
		}
	}
}

func TestIsValidInterfaceName_maxLength(t *testing.T) {
	if !isValidInterfaceName(strings.Repeat("a", 15)) {
		t.Error("15-char name should be valid")
	}
	if isValidInterfaceName(strings.Repeat("a", 16)) {
		t.Error("16-char name should be invalid")
	}
}

// ── prefixToNetmask ───────────────────────────────────────────────────────────

func TestPrefixToNetmask(t *testing.T) {
	cases := []struct {
		prefix int
		want   string
	}{
		{8, "255.0.0.0"},
		{16, "255.255.0.0"},
		{24, "255.255.255.0"},
		{32, "255.255.255.255"},
		{28, "255.255.255.240"},
	}
	for _, tc := range cases {
		got := prefixToNetmask(tc.prefix)
		if got != tc.want {
			t.Errorf("prefixToNetmask(%d) = %q; want %q", tc.prefix, got, tc.want)
		}
	}
}

// ── updateGrubContent ─────────────────────────────────────────────────────────

const grubBase = `GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX=""
`

const grubWithParam = `GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX="net.ifnames=0"
`

func TestUpdateGrubContent_emptyLine(t *testing.T) {
	ipParam := "ip=192.168.1.10::192.168.1.1:255.255.255.0:host:eth0:none"
	updated, changed := updateGrubContent(grubBase, ipParam)

	if !changed {
		t.Error("expected changed=true when adding ip= for the first time")
	}
	if !strings.Contains(updated, ipParam) {
		t.Errorf("updated GRUB content missing %q\ngot:\n%s", ipParam, updated)
	}
	// Ensure we didn't break the existing line structure
	if !strings.Contains(updated, `GRUB_CMDLINE_LINUX="`) {
		t.Error("GRUB_CMDLINE_LINUX line missing from updated content")
	}
}

func TestUpdateGrubContent_withExistingParams(t *testing.T) {
	ipParam := "ip=192.168.1.10::192.168.1.1:255.255.255.0:host:eth0:none"
	updated, changed := updateGrubContent(grubWithParam, ipParam)

	if !changed {
		t.Error("expected changed=true when adding ip= to non-empty line")
	}
	if !strings.Contains(updated, "net.ifnames=0") {
		t.Error("existing param net.ifnames=0 should be preserved")
	}
	if !strings.Contains(updated, ipParam) {
		t.Errorf("updated GRUB content missing %q\ngot:\n%s", ipParam, updated)
	}
}

func TestUpdateGrubContent_alreadyHasIP(t *testing.T) {
	content := `GRUB_CMDLINE_LINUX="ip=10.0.0.1::10.0.0.254:255.255.255.0:srv:eth0:none"`
	ipParam := "ip=192.168.1.10::192.168.1.1:255.255.255.0:host:eth0:none"

	_, changed := updateGrubContent(content, ipParam)
	if changed {
		t.Error("expected changed=false when ip= already present")
	}
}

func TestUpdateGrubContent_lineAbsent(t *testing.T) {
	content := `GRUB_DEFAULT=0
GRUB_TIMEOUT=5
`
	ipParam := "ip=192.168.1.10::192.168.1.1:255.255.255.0:host:eth0:none"
	updated, changed := updateGrubContent(content, ipParam)

	if !changed {
		t.Error("expected changed=true when GRUB_CMDLINE_LINUX line is absent")
	}
	if !strings.Contains(updated, `GRUB_CMDLINE_LINUX="`+ipParam+`"`) {
		t.Errorf("expected new GRUB_CMDLINE_LINUX line, got:\n%s", updated)
	}
}

func TestUpdateGrubContent_idempotent(t *testing.T) {
	ipParam := "ip=192.168.1.10::192.168.1.1:255.255.255.0:host:eth0:none"

	// Apply once
	first, _ := updateGrubContent(grubBase, ipParam)

	// Apply again — should not change
	_, changed := updateGrubContent(first, ipParam)
	if changed {
		t.Error("second application should be a no-op (changed=false)")
	}
}

func TestUpdateGrubContent_substringNotMistakenForIP(t *testing.T) {
	// Params like "gossip=" or "skip=" contain the substring "ip=" but are not
	// an ip= kernel param; a needed ip= must still be added.
	content := `GRUB_CMDLINE_LINUX="quiet gossip=on skip=1"`
	ipParam := "ip=192.168.1.10::192.168.1.1:255.255.255.0:host:eth0:none"

	updated, changed := updateGrubContent(content, ipParam)
	if !changed {
		t.Error("expected changed=true: gossip=/skip= must not be mistaken for ip=")
	}
	if !strings.Contains(updated, ipParam) {
		t.Errorf("updated GRUB content missing %q\ngot:\n%s", ipParam, updated)
	}
}

// ── ipParam format ────────────────────────────────────────────────────────────

func TestIPParamFormat(t *testing.T) {
	// Verify the ip= parameter format we generate matches the kernel's expectation:
	// ip=<client-ip>::<gateway>:<netmask>:<hostname>:<iface>:none
	ni := &NetworkInfo{
		IP:        "192.168.1.100",
		Gateway:   "192.168.1.1",
		Prefix:    24,
		Hostname:  "myserver",
		Interface: "eth0",
	}
	netmask := prefixToNetmask(ni.Prefix)
	got := "ip=" + ni.IP + "::" + ni.Gateway + ":" + netmask + ":" + ni.Hostname + ":" + ni.Interface + ":none"
	want := "ip=192.168.1.100::192.168.1.1:255.255.255.0:myserver:eth0:none"
	if got != want {
		t.Errorf("ip param = %q; want %q", got, want)
	}
}

// ── validateGrubNetFields / isValidHostname ───────────────────────────────────

func TestValidateGrubNetFields(t *testing.T) {
	base := func() *NetworkInfo {
		return &NetworkInfo{IP: "192.168.1.100", Gateway: "192.168.1.1", Hostname: "myserver", Interface: "eth0"}
	}
	if err := validateGrubNetFields(base()); err != nil {
		t.Errorf("valid fields: unexpected error %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*NetworkInfo)
	}{
		{"bad IP", func(n *NetworkInfo) { n.IP = "not-an-ip" }},
		{"bad gateway", func(n *NetworkInfo) { n.Gateway = "10.0.0.$(reboot)" }},
		{"hostname with shell metachar", func(n *NetworkInfo) { n.Hostname = "host;reboot" }},
		{"hostname with space", func(n *NetworkInfo) { n.Hostname = "host name" }},
		{"empty hostname", func(n *NetworkInfo) { n.Hostname = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ni := base()
			tt.mutate(ni)
			if err := validateGrubNetFields(ni); err == nil {
				t.Errorf("validateGrubNetFields() = nil; want error")
			}
		})
	}
}

func TestIsValidHostname(t *testing.T) {
	valid := []string{"server", "ubo-luks-server", "host.example.com", "h1"}
	for _, h := range valid {
		if !isValidHostname(h) {
			t.Errorf("isValidHostname(%q) = false; want true", h)
		}
	}
	invalid := []string{"", "host;reboot", "host name", "host`id`", "host$HOME", strings.Repeat("a", 64)}
	for _, h := range invalid {
		if isValidHostname(h) {
			t.Errorf("isValidHostname(%q) = true; want false", h)
		}
	}
}

// ── firstInetAddr ─────────────────────────────────────────────────────────────

func TestFirstInetAddr_found(t *testing.T) {
	// Typical `ip -4 addr show dev` output (192.254.68.234/29 is the real target).
	out := `2: ens3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    link/ether 52:54:00:01:02:03 brd ff:ff:ff:ff:ff:ff
    inet 192.254.68.234/29 brd 192.254.68.239 scope global ens3
       valid_lft forever preferred_lft forever`
	ip, prefix := firstInetAddr(out)
	if ip != "192.254.68.234" {
		t.Errorf("ip = %q; want 192.254.68.234", ip)
	}
	if prefix != 29 {
		t.Errorf("prefix = %d; want 29", prefix)
	}
}

func TestFirstInetAddr_notFound(t *testing.T) {
	ip, prefix := firstInetAddr("lo: flags=73  mtu 65536\nlink/loopback")
	if ip != "" || prefix != 0 {
		t.Errorf("firstInetAddr empty = (%q, %d); want (\"\", 0)", ip, prefix)
	}
}

func TestFirstInetAddr_loopbackSkipped(t *testing.T) {
	// Only a loopback address — firstInetAddr takes the first match regardless,
	// so this documents the behaviour rather than filtering loopback.
	out := "inet 127.0.0.1/8 scope host lo"
	ip, prefix := firstInetAddr(out)
	if ip != "127.0.0.1" || prefix != 8 {
		t.Errorf("firstInetAddr loopback = (%q, %d); want (127.0.0.1, 8)", ip, prefix)
	}
}

// ── buildSetupScriptData: bridge topology ─────────────────────────────────────

// minCfg returns a Config with the minimum fields needed by buildSetupScriptData.
func minCfg() *config.Config {
	return &config.Config{
		WireGuard: config.WGConfig{
			Port:     51820,
			ServerIP: "10.42.0.1/24",
			ClientIP: "10.42.0.2/32",
		},
		Dropbear: config.DBConfig{Port: 22},
	}
}

// minKeys returns a Keys struct with the minimum fields needed by buildSetupScriptData.
func minKeys() *keygen.Keys {
	return &keygen.Keys{
		ServerWGPrivate: "privatekey",
		ServerWGPublic:  "publickey",
		ClientWGPublic:  "clientpub",
		ClientSSHPubKey: "ssh-ed25519 AAAA ubo-client",
	}
}

// minNetInfo returns a plain-NIC NetworkInfo.
func minNetInfo() *NetworkInfo {
	return &NetworkInfo{
		Interface: "eth0",
		IP:        "192.168.1.100",
		Prefix:    24,
		Gateway:   "192.168.1.1",
		Hostname:  "server",
	}
}

// TestBuildSetupScriptData_bridgeUsesFirstPort verifies that when the default-
// route interface is a bridge (e.g. br0), buildSetupScriptData substitutes the
// first bridge port for both the initramfs WireGuard script and the GRUB ip=
// parameter. br0 does not exist in initramfs; the physical NIC does.
func TestBuildSetupScriptData_bridgeUsesFirstPort(t *testing.T) {
	ni := minNetInfo()
	ni.Interface = "br0"
	ni.BridgePorts = []string{"enp0s3", "enp0s4"}

	data, err := buildSetupScriptData(minCfg(), minKeys(), ni)
	if err != nil {
		t.Fatalf("buildSetupScriptData: %v", err)
	}

	if data.NetInterface != "enp0s3" {
		t.Errorf("NetInterface = %q; want enp0s3 (first bridge port)", data.NetInterface)
	}
	if data.GrubInterface != "enp0s3" {
		t.Errorf("GrubInterface = %q; want enp0s3 (first bridge port for GRUB ip=)", data.GrubInterface)
	}
	if strings.Contains(data.InitramfsScript, `IFACE="br0"`) {
		t.Error("initramfs script must not reference br0 (bridge not present in initramfs)")
	}
	if !strings.Contains(data.InitramfsScript, `IFACE="enp0s3"`) {
		t.Error("initramfs script should reference enp0s3 (first bridge port)")
	}
}

// TestBuildSetupScriptData_plainNIC verifies that a plain NIC passes through
// unchanged — the bridge/bond/VLAN fix must not alter non-virtual-iface setups.
func TestBuildSetupScriptData_plainNIC(t *testing.T) {
	ni := minNetInfo() // Interface = "eth0", no BridgePorts

	data, err := buildSetupScriptData(minCfg(), minKeys(), ni)
	if err != nil {
		t.Fatalf("buildSetupScriptData: %v", err)
	}

	if data.NetInterface != "eth0" {
		t.Errorf("NetInterface = %q; want eth0", data.NetInterface)
	}
	if data.GrubInterface != "eth0" {
		t.Errorf("GrubInterface = %q; want eth0", data.GrubInterface)
	}
	if !strings.Contains(data.InitramfsScript, `IFACE="eth0"`) {
		t.Error("initramfs script should reference eth0")
	}
}

// ── bond topology ─────────────────────────────────────────────────────────────

// TestBuildSetupScriptData_bond verifies that a bond interface generates an
// initramfs script that uses the first slave NIC directly (no bond created).
// Bond interfaces don't need to exist in the initramfs; the slave NIC provides
// the same physical connectivity. Not creating bond0 ensures ens3 is a plain
// NIC after pivot_root so DHCP works in the full OS.
func TestBuildSetupScriptData_bond(t *testing.T) {
	ni := minNetInfo()
	ni.Interface = "bond0"
	ni.BondSlaves = []string{"eth0", "eth1"}
	ni.BondMode = "active-backup"

	data, err := buildSetupScriptData(minCfg(), minKeys(), ni)
	if err != nil {
		t.Fatalf("buildSetupScriptData: %v", err)
	}

	// NetInterface is the slave NIC (for driver detection in the setup script).
	if data.NetInterface != "eth0" {
		t.Errorf("NetInterface = %q; want eth0 (slave NIC, no bond in initramfs)", data.NetInterface)
	}
	if data.GrubInterface != "eth0" {
		t.Errorf("GrubInterface = %q; want eth0 (first bond slave for GRUB ip=)", data.GrubInterface)
	}
	// Initramfs uses the slave NIC directly via the plain-NIC path; no bond.
	if strings.Contains(data.InitramfsScript, "modprobe bonding") {
		t.Error("initramfs script must NOT create bond (bond not needed for unlock)")
	}
	if !strings.Contains(data.InitramfsScript, `IFACE="eth0"`) {
		t.Error("initramfs script must assign IFACE=eth0 (slave NIC directly)")
	}
	// Must NOT set up a VLAN.
	if strings.Contains(data.InitramfsScript, "modprobe 8021q") {
		t.Error("plain bond script must not contain 8021q/VLAN setup")
	}
}

// ── VLAN topology ─────────────────────────────────────────────────────────────

// TestBuildSetupScriptData_vlan verifies that a VLAN interface generates an
// initramfs script that loads the 8021q module, brings up the physical parent
// NIC, and creates the VLAN interface with the correct ID. GrubInterface uses
// the physical parent NIC (not the VLAN) for the GRUB ip= kernel parameter.
func TestBuildSetupScriptData_vlan(t *testing.T) {
	ni := minNetInfo()
	ni.Interface = "eth0.100"
	ni.VLANPhysdev = "eth0"
	ni.VLANID = 100

	data, err := buildSetupScriptData(minCfg(), minKeys(), ni)
	if err != nil {
		t.Fatalf("buildSetupScriptData: %v", err)
	}

	if data.NetInterface != "eth0.100" {
		t.Errorf("NetInterface = %q; want eth0.100 (for driver detection)", data.NetInterface)
	}
	if data.GrubInterface != "eth0" {
		t.Errorf("GrubInterface = %q; want eth0 (VLAN physdev for GRUB ip=)", data.GrubInterface)
	}
	if !strings.Contains(data.InitramfsScript, "modprobe 8021q") {
		t.Error("initramfs script missing 'modprobe 8021q'")
	}
	if !strings.Contains(data.InitramfsScript, `IFACE="eth0.100"`) {
		t.Error("initramfs script must assign IFACE=eth0.100")
	}
	// Physical parent device must appear (to be brought up before the VLAN)
	if !strings.Contains(data.InitramfsScript, `"eth0"`) {
		t.Error("initramfs script missing physical parent device eth0")
	}
	if !strings.Contains(data.InitramfsScript, "id 100") {
		t.Error("initramfs script missing VLAN id 100")
	}
	// Must NOT set up a bond
	if strings.Contains(data.InitramfsScript, "modprobe bonding") {
		t.Error("plain VLAN script must not contain bonding setup")
	}
}

// ── VLAN-on-bond topology ─────────────────────────────────────────────────────

// TestBuildSetupScriptData_vlanOnBond verifies that a VLAN-on-bond topology
// generates an initramfs script that creates the VLAN directly on the bond slave
// NIC (eth0.100) rather than on the bond (bond0.100). No bond is created in the
// initramfs — the slave NIC provides the same physical connectivity for
// WireGuard + Dropbear unlock, and leaving ens3 un-enslaved ensures DHCP works
// after pivot_root in the full OS.
func TestBuildSetupScriptData_vlanOnBond(t *testing.T) {
	ni := minNetInfo()
	ni.Interface = "bond0.100"
	ni.VLANPhysdev = "bond0"
	ni.VLANID = 100
	ni.BondSlaves = []string{"eth0"}
	ni.BondMode = "active-backup"

	data, err := buildSetupScriptData(minCfg(), minKeys(), ni)
	if err != nil {
		t.Fatalf("buildSetupScriptData: %v", err)
	}

	// NetInterface is the real sysfs interface (bond0.100) for driver detection —
	// ens3.100 doesn't exist in sysfs on the remote server at ubo-run time.
	if data.NetInterface != "bond0.100" {
		t.Errorf("NetInterface = %q; want bond0.100 (real sysfs NIC for driver detection)", data.NetInterface)
	}
	if data.GrubInterface != "eth0" {
		t.Errorf("GrubInterface = %q; want eth0 (bond slave for GRUB ip=)", data.GrubInterface)
	}
	// No bond in initramfs; VLAN is created directly on the slave NIC.
	if strings.Contains(data.InitramfsScript, "modprobe bonding") {
		t.Error("initramfs script must NOT create bond (bond not needed for unlock)")
	}
	if !strings.Contains(data.InitramfsScript, "modprobe 8021q") {
		t.Error("initramfs script missing 'modprobe 8021q'")
	}
	// IFACE should be the VLAN on the slave NIC, not the bond.
	if !strings.Contains(data.InitramfsScript, `IFACE="eth0.100"`) {
		t.Error("initramfs script must assign IFACE=eth0.100 (slave NIC VLAN)")
	}
	if strings.Contains(data.InitramfsScript, `IFACE="bond0`) {
		t.Error("initramfs script must not reference bond0 (bond not created in initramfs)")
	}
	if !strings.Contains(data.InitramfsScript, "id 100") {
		t.Error("initramfs script missing VLAN id 100")
	}
	// Slave NIC must appear as the VLAN parent (physdev).
	if !strings.Contains(data.InitramfsScript, `"eth0"`) {
		t.Error("initramfs script missing slave NIC eth0 as VLAN parent")
	}
}
