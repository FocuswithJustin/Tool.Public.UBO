//go:build integration

package tests

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Topology integration tests: each test applies a specific Linux network
// topology (bridge, bond, VLAN, VLAN-on-bond) to the LUKS server VM, then
// verifies the full ubo run → reboot → ubo unlock → decrypted-boot cycle.
//
// The test uses the same two-VM setup as TestUBOUnlock_Integration:
//   - Client VM: router with NAT + dnsmasq + (for VLAN tests) a lan.100 VLAN iface
//   - Server VM: LUKS-encrypted single NIC (e1000, eth0) on the socket link
//
// After the first boot, a topology script is applied to the server in the
// background (nohup). Once done, ubo run configures the server for the new
// topology. The server reboots into initramfs, ubo unlock decrypts it, and we
// verify it booted into the full decrypted OS.

const (
	vlanID       = 100
	vlanServerIP = "10.99.1.2"
	vlanClientIP = "10.99.1.1"
)

// topoSpec describes a single network topology integration test.
type topoSpec struct {
	name        string // human-readable label for log messages
	needsVLAN   bool   // client seed must include lan.100 VLAN interface
	applyScript string // shell commands to run on server to apply topology
	host        string // IP used in ubo.toml host field (server's IP for ubo run)
	networkIP   string // network.ip in ubo.toml (static IP/CIDR override)
	waitIP      string // server IP to verify SSH reachability after topology change
	doneIP      string // server IP to poll for TOPOLOGY_DONE (defaults to serverLinkIP)
}

var (
	bridgeSpec = topoSpec{
		name:      "bridge",
		needsVLAN: false,
		// NIC is detected dynamically: Debian Trixie renames e1000 to ens3, not eth0.
		//
		// Key ordering: assign 10.99.0.2/24 to br0 BEFORE enslaving the NIC.
		// When the NIC is enslaved, Linux removes its address. If br0 already has
		// the address, the connected route stays active with no gap.
		applyScript: `#!/bin/sh
NIC=$(ip route show default | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1);exit}}')
[ -z "$NIC" ] && NIC=$(ls /sys/class/net/ | grep -v lo | head -1)
echo "bridge topology: NIC=$NIC" >&2
systemctl stop networking 2>/dev/null || true
pkill dhclient 2>/dev/null || pkill dhcpcd 2>/dev/null || true
# Create and configure br0 BEFORE enslaving the NIC to eliminate the IP gap.
ip link add name br0 type bridge 2>/dev/null || true
ip link set br0 up 2>/dev/null || true
ip addr add 10.99.0.2/24 dev br0 2>/dev/null || true
ip route add default via 10.99.0.1 dev br0 2>/dev/null || true
# Now enslave the NIC (Linux removes its IP, but br0 already has it).
ip link set "$NIC" master br0 2>/dev/null || true
ip link set "$NIC" up 2>/dev/null || true
# Remove stale IP/route from the physical NIC (should be gone already).
ip addr del 10.99.0.2/24 dev "$NIC" 2>/dev/null || true
ip route del default via 10.99.0.1 dev "$NIC" 2>/dev/null || true
`,
		host:      serverLinkIP,
		networkIP: serverLinkIP + "/24",
		waitIP:    serverLinkIP,
		doneIP:    serverLinkIP,
	}

	bondSpec = topoSpec{
		name:      "bond",
		needsVLAN: false,
		// Mirrors the bridge approach: assign IP to bond0 BEFORE enslaving the NIC
		// so there is never a window where 10.99.0.2 is unreachable.
		// bond0 can be brought up with no slaves; it will have NO-CARRIER until ens3
		// is enslaved, but the IP/route are installed and ARP works once carrier comes.
		// After the topology is stable, stop networkd+socket to prevent it from
		// reconfiguring bond slaves later.
		applyScript: `#!/bin/sh
NIC=$(ip route show default | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1);exit}}')
[ -z "$NIC" ] && NIC=$(ls /sys/class/net/ | grep -v lo | head -1)
echo "bond topology: NIC=$NIC" >&2
# Kill DHCP clients first so they cannot restore ens3's addresses mid-script
# or reinstall a default route via ens3 after we remove it.
pkill -f dhclient 2>/dev/null; pkill -f dhcpcd 2>/dev/null; true
systemctl stop networking 2>/dev/null || true
systemctl stop NetworkManager 2>/dev/null || true
modprobe bonding 2>/dev/null || true
ip link add name bond0 type bond 2>/dev/null || true
echo active-backup > /sys/class/net/bond0/bonding/mode 2>/dev/null || true
# Bring bond0 up before enslaving and assign IP immediately (like bridge does).
ip link set bond0 up 2>/dev/null || true
ip addr add 10.99.0.2/24 dev bond0 2>/dev/null || true
# Remove the DHCP-installed default route (via ens3) before adding ours.
# 'ip route add' fails with EEXIST if a default already exists; if we leave
# the ens3 route in place and then enslave ens3, the server loses its default
# route and cannot send TCP replies → client sees "No route to host".
ip route del default 2>/dev/null || true
ip route add default via 10.99.0.1 dev bond0 2>/dev/null || true
# Flush NIC addresses and enslave into bond0.
ip addr flush dev "$NIC" 2>/dev/null || true
ip link set "$NIC" down 2>/dev/null || true
ip link set "$NIC" master bond0 2>/dev/null || true
# Ensure bond0 still has the IP/route (defensive restore).
ip addr show dev bond0 2>/dev/null | grep -q '10\.99\.0\.2' || \
  ip addr add 10.99.0.2/24 dev bond0 2>/dev/null || true
ip route show 2>/dev/null | grep -q '^default' || \
  ip route add default via 10.99.0.1 dev bond0 2>/dev/null || true
`,
		host:      serverLinkIP,
		networkIP: serverLinkIP + "/24",
		waitIP:    serverLinkIP,
		doneIP:    serverLinkIP,
	}

	vlanSpec = topoSpec{
		name:      "vlan",
		needsVLAN: true,
		// Disable hardware VLAN offload on the NIC so 802.1Q frames are handled
		// purely in software — required for QEMU e1000 which may silently drop
		// VLAN-tagged frames when HW VLAN filtering is active.
		applyScript: `#!/bin/sh
NIC=$(ip route show default | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1);exit}}')
[ -z "$NIC" ] && NIC=$(ls /sys/class/net/ | grep -v lo | head -1)
VLAN_IF="${NIC}.100"
echo "vlan topology: NIC=$NIC VLAN_IF=$VLAN_IF" >&2
# Kill DHCP clients first so they cannot restore the ens3 default route after
# we remove it. Same EEXIST fix as bond: 'ip route add default' fails silently
# when a route already exists (installed by dhclient on NIC).
pkill -f dhclient 2>/dev/null; pkill -f dhcpcd 2>/dev/null; true
systemctl stop networking 2>/dev/null || true
modprobe 8021q 2>/dev/null || true
ip link set "$NIC" up
ip link add link "$NIC" name "$VLAN_IF" type vlan id 100 2>/dev/null || true
ip link set "$VLAN_IF" up
ip addr add 10.99.1.2/24 dev "$VLAN_IF" 2>/dev/null || true
# Remove the DHCP-installed default route (via NIC) before adding the VLAN route.
# Without this, 'ip route add default via 10.99.1.1' fails with EEXIST and the
# default route stays on NIC, so ubo run detects NIC (not VLAN_IF) as the iface.
ip route del default 2>/dev/null || true
ip route add default via 10.99.1.1 dev "$VLAN_IF" 2>/dev/null || true
`,
		host:   vlanServerIP,
		// ubo run must detect the VLAN interface and configure for 10.99.1.2.
		networkIP: vlanServerIP + "/24",
		// Poll TOPOLOGY_DONE at serverLinkIP (ens3 keeps 10.99.0.2 on its
		// connected route even after the default route changes to the VLAN iface).
		doneIP: serverLinkIP,
		waitIP: vlanServerIP,
	}

	vlanOnBondSpec = topoSpec{
		name:      "vlan-on-bond",
		needsVLAN: true,
		// Same IP-before-enslave pattern: bond0 gets 10.99.0.2 before ens3 is
		// enslaved, then VLAN bond0.100 is added on top with 10.99.1.2.
		// Default route via bond0.100 so ubo run detects bond0.100 as interface.
		// bond0 keeps 10.99.0.2 so TOPOLOGY_DONE polling at serverLinkIP works.
		applyScript: `#!/bin/sh
NIC=$(ip route show default | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1);exit}}')
[ -z "$NIC" ] && NIC=$(ls /sys/class/net/ | grep -v lo | head -1)
echo "vlan-on-bond topology: NIC=$NIC" >&2
# Kill DHCP clients first — same reason as bond: prevents ens3 route restore.
pkill -f dhclient 2>/dev/null; pkill -f dhcpcd 2>/dev/null; true
systemctl stop networking 2>/dev/null || true
systemctl stop NetworkManager 2>/dev/null || true
# Disable HW VLAN offload before enslaving.
ethtool -K "$NIC" rxvlan off txvlan off 2>/dev/null || true
modprobe bonding 2>/dev/null || true
modprobe 8021q 2>/dev/null || true
ip link add name bond0 type bond 2>/dev/null || true
echo active-backup > /sys/class/net/bond0/bonding/mode 2>/dev/null || true
ip link set bond0 up 2>/dev/null || true
ip addr add 10.99.0.2/24 dev bond0 2>/dev/null || true
# Remove the DHCP default route before installing ours (same EEXIST bug as bond).
ip route del default 2>/dev/null || true
ip route add default via 10.99.0.1 dev bond0 2>/dev/null || true
# Flush NIC addresses and enslave into bond0.
ip addr flush dev "$NIC" 2>/dev/null || true
ip link set "$NIC" down 2>/dev/null || true
ip link set "$NIC" master bond0 2>/dev/null || true
# Add VLAN on top of bond0.
ip link add link bond0 name bond0.100 type vlan id 100 2>/dev/null || true
ip link set bond0.100 up 2>/dev/null || true
ip addr add 10.99.1.2/24 dev bond0.100 2>/dev/null || true
# Change default route to go via bond0.100 so ubo run detects bond0.100.
# bond0 keeps 10.99.0.2 so TOPOLOGY_DONE polling at serverLinkIP still works.
ip route del default 2>/dev/null || true
ip route add default via 10.99.1.1 dev bond0.100 2>/dev/null || true
# Defensive restore.
ip addr show dev bond0 2>/dev/null | grep -q '10\.99\.0\.2' || \
  ip addr add 10.99.0.2/24 dev bond0 2>/dev/null || true
ip addr show dev bond0.100 2>/dev/null | grep -q '10\.99\.1\.2' || \
  ip addr add 10.99.1.2/24 dev bond0.100 2>/dev/null || true
ip route show 2>/dev/null | grep -q '^default' || \
  ip route add default via 10.99.1.1 dev bond0.100 2>/dev/null || true
`,
		host:   vlanServerIP,
		// ubo run targets 10.99.1.2 to detect bond0.100 topology.
		networkIP: vlanServerIP + "/24",
		// Poll TOPOLOGY_DONE at bond0 IP (serverLinkIP still reachable);
		// verify VLAN IP separately via waitServerSSHAt.
		doneIP: serverLinkIP,
		waitIP: vlanServerIP,
	}
)

// buildClientSeedWithVLAN is like buildClientSeed but also configures a VLAN
// interface (lan.100 at 10.99.1.1/24) on the client and adds NAT forwarding
// for the VLAN subnet. This is required for VLAN topology tests where the
// server's default route changes to 10.99.1.1.
func buildClientSeedWithVLAN(t *testing.T) string {
	t.Helper()
	seedDir := tmpPath("client-seed-vlan")
	if err := os.MkdirAll(seedDir, 0755); err != nil {
		t.Fatalf("mkdir seed dir: %v", err)
	}

	metaData := "instance-id: ubo-vlan-client-001\nlocal-hostname: ubo-client\n"

	networkConfig := fmt.Sprintf(`version: 1
config:
  - type: physical
    name: wan
    mac_address: "%s"
    subnets:
      - type: dhcp4
  - type: physical
    name: lan
    mac_address: "%s"
    subnets:
      - type: static
        address: 10.99.0.1/24
`, clientWANMAC, clientLANMAC)

	userData := fmt.Sprintf(`#cloud-config
hostname: ubo-client
disable_root: false
ssh_pwauth: false
users:
  - name: root
    lock_passwd: true
    ssh_authorized_keys:
      - %s
write_files:
  - path: /etc/dnsmasq.d/ubo.conf
    permissions: '0644'
    content: |
      interface=lan
      bind-interfaces
      dhcp-range=10.99.0.50,10.99.0.150,255.255.255.0,1h
      dhcp-host=%s,%s
      dhcp-option=3,10.99.0.1
      dhcp-option=6,10.99.0.1
      server=10.0.2.3
runcmd:
  - sysctl -w net.ipv4.ip_forward=1
  - iptables -t nat -A POSTROUTING -o wan -j MASQUERADE
  - iptables -A FORWARD -i lan -o wan -j ACCEPT
  - iptables -A FORWARD -i wan -o lan -m state --state RELATED,ESTABLISHED -j ACCEPT
  - DEBIAN_FRONTEND=noninteractive apt-get update -y
  - DEBIAN_FRONTEND=noninteractive apt-get install -y dnsmasq wireguard-tools expect openssh-client iputils-ping iptables
  - systemctl enable dnsmasq
  - systemctl restart dnsmasq
  - modprobe 8021q
  - ip link add link lan name lan.100 type vlan id %d || true
  - ip addr add %s/24 dev lan.100 || true
  - ip link set lan.100 up || true
  - iptables -A FORWARD -i lan.100 -o wan -j ACCEPT || true
  - iptables -A FORWARD -i wan -o lan.100 -m state --state RELATED,ESTABLISHED -j ACCEPT || true
  - touch /root/CLIENT_SETUP_DONE
`, readPubKey(t), serverLinkMAC, serverLinkIP, vlanID, vlanClientIP)

	writeSeedFile(t, seedDir+"/meta-data", metaData)
	writeSeedFile(t, seedDir+"/user-data", userData)
	writeSeedFile(t, seedDir+"/network-config", networkConfig)

	seedISO := tmpPath("client-seed-vlan.iso")
	out, err := exec.Command("xorriso", "-as", "mkisofs",
		"-output", seedISO,
		"-volid", "cidata",
		"-joliet", "-rock",
		"-input-charset", "utf-8",
		seedDir+"/user-data",
		seedDir+"/meta-data",
		seedDir+"/network-config",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("build client VLAN seed iso: %v\n%s", err, out)
	}
	return seedISO
}

// sshToServerAt builds an SSH command (run on the client) to the server at ip.
func sshToServerAt(ip, cmd string) string {
	return "ssh -i /root/test_ed25519 -o StrictHostKeyChecking=no " +
		"-o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o BatchMode=yes " +
		"-o LogLevel=ERROR root@" + ip + " " + shellQuote(cmd)
}

// waitServerSSHAt blocks until the client can SSH into the server at ip.
func waitServerSSHAt(t *testing.T, ip string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out := runOnClient(t, true, sshToServerAt(ip, "echo server-ready"))
		if strings.Contains(out, "server-ready") {
			return
		}
		time.Sleep(5 * time.Second)
	}
	diag := runOnClient(t, true,
		"echo '--- client addrs ---'; ip -br addr; echo '--- routes ---'; ip route; "+
			"echo '--- ping "+ip+" ---'; ping -c2 -W2 "+ip+" 2>&1; "+
			"echo '--- arp ---'; ip neigh")
	t.Fatalf("server not reachable at %s from client within %v\ndiagnostics:\n%s",
		ip, timeout, diag)
}

// applyServerTopology writes the topology script to the server and runs it in
// the background (nohup). It polls for a TOPOLOGY_DONE marker at spec.doneIP
// (defaults to serverLinkIP), which is always reachable even after the topology
// changes the primary IP. VLAN connectivity (spec.waitIP) is verified separately
// by the caller via waitServerSSHAt.
func applyServerTopology(t *testing.T, spec topoSpec, timeout time.Duration) {
	t.Helper()

	pollIP := spec.doneIP
	if pollIP == "" {
		pollIP = serverLinkIP
	}

	// Write script to local tmp/, SCP to client, then SCP from client to server.
	localScript := tmpPath("topo-" + spec.name + ".sh")
	content := spec.applyScript + "\ntouch /root/TOPOLOGY_DONE\n"
	if err := os.WriteFile(localScript, []byte(content), 0755); err != nil {
		t.Fatalf("write topology script: %v", err)
	}
	scpToClient(t, localScript, "/tmp/topo.sh")

	// SCP from client to server at serverLinkIP (server is always reachable here
	// BEFORE the topology change).
	runOnClient(t, false,
		"scp -i /root/test_ed25519 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "+
			"-o BatchMode=yes -o LogLevel=ERROR /tmp/topo.sh root@"+serverLinkIP+":/tmp/topo.sh")

	// Launch the topology script in the background so SSH session drop won't kill it.
	runOnClient(t, true, sshToServer("nohup sh /tmp/topo.sh >/tmp/topo.log 2>&1 &"))

	// Poll for the DONE marker at pollIP (always reachable even after topology change).
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out := runOnClient(t, true,
			sshToServerAt(pollIP, "test -f /root/TOPOLOGY_DONE && echo done || echo waiting"))
		if strings.Contains(out, "done") {
			log := runOnClient(t, true,
				sshToServerAt(pollIP, "cat /tmp/topo.log 2>/dev/null || echo 'no log'"))
			t.Logf("[%s] topology script output:\n%s", spec.name, log)
			netState := runOnClient(t, true,
				sshToServerAt(pollIP, "ip -br addr; ip route"))
			t.Logf("[%s] server network state after topology:\n%s", spec.name, netState)
			return
		}
		time.Sleep(3 * time.Second)
	}
	// Gather diagnostics from the always-reachable poll IP; also include the
	// server serial log which is readable from the host even if SSH is broken.
	log := runOnClient(t, true,
		sshToServerAt(pollIP, "cat /tmp/topo.log 2>/dev/null; echo '---'; ip -br addr; ip route"))
	t.Fatalf("[%s] topology did not complete within %v; topo log:\n%s\nserver serial tail:\n%s",
		spec.name, timeout, log, tailFile(tmpPath("server-serial.log"), 50))
}

// runUboRunForTopo writes a topology-specific ubo.toml to the client and runs
// 'ubo run'. The host and network.ip fields reflect the server's IP after the
// topology change (e.g. 10.99.1.2 for VLAN).
func runUboRunForTopo(t *testing.T, spec topoSpec) {
	t.Helper()
	uboToml := fmt.Sprintf(`host = "%s"

[ssh]
user = "root"
port = 22
key  = "/root/test_ed25519"

[wireguard]
port      = 51820
server_ip = "10.42.0.1/24"
client_ip = "10.42.0.2/32"

[dropbear]
port = 22

[output]
dir = "/root/ubo-out"

[network]
ip = "%s"
`, spec.host, spec.networkIP)
	writeRemoteFile(t, "/root/ubo.toml", uboToml)
	runOut := runOnClient(t, false, "cd /root && ./ubo run --config ubo.toml 2>&1")
	t.Logf("[%s] ubo run output:\n%s", spec.name, runOut)
	if !strings.Contains(runOut, "configuration complete") {
		t.Fatalf("[%s] ubo run did not report completion", spec.name)
	}
}

// runTopologyTest is the shared driver for all topology integration tests.
// It boots both VMs, applies the given topology, runs ubo run + unlock, and
// verifies the server decrypted successfully.
func runTopologyTest(t *testing.T, spec topoSpec) {
	t.Helper()
	checkLUKSPrereqs(t)
	bootTimeout, setupTimeout := unlockTimeouts(t)

	// ── 1. Client VM ─────────────────────────────────────────────────────────
	t.Logf("[%s] Building client seed + booting client VM...", spec.name)
	var seed string
	if spec.needsVLAN {
		seed = buildClientSeedWithVLAN(t)
	} else {
		seed = buildClientSeed(t)
	}
	startClientVM(t, seed)
	waitForSSHReadyPort(t, clientSSHPort, bootTimeout)
	t.Logf("[%s] Waiting for client NAT/dnsmasq setup...", spec.name)
	waitForClientSetup(t, setupTimeout)

	// ── 2. Deploy ubo + SSH key to client ────────────────────────────────────
	t.Logf("[%s] Deploying ubo + key to client...", spec.name)
	scpToClient(t, buildStaticUbo(t), "/root/ubo")
	scpToClient(t, tmpPath("test_ed25519"), "/root/test_ed25519")
	runOnClient(t, false, "chmod +x /root/ubo && chmod 600 /root/test_ed25519")

	// ── 3. LUKS server — boot + unlock first boot over serial ────────────────
	t.Logf("[%s] Booting LUKS server on the link...", spec.name)
	srv := startLinkedServer(t)
	t.Logf("[%s] Unlocking server first boot over serial...", spec.name)
	srv.unlock(t, bootTimeout)
	t.Logf("[%s] Waiting for server SSH at %s...", spec.name, serverLinkIP)
	waitServerSSHFromClient(t, bootTimeout)

	// ── 4. Apply topology ────────────────────────────────────────────────────
	t.Logf("[%s] Applying %s topology...", spec.name, spec.name)
	applyServerTopology(t, spec, 90*time.Second)
	t.Logf("[%s] Waiting for server SSH at %s after topology change...", spec.name, spec.waitIP)
	waitServerSSHAt(t, spec.waitIP, bootTimeout)

	// Flush the client's ARP cache and pause briefly so any transient bond/bridge
	// instability resolves before ubo run opens its SSH connection.
	runOnClient(t, true, "ip neigh flush all 2>/dev/null || true")
	time.Sleep(5 * time.Second)

	// ── 5. ubo run ───────────────────────────────────────────────────────────
	t.Logf("[%s] Running ubo run...", spec.name)
	runUboRunForTopo(t, spec)

	// ── 6. Reboot server into Dropbear+WireGuard initramfs ───────────────────
	t.Logf("[%s] Rebooting server into Dropbear+WireGuard initramfs...", spec.name)
	runOnClient(t, true, sshToServerAt(spec.waitIP, "systemctl reboot")+" || true")
	time.Sleep(35 * time.Second)

	// ── 7. ubo unlock ────────────────────────────────────────────────────────
	t.Logf("[%s] Running ubo unlock from the client...", spec.name)
	runUboUnlock(t)

	// ── 8. Verify server decrypted and booted ────────────────────────────────
	// After LUKS unlock, the server boots into the full OS. cloud-init restores
	// standard networking (eth0 DHCP = 10.99.0.2), so verifyServerDecrypted
	// correctly polls serverLinkIP regardless of which topology was active in
	// the initramfs.
	verifyServerDecrypted(t, bootTimeout)
}

// TestUBOTopology_Bridge_Integration verifies the full ubo run → unlock cycle
// when the server's default-route interface is a Linux bridge (br0). The bridge
// is not present in initramfs, so ubo must substitute the first bridge port
// (eth0) in both the WireGuard initramfs script and the GRUB ip= parameter.
func TestUBOTopology_Bridge_Integration(t *testing.T) {
	runTopologyTest(t, bridgeSpec)
}

// TestUBOTopology_Bond_Integration verifies the full cycle when the server's
// default-route interface is a bonding master (bond0 with eth0 as the sole
// slave in active-backup mode).
func TestUBOTopology_Bond_Integration(t *testing.T) {
	runTopologyTest(t, bondSpec)
}

// TestUBOTopology_VLAN_Integration verifies the full cycle when the server's
// default-route interface is an 802.1Q VLAN (eth0.100 at 10.99.1.2/24). The
// client VM is configured with a matching VLAN interface (lan.100 at
// 10.99.1.1/24) so ubo can reach the server.
func TestUBOTopology_VLAN_Integration(t *testing.T) {
	runTopologyTest(t, vlanSpec)
}

// TestUBOTopology_VLANonBond_Integration verifies the full cycle for the
// VLAN-on-bond topology: bond0 (active-backup, eth0 slave) with bond0.100 as
// the default-route VLAN interface.
func TestUBOTopology_VLANonBond_Integration(t *testing.T) {
	runTopologyTest(t, vlanOnBondSpec)
}
