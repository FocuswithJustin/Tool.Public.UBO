//go:build integration

package tests

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Two-VM topology constants. The client and server are joined by a userspace
// QEMU "socket" netdev (an L2 wire carried over a localhost TCP port) — no host
// root, no TAP. The client is the operator's machine AND the server's router.
const (
	linkPort      = 12399               // localhost TCP port carrying the L2 link
	serverLinkMAC = "52:54:00:00:00:02" // server NIC on the link (pinned in dnsmasq)
	clientWANMAC  = "52:54:00:00:aa:01" // client NIC on user-net (internet)
	clientLANMAC  = "52:54:00:00:aa:02" // client NIC on the link
	clientSSHPort = 2224                // host-forwarded SSH into the client VM
	serverLinkIP  = "10.99.0.2"         // server's pinned DHCP address on the link
)

// sshClientArgs returns ssh args to reach the client VM over the host forward.
func sshClientArgs(extra ...string) []string {
	absKey, _ := filepath.Abs(tmpPath("test_ed25519"))
	args := []string{
		"-i", absKey,
		"-p", fmt.Sprintf("%d", clientSSHPort),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=10",
		"-o", "BatchMode=yes",
		"-o", "LogLevel=ERROR",
	}
	args = append(args, extra...)
	return args
}

// runOnClient runs a command inside the client VM, returning combined output.
// allowFail controls whether a non-zero exit fails the test.
func runOnClient(t *testing.T, allowFail bool, cmd string) string {
	t.Helper()
	args := append(sshClientArgs("root@127.0.0.1"), cmd)
	out, err := exec.Command("ssh", args...).CombinedOutput()
	if err != nil && !allowFail {
		t.Fatalf("client cmd %q failed: %v\nOutput:\n%s", cmd, err, out)
	}
	return string(out)
}

// scpToClient copies a local file into the client VM.
func scpToClient(t *testing.T, localPath, remotePath string) {
	t.Helper()
	absKey, _ := filepath.Abs(tmpPath("test_ed25519"))
	args := []string{
		"-i", absKey,
		"-P", fmt.Sprintf("%d", clientSSHPort),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=10",
		"-o", "BatchMode=yes",
		"-o", "LogLevel=ERROR",
		localPath,
		"root@127.0.0.1:" + remotePath,
	}
	out, err := exec.Command("scp", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("scp %s -> %s failed: %v\n%s", localPath, remotePath, err, out)
	}
}

// buildClientSeed writes a NoCloud seed ISO that configures the client VM:
//   - network-config v1: WAN (DHCP, internet) + LAN (static 10.99.0.1/24), by MAC
//   - user-data runcmd: IP forwarding + NAT, then install dnsmasq/wireguard-tools/
//     expect, configure dnsmasq (pin server -> 10.99.0.2, advertise gw/dns), and
//     drop a completion marker.
func buildClientSeed(t *testing.T) string {
	t.Helper()
	seedDir := tmpPath("client-seed")
	if err := os.MkdirAll(seedDir, 0755); err != nil {
		t.Fatalf("mkdir seed dir: %v", err)
	}

	metaData := "instance-id: ubo-unlock-client-001\nlocal-hostname: ubo-client\n"

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
  - touch /root/CLIENT_SETUP_DONE
`, readPubKey(t), serverLinkMAC, serverLinkIP)

	writeSeedFile(t, filepath.Join(seedDir, "meta-data"), metaData)
	writeSeedFile(t, filepath.Join(seedDir, "user-data"), userData)
	writeSeedFile(t, filepath.Join(seedDir, "network-config"), networkConfig)

	seedISO := tmpPath("client-seed.iso")
	out, err := exec.Command("xorriso", "-as", "mkisofs",
		"-output", seedISO,
		"-volid", "cidata",
		"-joliet", "-rock",
		"-input-charset", "utf-8",
		filepath.Join(seedDir, "user-data"),
		filepath.Join(seedDir, "meta-data"),
		filepath.Join(seedDir, "network-config"),
	).CombinedOutput()
	if err != nil {
		t.Fatalf("build client seed iso: %v\n%s", err, out)
	}
	return seedISO
}

// buildStaticUbo builds a fully static ubo binary (CGO disabled) so it runs
// inside the Debian VM, which lacks the nix store's ELF interpreter that a normal
// nix-shell build depends on. Returns the path to the built binary.
func buildStaticUbo(t *testing.T) string {
	t.Helper()
	out := tmpPath("ubo-static")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = projectRoot()
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build static ubo: %v\n%s", err, b)
	}
	return out
}

func writeSeedFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readPubKey(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(tmpPath("test_ed25519.pub"))
	if err != nil {
		t.Fatalf("read test pubkey: %v", err)
	}
	return strings.TrimSpace(string(b))
}

// startClientVM boots the client VM. It listens on the socket link (the server
// connects later) and forwards host:clientSSHPort -> guest:22.
func startClientVM(t *testing.T, seedISO string) {
	t.Helper()
	serialLog := tmpPath("client-serial.log")
	args := []string{
		"-m", "1024",
		"-nographic",
		"-drive", "file=" + tmpPath("debian-trixie.qcow2") + ",format=qcow2,if=virtio,snapshot=on",
		"-drive", "file=" + seedISO + ",format=raw,if=virtio,media=cdrom,readonly=on",
		// WAN: user-mode networking + host SSH forward
		"-netdev", fmt.Sprintf("user,id=wan,hostfwd=tcp::%d-:22", clientSSHPort),
		"-device", "virtio-net-pci,netdev=wan,mac=" + clientWANMAC,
		// LAN: L2 socket link (listen; server connects)
		"-netdev", fmt.Sprintf("socket,id=lan,listen=:%d", linkPort),
		"-device", "virtio-net-pci,netdev=lan,mac=" + clientLANMAC,
		"-serial", "file:" + serialLog,
	}
	if _, err := os.Stat("/dev/kvm"); err == nil {
		args = append([]string{"-enable-kvm", "-cpu", "host"}, args...)
	}
	cmd := exec.Command("qemu-system-x86_64", args...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start client QEMU: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
	})
}

// startLinkedServer boots the LUKS server with a single NIC on the socket link
// (connecting to the client's listener) plus a serial control socket. No
// user-mode NIC, so the server's only default route is via the client — which is
// what ubo bakes into the initramfs.
func startLinkedServer(t *testing.T) *luksServer {
	t.Helper()
	serialSock := tmpPath("server-serial.sock")
	os.Remove(serialSock)
	serialLog := tmpPath("server-serial.log")
	args := []string{
		"-m", "1024",
		"-nographic",
		"-drive", "file=" + tmpPath("debian-luks.qcow2") + ",format=qcow2,if=virtio,snapshot=on",
		"-netdev", fmt.Sprintf("socket,id=link,connect=127.0.0.1:%d", linkPort),
		"-device", "virtio-net-pci,netdev=link,mac=" + serverLinkMAC,
		"-chardev", "socket,id=serial0,path=" + serialSock + ",server=on,wait=off,logfile=" + serialLog,
		"-serial", "chardev:serial0",
	}
	if _, err := os.Stat("/dev/kvm"); err == nil {
		args = append([]string{"-enable-kvm", "-cpu", "host"}, args...)
	}
	cmd := exec.Command("qemu-system-x86_64", args...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server QEMU: %v", err)
	}
	s := &luksServer{serialSock: serialSock, cmd: cmd}
	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
	})
	return s
}

// waitForClientSetup blocks until the client VM's cloud-init has finished its
// NAT/dnsmasq setup (the CLIENT_SETUP_DONE marker exists).
func waitForClientSetup(t *testing.T, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out := runOnClient(t, true, "test -f /root/CLIENT_SETUP_DONE && echo done || echo waiting")
		if strings.Contains(out, "done") {
			return
		}
		time.Sleep(5 * time.Second)
	}
	t.Fatalf("client cloud-init setup did not complete within %v\nclient serial tail:\n%s",
		timeout, tailFile(tmpPath("client-serial.log"), 40))
}

func tailFile(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// unlockTimeouts returns the (boot, setup) timeouts, longer without KVM.
func unlockTimeouts(t *testing.T) (time.Duration, time.Duration) {
	t.Helper()
	if _, err := os.Stat("/dev/kvm"); err != nil {
		t.Log("KVM not available — using software emulation (slower)")
		return 12 * time.Minute, 15 * time.Minute
	}
	return 4 * time.Minute, 6 * time.Minute
}

// verifyServerDecrypted confirms the server booted to the decrypted system after
// a remote unlock.
func verifyServerDecrypted(t *testing.T, bootTimeout time.Duration) {
	t.Helper()
	t.Log("Verifying server finished booting after remote unlock...")
	waitServerSSHFromClient(t, bootTimeout)
	host := strings.TrimSpace(runOnClient(t, false, sshToServer("hostname")))
	if !strings.Contains(host, "ubo-luks-server") {
		t.Errorf("server hostname after unlock = %q; want ubo-luks-server", host)
	}
	rootSrc := strings.TrimSpace(runOnClient(t, false, sshToServer("findmnt -no SOURCE /")))
	if !strings.Contains(rootSrc, "vg0") {
		t.Errorf("server root source after unlock = %q; want decrypted LVM (vg0)", rootSrc)
	}
	t.Log("Full remote LUKS unlock over WireGuard succeeded.")
}

// TestUBOUnlock_Integration exercises the COMPLETE remote-unlock path end to end,
// entirely inside VMs:
//
//  1. Boot the client VM (router + operator machine): NAT + dnsmasq + wireguard.
//  2. Boot the LUKS server on the shared link; unlock its first boot over serial.
//  3. From the client, run `ubo run` to install Dropbear+WireGuard into the
//     server's initramfs and bake static networking into GRUB.
//  4. Soft-reboot the server: it now halts in the Dropbear+WireGuard initramfs
//     with the disk locked.
//  5. From the client, run `ubo unlock` (passphrase driven by expect): it brings
//     up the WireGuard tunnel, SSHes to Dropbear with the pinned host key, and
//     runs cryptroot-unlock.
//  6. Verify the server finishes booting to the decrypted system.
func TestUBOUnlock_Integration(t *testing.T) {
	checkLUKSPrereqs(t)

	bootTimeout, setupTimeout := unlockTimeouts(t)

	// ── 1. Client VM (router) ────────────────────────────────────────────────
	t.Log("Building client seed + booting client VM...")
	seed := buildClientSeed(t)
	startClientVM(t, seed)
	waitForSSHReadyPort(t, clientSSHPort, bootTimeout)
	t.Log("Waiting for client NAT/dnsmasq setup...")
	waitForClientSetup(t, setupTimeout)

	// Deploy ubo + the SSH key onto the client now — the client uses this key for
	// its inner SSH to the server (both for reachability checks and ubo run).
	// The binary must be statically linked: a normal nix-shell build references
	// the nix store's ELF interpreter, which does not exist inside the Debian VM.
	t.Log("Deploying ubo + key to client...")
	scpToClient(t, buildStaticUbo(t), "/root/ubo")
	scpToClient(t, tmpPath("test_ed25519"), "/root/test_ed25519")
	runOnClient(t, false, "chmod +x /root/ubo && chmod 600 /root/test_ed25519")

	// ── 2. LUKS server on the link; unlock first boot over serial ────────────
	t.Log("Booting LUKS server on the link...")
	srv := startLinkedServer(t)
	t.Log("Unlocking server first boot over serial...")
	srv.unlock(t, bootTimeout)

	// Confirm the server got its pinned DHCP lease and is reachable from client.
	t.Log("Waiting for server to be reachable from the client over the link...")
	waitServerSSHFromClient(t, bootTimeout)

	// ── 3. ubo run (configure the server from the client) ────────────────────
	t.Log("Running ubo run...")
	runUboRunFromClient(t)

	// ── 4. Soft-reboot the server into the Dropbear initramfs ────────────────
	t.Log("Rebooting server into Dropbear+WireGuard initramfs...")
	rebootServerFromClient(t)
	// Give it time to shut down and come back up into the initramfs.
	time.Sleep(35 * time.Second)

	// ── 5. ubo unlock (remote, over the WireGuard tunnel) ────────────────────
	t.Log("Running ubo unlock from the client (expect drives the passphrase)...")
	runUboUnlock(t)

	// ── 6. Verify the server booted to the decrypted system ──────────────────
	verifyServerDecrypted(t, bootTimeout)
}

// sshToServer builds a command (run on the client) that SSHes to the server over
// the link and runs cmd.
func sshToServer(cmd string) string {
	return "ssh -i /root/test_ed25519 -o StrictHostKeyChecking=no " +
		"-o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o BatchMode=yes " +
		"-o LogLevel=ERROR root@" + serverLinkIP + " " + shellQuote(cmd)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// waitServerSSHFromClient blocks until the client can SSH into the server.
func waitServerSSHFromClient(t *testing.T, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out := runOnClient(t, true, sshToServer("echo server-ready"))
		if strings.Contains(out, "server-ready") {
			return
		}
		time.Sleep(5 * time.Second)
	}
	diag := runOnClient(t, true, "echo '--- client addrs ---'; ip -br addr; "+
		"echo '--- routes ---'; ip route; "+
		"echo '--- dnsmasq leases ---'; cat /var/lib/misc/dnsmasq.leases 2>/dev/null; "+
		"echo '--- ping server ---'; ping -c2 -W2 "+serverLinkIP+"; "+
		"echo '--- neigh ---'; ip neigh; "+
		"echo '--- dnsmasq ---'; systemctl is-active dnsmasq")
	t.Fatalf("server not reachable from client within %v\nclient link diagnostics:\n%s\nserver serial tail:\n%s",
		timeout, diag, tailFile(tmpPath("server-serial.log"), 40))
}

// rebootServerFromClient triggers a soft reboot of the server (connection drops).
func rebootServerFromClient(t *testing.T) {
	t.Helper()
	runOnClient(t, true, sshToServer("systemctl reboot")+" || true")
}

// writeRemoteFile writes content to a path on the client via a base64 heredoc
// (avoids quoting hazards).
func writeRemoteFile(t *testing.T, remotePath, content string) {
	t.Helper()
	local := tmpPath("xfer.tmp")
	if err := os.WriteFile(local, []byte(content), 0644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	scpToClient(t, local, remotePath)
	os.Remove(local)
}

// runUboRunFromClient writes ubo.toml on the client and runs 'ubo run' against
// the LUKS server. Called by every test that needs the server configured.
func runUboRunFromClient(t *testing.T) {
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
# dnsmasq on the client pins the server to this address; isc-dhcp-client's
# default route has no "src" field, so IP auto-detection can't see it.
ip = "%s/24"
`, serverLinkIP, serverLinkIP)
	writeRemoteFile(t, "/root/ubo.toml", uboToml)
	runOut := runOnClient(t, false, "cd /root && ./ubo run --config ubo.toml 2>&1")
	t.Logf("ubo run output:\n%s", runOut)
	if !strings.Contains(runOut, "configuration complete") {
		t.Fatalf("ubo run did not report completion")
	}
}

// pushUnlockExpect installs an expect script on the client that drives
// 'ubo unlock' interactively. unlockCmd is a shell command string (may contain
// shell operators); it is executed via bash -c so metacharacters work correctly.
func pushUnlockExpect(t *testing.T, unlockCmd string) {
	t.Helper()
	// Wrap in bash -c so && / env vars / runuser work inside the expect spawn.
	// Tcl curly braces {…} quote the string literally — safe as long as the
	// command itself contains no unbalanced braces (ours never do).
	script := fmt.Sprintf(`#!/usr/bin/expect -f
set timeout 200
set pass [lindex $argv 0]
spawn bash -c {%s}
expect {
  -re "(?i)(unlock disk|passphrase)" { send "$pass\r"; exp_continue }
  -re "(?i)unlock complete" { }
  timeout { puts "EXPECT_TIMEOUT" }
  eof { }
}
catch wait result
exit [lindex $result 3]
`, unlockCmd)
	writeRemoteFile(t, "/root/do-unlock.exp", script)
}

// runUboUnlock drives 'ubo unlock' as root from the client via expect, retrying
// a few times. It fails the test if the unlock never reports completion.
func runUboUnlock(t *testing.T) {
	t.Helper()
	pushUnlockExpect(t, "cd /root && ./ubo unlock --config /root/ubo.toml")
	for attempt := 1; attempt <= 4; attempt++ {
		out := runOnClient(t, true,
			"cd /root && expect /root/do-unlock.exp "+luksPassphrase+" 2>&1")
		t.Logf("ubo unlock attempt %d:\n%s", attempt, out)
		if strings.Contains(out, "unlock complete") {
			return
		}
		time.Sleep(15 * time.Second)
	}
	t.Fatalf("ubo unlock did not complete; server serial tail:\n%s",
		tailFile(tmpPath("server-serial.log"), 50))
}

// runUboUnlockAsUser drives 'ubo unlock' as a non-root user on the client via
// expect. It copies the key artifacts to ~user/ubo-out and rewrites the config
// to point there, then runs ubo as that user via runuser.
func runUboUnlockAsUser(t *testing.T, user string) {
	t.Helper()
	// Create user and copy artifacts so the non-root process can read them.
	runOnClient(t, false, fmt.Sprintf(
		"id %s 2>/dev/null || useradd -m %s && "+
			"mkdir -p /home/%s/ubo-out && "+
			"cp /root/ubo-out/* /home/%s/ubo-out/ && "+
			"sed 's|/root/ubo-out|/home/%s/ubo-out|g' /root/ubo.toml > /home/%s/ubo.toml && "+
			"chown -R %s: /home/%s/ubo-out /home/%s/ubo.toml && "+
			"chmod 700 /home/%s/ubo-out",
		user, user, user, user, user, user, user, user, user, user))

	cfgPath := fmt.Sprintf("/home/%s/ubo.toml", user)
	unlockCmd := fmt.Sprintf("runuser -u %s -- /root/ubo unlock --config %s", user, cfgPath)
	pushUnlockExpect(t, unlockCmd)
	for attempt := 1; attempt <= 4; attempt++ {
		out := runOnClient(t, true,
			"expect /root/do-unlock.exp "+luksPassphrase+" 2>&1")
		t.Logf("ubo unlock (as %s) attempt %d:\n%s", user, attempt, out)
		if strings.Contains(out, "unlock complete") {
			return
		}
		time.Sleep(15 * time.Second)
	}
	t.Fatalf("ubo unlock (as %s) did not complete; server serial tail:\n%s",
		user, tailFile(tmpPath("server-serial.log"), 50))
}

// TestUBOUnlock_Rootless_Integration tests the userspace WireGuard unlock path.
// Identical topology to TestUBOUnlock_Integration except 'ubo unlock' is run as
// a non-root user, forcing the wireguard-go netstack path (no wg-quick needed).
func TestUBOUnlock_Rootless_Integration(t *testing.T) {
	checkLUKSPrereqs(t)
	bootTimeout, setupTimeout := unlockTimeouts(t)

	t.Log("Building client seed + booting client VM...")
	seed := buildClientSeed(t)
	startClientVM(t, seed)
	waitForSSHReadyPort(t, clientSSHPort, bootTimeout)
	t.Log("Waiting for client NAT/dnsmasq setup...")
	waitForClientSetup(t, setupTimeout)

	t.Log("Deploying ubo + key to client...")
	scpToClient(t, buildStaticUbo(t), "/root/ubo")
	scpToClient(t, tmpPath("test_ed25519"), "/root/test_ed25519")
	runOnClient(t, false, "chmod +x /root/ubo && chmod 600 /root/test_ed25519")

	t.Log("Booting LUKS server on the link...")
	srv := startLinkedServer(t)
	t.Log("Unlocking server first boot over serial...")
	srv.unlock(t, bootTimeout)
	waitServerSSHFromClient(t, bootTimeout)

	t.Log("Running ubo run...")
	runUboRunFromClient(t)

	t.Log("Rebooting server into Dropbear+WireGuard initramfs...")
	rebootServerFromClient(t)
	time.Sleep(35 * time.Second)

	t.Log("Running ubo unlock as non-root (userspace WireGuard)...")
	runUboUnlockAsUser(t, "ubotest")

	verifyServerDecrypted(t, bootTimeout)
}

// TestUBOUnlock_HostKeyMismatch_Integration verifies that a tampered pinned host
// key causes unlock to fail — the SSH handshake must be rejected.
func TestUBOUnlock_HostKeyMismatch_Integration(t *testing.T) {
	checkLUKSPrereqs(t)
	bootTimeout, setupTimeout := unlockTimeouts(t)

	t.Log("Building client seed + booting client VM...")
	seed := buildClientSeed(t)
	startClientVM(t, seed)
	waitForSSHReadyPort(t, clientSSHPort, bootTimeout)
	t.Log("Waiting for client NAT/dnsmasq setup...")
	waitForClientSetup(t, setupTimeout)

	t.Log("Deploying ubo + key to client...")
	scpToClient(t, buildStaticUbo(t), "/root/ubo")
	scpToClient(t, tmpPath("test_ed25519"), "/root/test_ed25519")
	runOnClient(t, false, "chmod +x /root/ubo && chmod 600 /root/test_ed25519")

	t.Log("Booting LUKS server on the link...")
	srv := startLinkedServer(t)
	t.Log("Unlocking server first boot over serial...")
	srv.unlock(t, bootTimeout)
	waitServerSSHFromClient(t, bootTimeout)

	t.Log("Running ubo run...")
	runUboRunFromClient(t)

	// Tamper the pinned host key before rebooting — a different key should cause
	// the SSH handshake to be rejected.
	t.Log("Tampering pinned host key...")
	runOnClient(t, false,
		"ssh-keygen -t ed25519 -f /tmp/fake_host -N '' -q && "+
			"cat /tmp/fake_host.pub > /root/ubo-out/dropbear_host_key.pub")

	t.Log("Rebooting server into Dropbear+WireGuard initramfs...")
	rebootServerFromClient(t)
	time.Sleep(35 * time.Second)

	t.Log("Attempting unlock with mismatched host key (expect failure)...")
	// Run without expect — should fail at SSH handshake, no passphrase prompt.
	for attempt := 1; attempt <= 3; attempt++ {
		out := runOnClient(t, true,
			"cd /root && ./ubo unlock --config /root/ubo.toml 2>&1; echo EXIT:$?")
		t.Logf("attempt %d:\n%s", attempt, out)
		if looksLikeSSHRejection(out) && !strings.Contains(out, "unlock complete") {
			t.Log("Host key mismatch correctly rejected connection.")
			return
		}
		time.Sleep(15 * time.Second)
	}
	t.Fatal("expected unlock to fail with host key mismatch but it did not")
}

// looksLikeSSHRejection returns true when unlock output suggests the SSH
// handshake was rejected (as opposed to the tunnel not yet being reachable).
func looksLikeSSHRejection(out string) bool {
	return strings.Contains(out, "host key") ||
		strings.Contains(out, "handshake") ||
		strings.Contains(out, "SSH") ||
		strings.Contains(out, "connect")
}
