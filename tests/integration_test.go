//go:build integration

package tests

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// projectRoot returns the absolute path to the repository root by walking up
// from this test file's location. This is necessary because go test sets the
// working directory to the package directory (tests/), not the repo root.
func projectRoot() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(f), ".."))
}

func tmpPath(name string) string {
	return filepath.Join(projectRoot(), "tmp", name)
}

const testSSHPort = 2222

// checkPrereqs skips the test if the VM image or required files are absent.
func checkPrereqs(t *testing.T) {
	t.Helper()
	for _, p := range []string{
		tmpPath("debian-trixie.qcow2"),
		tmpPath("seed.iso"),
		tmpPath("test_ed25519"),
		filepath.Join(projectRoot(), "ubo"),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("prerequisite missing: %s\nRun 'make vm-build' and 'make build' first.", p)
		}
	}
}

// startVM boots the test VM. Snapshot mode is used so the base image is never
// modified. The QEMU process is killed when the test ends.
func startVM(t *testing.T) {
	t.Helper()

	serialLog := tmpPath("vm-serial.log")

	args := []string{
		"-m", "1024",
		"-nographic",
		"-drive", "file=" + tmpPath("debian-trixie.qcow2") + ",format=qcow2,if=virtio,snapshot=on",
		"-drive", "file=" + tmpPath("seed.iso") + ",format=raw,if=virtio,media=cdrom,readonly=on",
		"-netdev", fmt.Sprintf("user,id=net0,hostfwd=tcp::%d-:22", testSSHPort),
		"-device", "virtio-net-pci,netdev=net0",
		"-serial", "file:" + serialLog,
	}

	// Use KVM for much faster boot when available.
	if _, err := os.Stat("/dev/kvm"); err == nil {
		args = append([]string{"-enable-kvm", "-cpu", "host"}, args...)
	}

	cmd := exec.Command("qemu-system-x86_64", args...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start QEMU: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
	})
}

// waitForSSH polls 127.0.0.1:testSSHPort until a TCP connection succeeds.
func waitForSSH(t *testing.T, timeout time.Duration) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", testSSHPort)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("SSH at %s not ready after %v — see %s for boot errors",
		addr, timeout, tmpPath("vm-serial.log"))
}

// waitForCloudInit retries a simple SSH command until it succeeds, ensuring
// cloud-init has finished setting up authorized_keys before we proceed.
func waitForCloudInit(t *testing.T, timeout time.Duration) {
	t.Helper()
	absKey, _ := filepath.Abs(tmpPath("test_ed25519"))
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := exec.Command("ssh",
			"-i", absKey,
			"-p", fmt.Sprintf("%d", testSSHPort),
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "ConnectTimeout=5",
			"-o", "BatchMode=yes",
			"root@127.0.0.1",
			"echo ready",
		).CombinedOutput()
		if err == nil && strings.Contains(string(out), "ready") {
			return
		}
		time.Sleep(5 * time.Second)
	}
	t.Fatalf("cloud-init did not complete within %v — VM not accessible via SSH key", timeout)
}

// sshRun executes a shell command on the test VM and returns trimmed stdout.
// Stderr is captured separately so SSH client warnings never corrupt the result.
// The test fails immediately if the command returns a non-zero exit status.
func sshRun(t *testing.T, cmd string) string {
	t.Helper()
	absKey, _ := filepath.Abs(tmpPath("test_ed25519"))
	c := exec.Command("ssh",
		"-i", absKey,
		"-p", fmt.Sprintf("%d", testSSHPort),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=10",
		"-o", "BatchMode=yes",
		"-o", "LogLevel=ERROR",
		"root@127.0.0.1",
		cmd,
	)
	var stderr strings.Builder
	c.Stderr = &stderr
	out, err := c.Output() // stdout only — keeps SSH warnings out of return value
	if err != nil {
		t.Fatalf("ssh %q failed: %v\nStderr: %s", cmd, err, stderr.String())
	}
	return strings.TrimSpace(string(out))
}

// TestUBORun_Integration boots a Debian 13 Trixie VM, runs ubo run against
// it, and verifies both local output files and the deployed remote files.
func TestUBORun_Integration(t *testing.T) {
	checkPrereqs(t)

	// Determine SSH wait timeout based on KVM availability.
	sshTimeout := 5 * time.Minute
	if _, err := os.Stat("/dev/kvm"); err != nil {
		sshTimeout = 15 * time.Minute
		t.Log("KVM not available — using software emulation (slower boot)")
	}

	t.Log("Starting test VM...")
	startVM(t)

	t.Logf("Waiting for SSH (timeout %v)...", sshTimeout)
	waitForSSH(t, sshTimeout)

	t.Log("Waiting for cloud-init to configure SSH keys...")
	waitForCloudInit(t, 5*time.Minute)
	t.Log("VM ready.")

	// ── Write test config ─────────────────────────────────────────────────────
	outDir := t.TempDir()
	cfgPath := filepath.Join(outDir, "ubo.toml")
	absSSHKey, _ := filepath.Abs(tmpPath("test_ed25519"))

	cfg := fmt.Sprintf(`host = "127.0.0.1"

[ssh]
user = "root"
port = %d
key  = %q

[wireguard]
port      = 51820
server_ip = "10.42.0.1/24"
client_ip = "10.42.0.2/32"

[dropbear]
port = 22

[output]
dir = %q
`, testSSHPort, absSSHKey, outDir)

	if err := os.WriteFile(cfgPath, []byte(cfg), 0644); err != nil {
		t.Fatalf("write test config: %v", err)
	}

	// ── Run ubo ──────────────────────────────────────────────────────────────
	t.Log("Running ubo run...")
	ubo := exec.Command(filepath.Join(projectRoot(), "ubo"), "run", "--config", cfgPath)
	ubo.Stdout = os.Stdout
	ubo.Stderr = os.Stderr
	if err := ubo.Run(); err != nil {
		t.Fatalf("ubo run: %v", err)
	}

	// ── Local output file checks ──────────────────────────────────────────────
	t.Log("Checking local output files...")

	type fileCheck struct {
		name string
		mode os.FileMode // 0 = skip mode check
	}
	wantLocal := []fileCheck{
		{"server_wg_private.key", 0600},
		{"server_wg_public.key", 0644},
		{"client_wg_private.key", 0600},
		{"client_wg_public.key", 0644},
		{"client_auth_ed25519", 0600},
		{"client_auth_ed25519.pub", 0},
		{"dropbear_host_key.pub", 0},
		{"client_wg.conf", 0600},
		{"README.txt", 0},
	}
	for _, fc := range wantLocal {
		info, err := os.Stat(filepath.Join(outDir, fc.name))
		if err != nil {
			t.Errorf("missing output file: %s", fc.name)
			continue
		}
		if fc.mode != 0 && info.Mode().Perm() != fc.mode {
			t.Errorf("%s: mode %o; want %o", fc.name, info.Mode().Perm(), fc.mode)
		}
	}

	// dropbear_host_key.pub must be an SSH public key
	pubKeyBytes, _ := os.ReadFile(filepath.Join(outDir, "dropbear_host_key.pub"))
	if !strings.HasPrefix(strings.TrimSpace(string(pubKeyBytes)), "ssh-") {
		t.Errorf("dropbear_host_key.pub: unexpected content: %q", string(pubKeyBytes)[:min(60, len(pubKeyBytes))])
	}

	// client_wg.conf must reference the server endpoint
	wgConf, _ := os.ReadFile(filepath.Join(outDir, "client_wg.conf"))
	if !strings.Contains(string(wgConf), "127.0.0.1:51820") {
		t.Errorf("client_wg.conf: missing endpoint 127.0.0.1:51820")
	}

	// README.txt must mention cryptroot-unlock
	readme, _ := os.ReadFile(filepath.Join(outDir, "README.txt"))
	if !strings.Contains(string(readme), "cryptroot-unlock") {
		t.Errorf("README.txt: missing cryptroot-unlock instruction")
	}

	// ── Remote file checks ────────────────────────────────────────────────────
	t.Log("Checking remote deployed files...")

	remoteFiles := []string{
		"/etc/wireguard/wg-initramfs.conf",
		"/etc/initramfs-tools/hooks/wireguard",
		"/etc/initramfs-tools/scripts/init-premount/wireguard",
	}
	for _, f := range remoteFiles {
		out := sshRun(t, fmt.Sprintf("test -f %q && echo ok || echo missing", f))
		if out != "ok" {
			t.Errorf("remote file not deployed: %s", f)
		}
	}

	// Initramfs hook and script must be executable
	for _, f := range []string{
		"/etc/initramfs-tools/hooks/wireguard",
		"/etc/initramfs-tools/scripts/init-premount/wireguard",
	} {
		out := sshRun(t, fmt.Sprintf("test -x %q && echo ok || echo not-executable", f))
		if out != "ok" {
			t.Errorf("not executable on remote: %s", f)
		}
	}

	// WireGuard config must be mode 600
	mode := sshRun(t, "stat -c %a /etc/wireguard/wg-initramfs.conf")
	if mode != "600" {
		t.Errorf("wg-initramfs.conf: remote mode=%s want 600", mode)
	}

	// Dropbear authorized_keys must exist (check both possible paths)
	authKeys := sshRun(t,
		`ls /etc/dropbear/initramfs/authorized_keys 2>/dev/null || `+
			`ls /etc/dropbear-initramfs/authorized_keys 2>/dev/null || `+
			`echo missing`)
	if authKeys == "missing" {
		t.Error("dropbear authorized_keys not deployed on remote")
	}

	// GRUB must contain ip= parameter
	grepCount := sshRun(t, "grep -c 'GRUB_CMDLINE_LINUX=.*ip=' /etc/default/grub || echo 0")
	if grepCount == "0" {
		t.Error("GRUB not updated with ip= parameter")
	}

	// Initramfs must have been rebuilt after our deployment (initrd newer than grub file)
	rebuilt := sshRun(t, "find /boot -name 'initrd.img*' -newer /etc/wireguard/wg-initramfs.conf | wc -l")
	if rebuilt == "0" {
		t.Error("initramfs does not appear to have been rebuilt after deployment")
	}

	t.Log("Remote verification complete.")
}
