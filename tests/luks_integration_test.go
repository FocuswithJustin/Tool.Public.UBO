//go:build integration

package tests

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The LUKS passphrase baked into tmp/debian-luks.qcow2 by build-luks-vm.sh.
const luksPassphrase = "ubotestphrase"

// checkLUKSPrereqs skips the test unless the LUKS server image and test key exist.
func checkLUKSPrereqs(t *testing.T) {
	t.Helper()
	for _, p := range []string{
		tmpPath("debian-luks.qcow2"),
		tmpPath("test_ed25519"),
		filepath.Join(projectRoot(), "ubo"),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("prerequisite missing: %s\nRun 'make vm-build', 'make luks-build' and 'make build' first.", p)
		}
	}
}

// luksServer is a booted LUKS server VM with a serial control socket.
type luksServer struct {
	sshPort    int
	serialSock string
	cmd        *exec.Cmd
}

// startLUKSServer boots the LUKS server image with:
//   - a serial unix socket (for entering the LUKS passphrase / watching boot)
//   - user-mode networking with an SSH host-forward on sshPort
//
// extraQEMU lets callers add NICs (e.g. the socket link for the two-VM test).
// The base image is never modified (snapshot=on).
func startLUKSServer(t *testing.T, sshPort int, extraQEMU ...string) *luksServer {
	t.Helper()
	serialSock := tmpPath(fmt.Sprintf("luks-serial-%d.sock", sshPort))
	os.Remove(serialSock)
	serialLog := tmpPath(fmt.Sprintf("luks-server-%d.log", sshPort))

	args := []string{
		"-m", "1024",
		"-nographic",
		"-drive", "file=" + tmpPath("debian-luks.qcow2") + ",format=qcow2,if=virtio,snapshot=on",
		"-netdev", fmt.Sprintf("user,id=net0,hostfwd=tcp::%d-:22", sshPort),
		"-device", "virtio-net-pci,netdev=net0",
		// ttyS0 is exposed as a unix socket (for entering the passphrase) and
		// mirrored to a logfile so boot output is inspectable after the fact.
		"-chardev", "socket,id=serial0,path=" + serialSock + ",server=on,wait=off,logfile=" + serialLog,
		"-serial", "chardev:serial0",
	}
	args = append(args, extraQEMU...)
	if _, err := os.Stat("/dev/kvm"); err == nil {
		args = append([]string{"-enable-kvm", "-cpu", "host"}, args...)
	}

	cmd := exec.Command("qemu-system-x86_64", args...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start LUKS server QEMU: %v", err)
	}
	s := &luksServer{sshPort: sshPort, serialSock: serialSock, cmd: cmd}
	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
	})
	return s
}

// unlock connects to the serial socket and answers the initramfs LUKS passphrase
// prompt. It keeps responding to any re-prompt until the deadline, so a missed
// first prompt (if we connect slightly late) still gets answered on retry.
func (s *luksServer) unlock(t *testing.T, timeout time.Duration) {
	t.Helper()

	var conn net.Conn
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.Dial("unix", s.serialSock)
		if err == nil {
			conn = c
			break
		}
		time.Sleep(time.Second)
	}
	if conn == nil {
		t.Fatalf("could not connect to serial socket %s within %v", s.serialSock, timeout)
	}
	defer conn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		br := bufio.NewReader(conn)
		var acc strings.Builder
		lastSent := time.Time{}
		buf := make([]byte, 512)
		for {
			conn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
			n, err := br.Read(buf)
			if n > 0 {
				chunk := string(buf[:n])
				acc.WriteString(chunk)
				low := strings.ToLower(acc.String())
				if (strings.Contains(low, "unlock disk") ||
					strings.Contains(low, "passphrase for") ||
					strings.Contains(low, "please enter passphrase")) &&
					time.Since(lastSent) > 3*time.Second {
					conn.Write([]byte(luksPassphrase + "\n")) //nolint:errcheck
					lastSent = time.Now()
					acc.Reset()
				}
				// Stop once we see the system reaching userspace.
				if strings.Contains(low, "ubo-luks-server login:") ||
					strings.Contains(low, "reached target") && strings.Contains(low, "multi-user") {
					return
				}
			}
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					if time.Now().After(deadline) {
						return
					}
					continue
				}
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(time.Until(deadline)):
	}
}

// waitForSSHPort polls 127.0.0.1:port until a TCP connection succeeds.
func waitForSSHPort(t *testing.T, port int, timeout time.Duration) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("SSH at %s not ready after %v", addr, timeout)
}

// sshRunPort runs a command over SSH on the given host-forwarded port (root user,
// test key) and returns trimmed stdout. Fails the test on non-zero exit.
func sshRunPort(t *testing.T, port int, cmd string) string {
	t.Helper()
	absKey, _ := filepath.Abs(tmpPath("test_ed25519"))
	c := exec.Command("ssh",
		"-i", absKey,
		"-p", fmt.Sprintf("%d", port),
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
	out, err := c.Output()
	if err != nil {
		t.Fatalf("ssh %q failed: %v\nStderr: %s", cmd, err, stderr.String())
	}
	return strings.TrimSpace(string(out))
}

// waitForCloudInitPort retries an SSH command on the given port until it works.
func waitForSSHReadyPort(t *testing.T, port int, timeout time.Duration) {
	t.Helper()
	absKey, _ := filepath.Abs(tmpPath("test_ed25519"))
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := exec.Command("ssh",
			"-i", absKey,
			"-p", fmt.Sprintf("%d", port),
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "ConnectTimeout=5",
			"-o", "BatchMode=yes",
			"-o", "LogLevel=ERROR",
			"root@127.0.0.1",
			"echo ready",
		).CombinedOutput()
		if err == nil && strings.Contains(string(out), "ready") {
			return
		}
		time.Sleep(5 * time.Second)
	}
	t.Fatalf("SSH login not ready on port %d within %v", port, timeout)
}

// TestLUKSServer_BootUnlock validates the LUKS server image itself: it must boot,
// halt in the initramfs for a LUKS passphrase, accept the passphrase over the
// serial console, and continue to a fully booted system reachable over SSH whose
// root filesystem is the decrypted LVM volume. This is the foundation the full
// remote-unlock test builds on.
func TestLUKSServer_BootUnlock(t *testing.T) {
	checkLUKSPrereqs(t)

	bootTimeout := 4 * time.Minute
	if _, err := os.Stat("/dev/kvm"); err != nil {
		bootTimeout = 12 * time.Minute
		t.Log("KVM not available — using software emulation (slower boot)")
	}

	const port = 2223
	t.Log("Booting LUKS server VM...")
	s := startLUKSServer(t, port)

	t.Log("Answering LUKS passphrase prompt over serial...")
	s.unlock(t, bootTimeout)

	t.Log("Waiting for SSH after unlock...")
	waitForSSHReadyPort(t, port, bootTimeout)

	host := sshRunPort(t, port, "hostname")
	if host != "ubo-luks-server" {
		t.Errorf("hostname = %q; want ubo-luks-server", host)
	}

	rootSrc := sshRunPort(t, port, "findmnt -no SOURCE /")
	if !strings.Contains(rootSrc, "vg0-root") && !strings.Contains(rootSrc, "vg0/root") {
		t.Errorf("root filesystem source = %q; want the decrypted LVM volume (vg0-root)", rootSrc)
	}

	// The LUKS mapping must be active — proof the disk was really encrypted.
	dm := sshRunPort(t, port, "test -e /dev/mapper/cryptroot && echo present || echo absent")
	if dm != "present" {
		t.Errorf("/dev/mapper/cryptroot = %q; want present (LUKS mapping active)", dm)
	}

	t.Log("LUKS server boots and unlocks over serial successfully.")
}
