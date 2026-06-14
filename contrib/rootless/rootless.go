//go:build rootless

// Package rootless implements a privilege-free unlock path using userspace
// WireGuard (wireguard-go netstack) and an in-process SSH client
// (golang.org/x/crypto/ssh). No root is required, no kernel WireGuard module
// is loaded, and no external ssh or wg-quick binaries are invoked.
package rootless

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"ubo/internal/config"
)

// Unlock brings up a userspace WireGuard tunnel, connects to Dropbear over it
// using a pinned host key, and runs cryptroot-unlock interactively. If
// changeKey is true it runs luksChangeKey first and asks whether to unlock.
func Unlock(ctx context.Context, cfg *config.Config, outputDir string, changeKey bool) error {
	wgCfg, err := parseWGConfig(outputDir + "/client_wg.conf")
	if err != nil {
		return err
	}

	dev, tnet, err := setupWGDevice(wgCfg)
	if err != nil {
		return err
	}
	defer func() {
		dev.Down()
		dev.Close()
	}()

	serverIP := cfg.WGServerTunnelIP()
	serverAddr, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", serverIP, cfg.Dropbear.Port))
	if err != nil {
		return fmt.Errorf("parse server address: %w", err)
	}

	fmt.Printf("[ubo] waiting for tunnel to %s...\n", serverIP)
	if err := waitTunnel(ctx, tnet, serverAddr); err != nil {
		return err
	}

	client, err := dialSSH(ctx, tnet, serverAddr, outputDir, cfg)
	if err != nil {
		return err
	}
	defer client.Close()

	return performUnlock(client, cfg, changeKey)
}

// setupWGDevice creates a netstack TUN and configures a wireguard-go device on it.
func setupWGDevice(wgCfg *wgClientConfig) (*device.Device, *netstack.Net, error) {
	clientIP, err := parseFirstAddr(wgCfg.Address)
	if err != nil {
		return nil, nil, fmt.Errorf("parse client address: %w", err)
	}

	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1420)
	if err != nil {
		return nil, nil, fmt.Errorf("create netstack TUN: %w", err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(),
		device.NewLogger(device.LogLevelSilent, ""))

	ipc, err := buildIPC(wgCfg)
	if err != nil {
		return nil, nil, err
	}
	if err := dev.IpcSet(ipc); err != nil {
		return nil, nil, fmt.Errorf("configure wireguard device: %w", err)
	}
	if err := dev.Up(); err != nil {
		return nil, nil, fmt.Errorf("wireguard device up: %w", err)
	}
	return dev, tnet, nil
}

// buildIPC renders the WireGuard UAPI configuration string for the device.
func buildIPC(wgCfg *wgClientConfig) (string, error) {
	privHex, err := b64ToHex(wgCfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	pubHex, err := b64ToHex(wgCfg.PeerPubKey)
	if err != nil {
		return "", fmt.Errorf("peer public key: %w", err)
	}
	return fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=%s\npersistent_keepalive_interval=25\n",
		privHex, pubHex, wgCfg.Endpoint, wgCfg.AllowedIPs,
	), nil
}

// waitTunnel polls the server over the netstack until reachable or timeout.
func waitTunnel(ctx context.Context, tnet *netstack.Net, addr netip.AddrPort) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		dialCtx, cancel := context.WithTimeout(ctx, time.Second)
		c, err := tnet.DialContextTCPAddrPort(dialCtx, addr)
		cancel()
		if err == nil {
			c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("tunnel to %s not reachable after 15s", addr)
}

// dialSSH reads the client SSH key and pinned host key, then opens an SSH
// connection to Dropbear over the netstack tunnel.
func dialSSH(ctx context.Context, tnet *netstack.Net, addr netip.AddrPort, outputDir string, cfg *config.Config) (*ssh.Client, error) {
	signer, err := loadSSHKey(outputDir + "/client_auth_ed25519")
	if err != nil {
		return nil, err
	}
	hostKey, err := loadPinnedKey(outputDir + "/dropbear_host_key.pub")
	if err != nil {
		return nil, err
	}

	fmt.Printf("[ubo] connecting to Dropbear at %s (rootless)...\n", addr)
	tcpConn, err := tnet.DialContextTCPAddrPort(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("dial Dropbear: %w", err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(tcpConn, addr.String(), &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("SSH handshake: %w", err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

// performUnlock optionally changes the LUKS passphrase, then runs cryptroot-unlock.
func performUnlock(client *ssh.Client, cfg *config.Config, changeKey bool) error {
	if changeKey {
		proceed, err := runChangeKey(client, cfg)
		if err != nil {
			return err
		}
		if !proceed {
			return nil
		}
	}
	fmt.Println("[ubo] unlocking disk (enter LUKS passphrase when prompted)...")
	if err := runPTY(client, "cryptroot-unlock"); err != nil {
		return fmt.Errorf("cryptroot-unlock: %w", err)
	}
	fmt.Println("[ubo] unlock complete")
	return nil
}

// runChangeKey runs luksChangeKey interactively and asks whether to proceed to unlock.
func runChangeKey(client *ssh.Client, cfg *config.Config) (bool, error) {
	changeCmd := `SRC=$(awk 'NF && !/^#/{print $2; exit}' /etc/crypttab)
case "$SRC" in
  UUID=*) DEV="/dev/disk/by-uuid/${SRC#UUID=}" ;;
  PARTUUID=*) DEV="/dev/disk/by-partuuid/${SRC#PARTUUID=}" ;;
  LABEL=*) DEV="/dev/disk/by-label/${SRC#LABEL=}" ;;
  PARTLABEL=*) DEV="/dev/disk/by-partlabel/${SRC#PARTLABEL=}" ;;
  *) DEV="$SRC" ;;
esac
test -n "$DEV" || { echo "could not determine LUKS device from /etc/crypttab" >&2; exit 1; }
cryptsetup luksChangeKey "$DEV"`
	if cfg.LUKS.Device != "" {
		changeCmd = fmt.Sprintf("cryptsetup luksChangeKey %q", cfg.LUKS.Device)
	}

	fmt.Println("[ubo] changing LUKS passphrase (enter current passphrase, then new passphrase twice)...")
	if err := runPTY(client, changeCmd); err != nil {
		return false, fmt.Errorf("luksChangeKey: %w", err)
	}
	fmt.Print("\nChange complete. Unlock and boot now? [Y/n]: ")
	var ans string
	fmt.Scanln(&ans)
	return ans == "" || ans == "y" || ans == "Y", nil
}

// runPTY opens an SSH session with a PTY and runs cmd, wiring the local terminal.
func runPTY(client *ssh.Client, cmd string) error {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("open SSH session: %w", err)
	}
	defer session.Close()

	restore, err := attachPTY(session)
	if err != nil {
		return err
	}
	if restore != nil {
		defer restore()
	}

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	if err := session.Start(cmd); err != nil {
		return fmt.Errorf("start command: %w", err)
	}
	return session.Wait()
}

// attachPTY requests a PTY on session and sets the local terminal to raw mode.
// Returns a restore function (non-nil only when raw mode was engaged) or an error.
func attachPTY(session *ssh.Session) (func(), error) {
	fd := int(os.Stdin.Fd())
	width, height, _ := term.GetSize(fd)
	if width == 0 {
		width, height = 80, 24
	}
	if err := session.RequestPty("xterm-256color", height, width, ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		return nil, fmt.Errorf("request PTY: %w", err)
	}
	if !term.IsTerminal(fd) {
		return nil, nil
	}
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return nil, nil // non-fatal: proceed without raw mode
	}
	return func() { term.Restore(fd, oldState) }, nil //nolint:errcheck
}

// loadSSHKey reads an OpenSSH private key file and returns a Signer.
func loadSSHKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read SSH key %s: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse SSH key: %w", err)
	}
	return signer, nil
}

// loadPinnedKey reads a dropbear_host_key.pub file (authorized_keys format)
// and returns the public key for use with ssh.FixedHostKey.
func loadPinnedKey(path string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pinned key %s: %w", path, err)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse pinned key: %w", err)
	}
	return key, nil
}

// parseFirstAddr parses an IP/CIDR string and returns the host address.
func parseFirstAddr(cidr string) (netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		// Try bare IP
		addr, aerr := netip.ParseAddr(cidr)
		if aerr != nil {
			return netip.Addr{}, fmt.Errorf("parse address %q: %w", cidr, err)
		}
		return addr, nil
	}
	return prefix.Addr(), nil
}

// b64ToHex converts a base64-encoded WireGuard key to its hex representation
// as required by the wireguard-go UAPI IPC protocol.
func b64ToHex(b64key string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64key)
	if err != nil {
		return "", fmt.Errorf("base64 decode key: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key must be 32 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// parseFirstAddr (net.IP variant) resolves an endpoint host for dialing.
// Used internally by waitTunnel via the standard net package.
var _ = net.IP(nil) // keep net imported for potential future use
