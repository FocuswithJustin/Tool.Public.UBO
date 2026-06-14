package templates

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
)

// WireGuardServerConfig builds a WireGuard server configuration.
type WireGuardServerConfig struct {
	Address        string // e.g. "10.42.0.1/24"
	PrivateKey     string
	ListenPort     int
	PeerPublicKey  string
	PeerAllowedIPs string // e.g. "10.42.0.2/32"
}

// MarshalINI validates fields and returns the wg-conf INI string.
//
// The output is consumed by `wg setconf` inside the initramfs, which only
// understands kernel-level WireGuard keys. It must NOT contain the Address
// field (a wg-quick extension that `wg setconf` rejects with "Line
// unrecognized"); the interface address is applied separately by the
// init-premount script via `ip addr add`. The Address field is still required
// here because the caller must supply the server tunnel IP for that script.
func (c WireGuardServerConfig) MarshalINI() (string, error) {
	if c.Address == "" {
		return "", fmt.Errorf("WireGuardServerConfig: Address is required")
	}
	if c.PrivateKey == "" {
		return "", fmt.Errorf("WireGuardServerConfig: PrivateKey is required")
	}
	if c.ListenPort == 0 {
		return "", fmt.Errorf("WireGuardServerConfig: ListenPort is required")
	}
	if c.PeerPublicKey == "" {
		return "", fmt.Errorf("WireGuardServerConfig: PeerPublicKey is required")
	}
	if c.PeerAllowedIPs == "" {
		return "", fmt.Errorf("WireGuardServerConfig: PeerAllowedIPs is required")
	}

	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	fmt.Fprintf(&sb, "PrivateKey = %s\n", c.PrivateKey)
	fmt.Fprintf(&sb, "ListenPort = %d\n", c.ListenPort)
	sb.WriteString("\n[Peer]\n")
	fmt.Fprintf(&sb, "PublicKey = %s\n", c.PeerPublicKey)
	fmt.Fprintf(&sb, "AllowedIPs = %s\n", c.PeerAllowedIPs)
	sb.WriteString("PersistentKeepalive = 25\n")
	return sb.String(), nil
}

// WireGuardClientConfig builds a WireGuard client configuration.
type WireGuardClientConfig struct {
	PrivateKey      string
	Address         string // e.g. "10.42.0.2/32"
	ServerPublicKey string
	ServerEndpoint  string // host:port
	AllowedIPs      string // e.g. "10.42.0.1/32"
}

// MarshalINI validates fields and returns the wg-conf INI string.
func (c WireGuardClientConfig) MarshalINI() (string, error) {
	if c.PrivateKey == "" {
		return "", fmt.Errorf("WireGuardClientConfig: PrivateKey is required")
	}
	if c.Address == "" {
		return "", fmt.Errorf("WireGuardClientConfig: Address is required")
	}
	if c.ServerPublicKey == "" {
		return "", fmt.Errorf("WireGuardClientConfig: ServerPublicKey is required")
	}
	if c.ServerEndpoint == "" {
		return "", fmt.Errorf("WireGuardClientConfig: ServerEndpoint is required")
	}
	if c.AllowedIPs == "" {
		return "", fmt.Errorf("WireGuardClientConfig: AllowedIPs is required")
	}

	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	fmt.Fprintf(&sb, "PrivateKey = %s\n", c.PrivateKey)
	fmt.Fprintf(&sb, "Address = %s\n", c.Address)
	sb.WriteString("\n[Peer]\n")
	fmt.Fprintf(&sb, "PublicKey = %s\n", c.ServerPublicKey)
	fmt.Fprintf(&sb, "Endpoint = %s\n", c.ServerEndpoint)
	fmt.Fprintf(&sb, "AllowedIPs = %s\n", c.AllowedIPs)
	sb.WriteString("PersistentKeepalive = 25\n")
	return sb.String(), nil
}

// InitramfsHookTmpl is the /etc/initramfs-tools/hooks/wireguard hook script.
// It copies wg and the wireguard module into the initramfs image.
const InitramfsHookTmpl = `#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in prereqs) prereqs; exit 0;; esac
. /usr/share/initramfs-tools/hook-functions
copy_exec /usr/bin/wg
manual_add_modules wireguard
mkdir -p "${DESTDIR}/etc/wireguard"
cp /etc/wireguard/wg-initramfs.conf "${DESTDIR}/etc/wireguard/"
`

// InitramfsScriptData holds template variables for InitramfsScriptTmpl.
type InitramfsScriptData struct {
	ServerIP string // e.g. "10.42.0.1/24"
}

// InitramfsScriptTmpl is the /etc/initramfs-tools/scripts/init-premount/wireguard script.
// It sets up the WireGuard interface during early boot, after the network is available.
const InitramfsScriptTmpl = `#!/bin/sh
PREREQ="udev"
prereqs() { echo "$PREREQ"; }
case "$1" in prereqs) prereqs; exit 0;; esac

# Wait for default route — max 30 seconds
TIMEOUT=30
while [ $TIMEOUT -gt 0 ]; do
    ip route show default 2>/dev/null | grep -q default && break
    sleep 1
    TIMEOUT=$((TIMEOUT - 1))
done

modprobe wireguard 2>/dev/null || true
ip link add dev wg0 type wireguard
ip addr add {{.ServerIP}} dev wg0
wg setconf wg0 /etc/wireguard/wg-initramfs.conf
ip link set dev wg0 up
`

// RenderInitramfsScript renders InitramfsScriptTmpl with d.
func RenderInitramfsScript(d InitramfsScriptData) (string, error) {
	if d.ServerIP == "" {
		return "", fmt.Errorf("RenderInitramfsScript: ServerIP is required")
	}
	tmpl, err := template.New("wg-script").Parse(InitramfsScriptTmpl)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, d); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// DropbearConfigData holds template variables for DropbearConfigTmpl.
type DropbearConfigData struct {
	ServerTunnelIP string // IP only, no prefix
	DropbearPort   int
}

// DropbearConfigTmpl is the /etc/dropbear/initramfs/dropbear.conf content.
const DropbearConfigTmpl = `DROPBEAR_OPTIONS="-p {{.ServerTunnelIP}}:{{.DropbearPort}} -s -j -k"
`

// RenderDropbearConfig renders DropbearConfigTmpl with d.
func RenderDropbearConfig(d DropbearConfigData) (string, error) {
	if d.ServerTunnelIP == "" {
		return "", fmt.Errorf("RenderDropbearConfig: ServerTunnelIP is required")
	}
	if d.DropbearPort == 0 {
		return "", fmt.Errorf("RenderDropbearConfig: DropbearPort is required")
	}
	tmpl, err := template.New("dropbear-conf").Parse(DropbearConfigTmpl)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, d); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ReadmeTmplData holds template variables for ReadmeTmpl.
type ReadmeTmplData struct {
	ServerTunnelIP string
	DropbearPort   int
	ConfigPath     string
}

// ReadmeTmpl is the README.txt written to the output directory.
const ReadmeTmpl = `Remote LUKS Unlock Instructions
================================

Generated by ubo (Unlock Before Operation).

Files in this directory:
  client_wg.conf          WireGuard client config (import into wg-quick)
  client_auth_ed25519     SSH private key for Dropbear authentication
  dropbear_host_key.pub   Pinned Dropbear host key (used for verification)

Unlock procedure
----------------

1. Reboot the remote server.

2. Bring up the WireGuard tunnel (requires root):
   sudo wg-quick up ./client_wg.conf

   Or use the ubo tool (handles this automatically):
   sudo ubo unlock --config {{.ConfigPath}}

3. SSH to the Dropbear server in initramfs:
   ssh -i client_auth_ed25519 -p {{.DropbearPort}} root@{{.ServerTunnelIP}}

4. At the Dropbear prompt, unlock the disk:
   cryptroot-unlock

5. Enter the LUKS passphrase when prompted.
   The server will continue booting automatically.

6. Tear down the tunnel once the server is up:
   sudo wg-quick down ./client_wg.conf

Change LUKS passphrase
----------------------

   sudo ubo unlock change --config {{.ConfigPath}}

This connects via WireGuard + Dropbear and runs:
  cryptsetup luksChangeKey <device>
Then prompts whether to unlock and boot immediately.
`

// RenderReadme renders ReadmeTmpl with d.
func RenderReadme(d ReadmeTmplData) (string, error) {
	tmpl, err := template.New("readme").Parse(ReadmeTmpl)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, d); err != nil {
		return "", err
	}
	return buf.String(), nil
}
