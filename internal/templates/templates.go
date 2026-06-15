package templates

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
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
// It copies wg and the wireguard module into the initramfs image, and also
// copies mdadm and the RAID modules needed for LUKS-on-RAID hosts where the
// LUKS device lives on a software RAID array that must be assembled before the
// passphrase prompt.
const InitramfsHookTmpl = `#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in prereqs) prereqs; exit 0;; esac
. /usr/share/initramfs-tools/hook-functions
copy_exec /usr/bin/wg
manual_add_modules wireguard
copy_exec /usr/sbin/mdadm
manual_add_modules md_mod raid1
if command -v lvm >/dev/null 2>&1; then
    copy_exec /sbin/lvm
    manual_add_modules dm-mod
fi
mkdir -p "${DESTDIR}/etc/wireguard"
cp /etc/wireguard/wg-initramfs.conf "${DESTDIR}/etc/wireguard/"
`

// InitramfsUMASKConf is written to /etc/initramfs-tools/conf.d/ubo. It sets
// UMASK=0077 so update-initramfs creates the boot image mode 0600 (root only).
//
// The initramfs embeds the WireGuard server private key (and the Dropbear host
// key) because they must be available before the root disk is decrypted, so
// they necessarily live in the unencrypted /boot. By default initramfs images
// are world-readable (0644), which would let any local unprivileged user
// extract those secrets with lsinitramfs/unmkinitramfs. UMASK=0077 closes that
// exposure. GRUB reads the image as raw disk blocks at boot, so 0600 does not
// affect booting.
const InitramfsUMASKConf = `# Written by ubo: initramfs images embed the WireGuard private key, so restrict
# them to root only (otherwise /boot exposes the key to local users).
UMASK=0077
`

// InitramfsScriptData holds template variables for InitramfsScriptTmpl.
type InitramfsScriptData struct {
	ServerIP    string // e.g. "10.42.0.1/24" — WireGuard server tunnel CIDR
	StaticIP    string // host IP/CIDR for initramfs, e.g. "192.168.1.10/24"
	GatewayIP   string // physical network gateway, e.g. "192.168.1.1"
	Interface   string // network interface name (VLAN, bond, bridge, or plain NIC)
	VLANPhysdev string // parent NIC for VLAN (e.g. "eth0"); empty if not a VLAN
	VLANID      int    // 802.1Q VLAN ID (0 if not a VLAN)
	BondSlaves  string // space-separated slave NICs for bond (empty if not bond)
	BondMode    string // bonding mode e.g. "active-backup" (empty if not bond or unknown)
}

// InitramfsScriptTmpl is the /etc/initramfs-tools/scripts/init-premount/wireguard
// script. It runs in init-premount, which is earlier than the init-local stage
// where dropbear-initramfs starts Dropbear — so wg0 is guaranteed to exist
// before Dropbear tries to bind its tunnel IP (audit M1).
//
// set -e makes the script fail-closed: if any command fails (e.g. wg setconf
// rejects the config, or ip link add returns an error) the script exits non-zero
// and the initramfs halts rather than leaving the machine in an undefined state
// where Dropbear may be unreachable (audit M2).
//
// The route-wait loop uses `if` rather than `&& break` so that grep's non-zero
// exit (route not yet present) does not trigger set -e's automatic exit.
const InitramfsScriptTmpl = `#!/bin/sh
PREREQ="udev"
prereqs() { echo "$PREREQ"; }
case "$1" in prereqs) prereqs; exit 0;; esac
set -e

{{- if and .VLANPhysdev .BondSlaves}}
# VLAN on top of a bond: create bond, set mode, enslave NICs, then add VLAN.
modprobe bonding 2>/dev/null || true
modprobe 8021q 2>/dev/null || true
ip link add name "{{.VLANPhysdev}}" type bond 2>/dev/null || true
{{- if .BondMode}}
echo "{{.BondMode}}" > /sys/class/net/"{{.VLANPhysdev}}"/bonding/mode 2>/dev/null || true
{{- end}}
for _slave in {{.BondSlaves}}; do
    ip link set dev "$_slave" down 2>/dev/null || true
    ip link set dev "$_slave" master "{{.VLANPhysdev}}" 2>/dev/null || true
done
ip link set dev "{{.VLANPhysdev}}" up
ip link add link "{{.VLANPhysdev}}" name "{{.Interface}}" type vlan id {{.VLANID}} 2>/dev/null || true
IFACE="{{.Interface}}"
{{- else if .VLANPhysdev}}
# VLAN interface: bring up the physical NIC, then create the VLAN on top of it.
modprobe 8021q 2>/dev/null || true
ip link set dev "{{.VLANPhysdev}}" up
ip link add link "{{.VLANPhysdev}}" name "{{.Interface}}" type vlan id {{.VLANID}} 2>/dev/null || true
IFACE="{{.Interface}}"
{{- else if .BondSlaves}}
# Bond interface: create bond, set mode, then enslave the physical NICs.
modprobe bonding 2>/dev/null || true
ip link add name "{{.Interface}}" type bond 2>/dev/null || true
{{- if .BondMode}}
echo "{{.BondMode}}" > /sys/class/net/"{{.Interface}}"/bonding/mode 2>/dev/null || true
{{- end}}
for _slave in {{.BondSlaves}}; do
    ip link set dev "$_slave" down 2>/dev/null || true
    ip link set dev "$_slave" master "{{.Interface}}" 2>/dev/null || true
done
IFACE="{{.Interface}}"
{{- else}}
# Plain NIC. Predictable names (e.g. enp1s0) need udev rules that may not be
# present in initramfs; fall back to the first non-loopback Ethernet interface
# found in /sys/class/net if the configured name is not visible.
IFACE="{{.Interface}}"
if ! ip link show dev "$IFACE" >/dev/null 2>&1; then
    for _dev in /sys/class/net/*; do
        _n=$(basename "$_dev")
        [ "$_n" = "lo" ] && continue
        [ "$(cat "$_dev/type" 2>/dev/null)" = "1" ] || continue
        IFACE="$_n"; break
    done
fi
{{- end}}

ip link set dev "$IFACE" up
ip addr add {{.StaticIP}} dev "$IFACE" 2>/dev/null || true
if ! ip route show default | grep -q default; then
    if ! ip route add default via {{.GatewayIP}} 2>/dev/null; then
        ip route add {{.GatewayIP}}/32 dev "$IFACE" onlink 2>/dev/null || true
        ip route add default via {{.GatewayIP}} 2>/dev/null || true
    fi
fi

modprobe wireguard 2>/dev/null || true
ip link del dev wg0 2>/dev/null || true
ip link add dev wg0 type wireguard
ip addr add {{.ServerIP}} dev wg0
wg setconf wg0 /etc/wireguard/wg-initramfs.conf
ip link set dev wg0 up
`

var initramfsScriptTmpl = template.Must(template.New("wg-script").Parse(InitramfsScriptTmpl))

// RenderInitramfsScript renders InitramfsScriptTmpl with d.
// It validates that ServerIP is a non-empty CIDR before rendering.
func RenderInitramfsScript(d InitramfsScriptData) (string, error) {
	if err := validateInitramfsScriptData(d); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	_ = initramfsScriptTmpl.Execute(&buf, d) // pre-parsed template, no error-returning methods: cannot fail
	return buf.String(), nil
}

// validateInitramfsScriptData returns an error if d contains invalid fields.
func validateInitramfsScriptData(d InitramfsScriptData) error {
	if err := validateScriptCIDRs(d); err != nil {
		return err
	}
	if d.GatewayIP == "" {
		return fmt.Errorf("RenderInitramfsScript: GatewayIP is required")
	}
	if net.ParseIP(d.GatewayIP) == nil {
		return fmt.Errorf("RenderInitramfsScript: GatewayIP %q is not a valid IP address", d.GatewayIP)
	}
	if d.Interface == "" {
		return fmt.Errorf("RenderInitramfsScript: Interface is required")
	}
	return nil
}

// validateScriptCIDRs checks the CIDR fields of InitramfsScriptData.
func validateScriptCIDRs(d InitramfsScriptData) error {
	if d.ServerIP == "" {
		return fmt.Errorf("RenderInitramfsScript: ServerIP is required")
	}
	if _, _, err := net.ParseCIDR(d.ServerIP); err != nil {
		return fmt.Errorf("RenderInitramfsScript: ServerIP %q is not a valid CIDR: %w", d.ServerIP, err)
	}
	if d.StaticIP == "" {
		return fmt.Errorf("RenderInitramfsScript: StaticIP is required")
	}
	if _, _, err := net.ParseCIDR(d.StaticIP); err != nil {
		return fmt.Errorf("RenderInitramfsScript: StaticIP %q is not a valid CIDR: %w", d.StaticIP, err)
	}
	return nil
}

// DropbearConfigData holds template variables for DropbearConfigTmpl.
type DropbearConfigData struct {
	ServerTunnelIP string // IP only, no prefix
	DropbearPort   int
}

// DropbearConfigTmpl is the /etc/dropbear/initramfs/dropbear.conf content.
const DropbearConfigTmpl = `DROPBEAR_OPTIONS="-p {{.ServerTunnelIP}}:{{.DropbearPort}} -s -j -k"
`

var dropbearConfigTmpl = template.Must(template.New("dropbear-conf").Parse(DropbearConfigTmpl))

// RenderDropbearConfig renders DropbearConfigTmpl with d.
func RenderDropbearConfig(d DropbearConfigData) (string, error) {
	if d.ServerTunnelIP == "" {
		return "", fmt.Errorf("RenderDropbearConfig: ServerTunnelIP is required")
	}
	if d.DropbearPort == 0 {
		return "", fmt.Errorf("RenderDropbearConfig: DropbearPort is required")
	}
	var buf bytes.Buffer
	_ = dropbearConfigTmpl.Execute(&buf, d) // pre-parsed template, no error-returning methods: cannot fail
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

var readmeTmpl = template.Must(template.New("readme").Parse(ReadmeTmpl))

// RenderReadme renders ReadmeTmpl with d. It has no required-field validation
// and cannot fail, so it returns a plain string rather than (string, error).
func RenderReadme(d ReadmeTmplData) string {
	var buf bytes.Buffer
	_ = readmeTmpl.Execute(&buf, d) // pre-parsed template, no error-returning methods: cannot fail
	return buf.String()
}

// SetupScriptData holds all inputs needed to render the idempotent setup.sh.
type SetupScriptData struct {
	// File contents to embed (base64-encoded) in the script.
	WGServerConf    string // /etc/wireguard/wg-initramfs.conf (mode 0600)
	InitramfsHook   string // /etc/initramfs-tools/hooks/wireguard (chmod +x)
	InitramfsScript string // /etc/initramfs-tools/scripts/init-premount/wireguard (chmod +x)
	AuthorizedKeys  string // <dropbear_dir>/authorized_keys (mode 0600)
	DropbearConf    string // <dropbear_dir>/dropbear.conf
	UMASKConf       string // /etc/initramfs-tools/conf.d/ubo

	// Network info for GRUB ip= param.
	NetIP        string // e.g. "192.168.1.100"
	NetGateway   string // e.g. "192.168.1.1"
	NetMask      string // e.g. "255.255.255.0"
	NetHostname  string // e.g. "server"
	NetInterface string // e.g. "eth0"
}

// setupScriptRendered is the internal struct passed to the template after
// pre-encoding all file contents to base64.
type setupScriptRendered struct {
	WGServerConf    string
	InitramfsHook   string
	InitramfsScript string
	AuthorizedKeys  string
	DropbearConf    string
	UMASKConf       string
	NetIP           string
	NetGateway      string
	NetMask         string
	NetHostname     string
	NetInterface    string
}

// SetupScriptTmpl is the idempotent setup.sh script. It runs all configuration
// steps on the remote host in one SSH session and prints a JSON result on stdout.
// File contents are base64-encoded to avoid shell quoting issues.
const SetupScriptTmpl = `#!/bin/sh
set -e

# ── Step 2: Install packages ──────────────────────────────────────────────────
echo "[ubo-setup] step 2/11: installing packages" >&2
DEBIAN_FRONTEND=noninteractive apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dropbear-initramfs wireguard-tools mdadm

# ── Step 2b: Preflight checks ────────────────────────────────────────────────
# Abort if /boot is on an encrypted volume: the initramfs would embed the WireGuard
# private key inside the very image that can't be read without unlocking first.
_boot_dev=$(df /boot 2>/dev/null | awk 'NR==2{print $1}')
if [ -n "$_boot_dev" ] && cryptsetup isLuks "$_boot_dev" 2>/dev/null; then
    echo "[ubo-setup] ERROR: /boot is on an encrypted device ($boot_dev); cannot embed keys in initramfs" >&2
    exit 1
fi

# Warn if Secure Boot is enabled — our initramfs hook is unsigned.
if [ -d /sys/firmware/efi/efivars ]; then
    _sb_file=$(ls /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | head -1)
    if [ -n "$_sb_file" ]; then
        _sb=$(od -An -j4 -N1 -t u1 < "$_sb_file" 2>/dev/null | tr -d ' \n')
        if [ "$_sb" = "1" ]; then
            echo "[ubo-setup] WARNING: Secure Boot is enabled; the initramfs WireGuard hook is unsigned and may be blocked at boot" >&2
        fi
    fi
fi

# Warn if the WireGuard kernel module is not available.
if ! modinfo wireguard >/dev/null 2>&1; then
    echo "[ubo-setup] WARNING: wireguard kernel module not found; ensure linux-headers or linux-image-extra is installed" >&2
fi

# ── Step 3: Detect dropbear path and regenerate host key ─────────────────────
echo "[ubo-setup] step 3/11: generating dropbear host key" >&2
if [ -d /etc/dropbear/initramfs ]; then
    DROPBEAR_DIR=/etc/dropbear/initramfs
elif [ -d /etc/dropbear-initramfs ]; then
    DROPBEAR_DIR=/etc/dropbear-initramfs
else
    echo "[ubo-setup] error: dropbear-initramfs config directory not found" >&2
    exit 1
fi
DROPBEAR_KEY="$DROPBEAR_DIR/dropbear_ed25519_host_key"
rm -f "$DROPBEAR_KEY"
dropbearkey -t ed25519 -f "$DROPBEAR_KEY" >&2
DROPBEAR_PUB=$(dropbearkey -y -f "$DROPBEAR_KEY" 2>/dev/null | grep '^ssh-')

# ── Steps 4-9: Write config files ─────────────────────────────────────────────
echo "[ubo-setup] steps 4-9/11: writing config files" >&2

mkdir -p /etc/wireguard
printf '%s' '{{.WGServerConf}}' | base64 -d > /etc/wireguard/wg-initramfs.conf
chmod 600 /etc/wireguard/wg-initramfs.conf

mkdir -p /etc/initramfs-tools/hooks
printf '%s' '{{.InitramfsHook}}' | base64 -d > /etc/initramfs-tools/hooks/wireguard
chmod 755 /etc/initramfs-tools/hooks/wireguard

mkdir -p /etc/initramfs-tools/scripts/init-premount
printf '%s' '{{.InitramfsScript}}' | base64 -d > /etc/initramfs-tools/scripts/init-premount/wireguard
chmod 755 /etc/initramfs-tools/scripts/init-premount/wireguard

printf '%s' '{{.AuthorizedKeys}}' | base64 -d > "$DROPBEAR_DIR/authorized_keys"
chmod 600 "$DROPBEAR_DIR/authorized_keys"

printf '%s' '{{.DropbearConf}}' | base64 -d > "$DROPBEAR_DIR/dropbear.conf"

mkdir -p /etc/initramfs-tools/conf.d
printf '%s' '{{.UMASKConf}}' | base64 -d > /etc/initramfs-tools/conf.d/ubo

# ── Step 9b: Ensure NIC driver(s) are included in initramfs ──────────────────
# update-initramfs includes storage drivers for LUKS but skips NIC drivers on
# systems where the root filesystem is local (not NFS). Detect and add each
# required module (handles plain NIC, bond, bridge, and VLAN topologies).
_add_mod() {
    [ -z "$1" ] && return
    grep -qxF "$1" /etc/initramfs-tools/modules 2>/dev/null || \
        echo "$1" >> /etc/initramfs-tools/modules
    echo "[ubo-setup] initramfs module: $1" >&2
}
_drv_for() {
    basename "$(readlink /sys/class/net/"$1"/device/driver 2>/dev/null)" 2>/dev/null || true
}
_NIC="{{.NetInterface}}"
if [ -f /sys/class/net/"$_NIC"/bonding/slaves ]; then
    _add_mod bonding
    for _sl in $(cat /sys/class/net/"$_NIC"/bonding/slaves); do _add_mod "$(_drv_for "$_sl")"; done
elif ls /sys/class/net/"$_NIC"/brif/ >/dev/null 2>&1; then
    _add_mod bridge
    for _pt in $(ls /sys/class/net/"$_NIC"/brif/); do _add_mod "$(_drv_for "$_pt")"; done
elif ls /sys/class/net/"$_NIC"/lower_* >/dev/null 2>&1; then
    _add_mod 8021q
    for _lw in /sys/class/net/"$_NIC"/lower_*; do
        _pd=$(basename "$(readlink "$_lw" 2>/dev/null)" 2>/dev/null || true)
        [ -n "$_pd" ] && _add_mod "$(_drv_for "$_pd")"
    done
else
    _add_mod "$(_drv_for "$_NIC")"
fi

# ── Step 10: Configure bootloader ─────────────────────────────────────────────
echo "[ubo-setup] step 10/11: configuring bootloader" >&2
IP_PARAM="ip={{.NetIP}}::{{.NetGateway}}:{{.NetMask}}:{{.NetHostname}}:{{.NetInterface}}:none"
if [ -f /etc/default/grub ]; then
    GRUB_FILE=/etc/default/grub
    if grep -qE '^GRUB_CMDLINE_LINUX="[^"]*ip=' "$GRUB_FILE" 2>/dev/null; then
        echo "[ubo-setup] GRUB_CMDLINE_LINUX already contains ip=; skipping" >&2
    elif grep -qE '^GRUB_CMDLINE_LINUX="' "$GRUB_FILE" 2>/dev/null; then
        sed -i "s|^GRUB_CMDLINE_LINUX=\"\(.*\)\"|GRUB_CMDLINE_LINUX=\"\1 $IP_PARAM\"|" "$GRUB_FILE"
        update-grub 2>&1 >&2
    else
        printf '\nGRUB_CMDLINE_LINUX="%s"\n' "$IP_PARAM" >> "$GRUB_FILE"
        update-grub 2>&1 >&2
    fi
else
    _updated=0
    for _efi_dir in /boot/loader/entries /efi/loader/entries /boot/efi/loader/entries; do
        [ -d "$_efi_dir" ] || continue
        for _entry in "$_efi_dir"/*.conf; do
            [ -f "$_entry" ] || continue
            grep -q ' ip=' "$_entry" && continue
            grep -q '^options ' "$_entry" || continue
            sed -i "s|^\(options .*\)$|\1 $IP_PARAM|" "$_entry" && _updated=1
        done
    done
    if [ "$_updated" = "1" ]; then
        echo "[ubo-setup] added $IP_PARAM to systemd-boot entries" >&2
    elif ls /boot/loader/entries/*.conf /efi/loader/entries/*.conf /boot/efi/loader/entries/*.conf >/dev/null 2>&1; then
        echo "[ubo-setup] systemd-boot entries already contain ip=; skipping" >&2
    else
        echo "[ubo-setup] WARNING: no GRUB or systemd-boot config found; add manually: $IP_PARAM" >&2
    fi
fi

# ── Step 11: Rebuild initramfs ────────────────────────────────────────────────
echo "[ubo-setup] step 11/11: rebuilding initramfs" >&2
update-initramfs -u -k all >&2

# ── Output JSON result ────────────────────────────────────────────────────────
printf '{"dropbear_pub_key":"%s"}\n' "$DROPBEAR_PUB"
`

var setupScriptTmpl = template.Must(template.New("setup-script").Parse(SetupScriptTmpl))

// RenderSetupScript renders SetupScriptTmpl with d, base64-encoding all file
// contents so they can be safely embedded in the shell script.
func RenderSetupScript(d SetupScriptData) (string, error) {
	if err := validateSetupScriptData(d); err != nil {
		return "", err
	}
	r := setupScriptRendered{
		WGServerConf:    base64.StdEncoding.EncodeToString([]byte(d.WGServerConf)),
		InitramfsHook:   base64.StdEncoding.EncodeToString([]byte(d.InitramfsHook)),
		InitramfsScript: base64.StdEncoding.EncodeToString([]byte(d.InitramfsScript)),
		AuthorizedKeys:  base64.StdEncoding.EncodeToString([]byte(d.AuthorizedKeys)),
		DropbearConf:    base64.StdEncoding.EncodeToString([]byte(d.DropbearConf)),
		UMASKConf:       base64.StdEncoding.EncodeToString([]byte(d.UMASKConf)),
		NetIP:           d.NetIP,
		NetGateway:      d.NetGateway,
		NetMask:         d.NetMask,
		NetHostname:     d.NetHostname,
		NetInterface:    d.NetInterface,
	}
	var buf bytes.Buffer
	_ = setupScriptTmpl.Execute(&buf, r) // pre-parsed template, no error-returning methods: cannot fail
	return buf.String(), nil
}

// validateSetupScriptData checks that all required fields are present.
func validateSetupScriptData(d SetupScriptData) error {
	type req struct {
		name string
		val  string
	}
	for _, r := range []req{
		{"WGServerConf", d.WGServerConf},
		{"InitramfsHook", d.InitramfsHook},
		{"InitramfsScript", d.InitramfsScript},
		{"AuthorizedKeys", d.AuthorizedKeys},
		{"DropbearConf", d.DropbearConf},
		{"UMASKConf", d.UMASKConf},
		{"NetIP", d.NetIP},
		{"NetGateway", d.NetGateway},
		{"NetMask", d.NetMask},
		{"NetHostname", d.NetHostname},
		{"NetInterface", d.NetInterface},
	} {
		if r.val == "" {
			return fmt.Errorf("RenderSetupScript: %s is required", r.name)
		}
	}
	return nil
}
