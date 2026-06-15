package setup

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"ubo/internal/config"
	"ubo/internal/keygen"
	"ubo/internal/remote"
	"ubo/internal/templates"
)

const totalSteps = 11

// Test seams: indirection over the remote package so tests can inject fakes
// without a real SSH connection. Production behavior is identical to calling
// the remote.* functions directly.
var (
	runCommand    = remote.RunCommand
	readFile      = remote.ReadFile
	writeFile     = remote.WriteFile
	writeFileExec = remote.WriteFileExec
)

// runSetupScript uploads script to /tmp/ubo-setup.sh and executes it on the
// remote host, returning its stdout (the JSON result).
var runSetupScript = func(ctx context.Context, client *remote.Client, script string) (string, error) {
	if err := writeFile(client, "/tmp/ubo-setup.sh", script, 0700); err != nil {
		return "", fmt.Errorf("upload setup script: %w", err)
	}
	out, err := runCommand(ctx, client, "sh /tmp/ubo-setup.sh")
	if err != nil {
		return "", fmt.Errorf("run setup script: %w", err)
	}
	return out, nil
}

func step(n int, msg string) {
	fmt.Printf("[ubo] step %d/%d: %s\n", n, totalSteps, msg)
}

// NetworkInfo holds the detected network configuration of the remote host.
type NetworkInfo struct {
	Interface   string
	IP          string
	Prefix      int
	Gateway     string
	Hostname    string
	VLANPhysdev string   // parent NIC if Interface is a VLAN (empty if not VLAN)
	VLANID      int      // 802.1Q VLAN ID (0 if not a VLAN)
	BondSlaves  []string // slave NICs for a bond interface (nil if not bond)
	BondMode    string   // bonding mode, e.g. "active-backup" (empty if not bond)
	BridgePorts []string // bridge port NICs (nil if not bridge)
}

// dropbearPaths holds the detected dropbear-initramfs config directory and key file.
type dropbearPaths struct {
	ConfigDir   string
	HostKeyFile string
}

// setupResult is the JSON returned by the setup script on stdout.
type setupResult struct {
	DropbearPubKey string `json:"dropbear_pub_key"`
}

// Configure runs all 11 setup steps on the remote host.
// It saves the Dropbear host public key to outputDir/dropbear_host_key.pub.
func Configure(ctx context.Context, client *remote.Client, cfg *config.Config, keys *keygen.Keys, outputDir string) error {
	// Step 1: Detect remote network configuration (still separate SSH calls
	// because we need the results to embed in the setup script).
	netInfo, err := stepDetectNetwork(ctx, client, cfg)
	if err != nil {
		return err
	}

	// Build all file contents that will be embedded in the setup script.
	scriptData, err := buildSetupScriptData(cfg, keys, netInfo)
	if err != nil {
		return err
	}

	// Render the setup script.
	script, err := templates.RenderSetupScript(scriptData)
	if err != nil {
		return fmt.Errorf("render setup script: %w", err)
	}

	// Steps 2-11: run the setup script on the remote host.
	step(2, "installing packages, writing configs, configuring GRUB, rebuilding initramfs")
	out, err := runSetupScript(ctx, client, script)
	if err != nil {
		return err
	}

	// Parse the JSON result from the script.
	pubKey, err := parseSetupResult(out)
	if err != nil {
		return err
	}

	// Save the Dropbear host public key locally.
	return savePinnedKey(outputDir, pubKey)
}

// buildSetupScriptData renders all file contents and assembles SetupScriptData.
func buildSetupScriptData(cfg *config.Config, keys *keygen.Keys, netInfo *NetworkInfo) (templates.SetupScriptData, error) {
	wgServerINI, err := renderWGConfig(cfg, keys)
	if err != nil {
		return templates.SetupScriptData{}, err
	}

	initScript, err := templates.RenderInitramfsScript(templates.InitramfsScriptData{
		ServerIP:    cfg.WireGuard.ServerIP,
		StaticIP:    fmt.Sprintf("%s/%d", netInfo.IP, netInfo.Prefix),
		GatewayIP:   netInfo.Gateway,
		Interface:   netInfo.Interface,
		VLANPhysdev: netInfo.VLANPhysdev,
		VLANID:      netInfo.VLANID,
		BondSlaves:  strings.Join(netInfo.BondSlaves, " "),
		BondMode:    netInfo.BondMode,
	})
	if err != nil {
		return templates.SetupScriptData{}, fmt.Errorf("render initramfs script: %w", err)
	}

	dbConf, err := templates.RenderDropbearConfig(templates.DropbearConfigData{
		ServerTunnelIP: cfg.WGServerTunnelIP(),
		DropbearPort:   cfg.Dropbear.Port,
	})
	if err != nil {
		return templates.SetupScriptData{}, fmt.Errorf("render dropbear config: %w", err)
	}

	if err := validateGrubNetFields(netInfo); err != nil {
		return templates.SetupScriptData{}, fmt.Errorf("validate network fields: %w", err)
	}

	return templates.SetupScriptData{
		WGServerConf:    wgServerINI,
		InitramfsHook:   templates.InitramfsHookTmpl,
		InitramfsScript: initScript,
		AuthorizedKeys:  keys.ClientSSHPubKey + "\n",
		DropbearConf:    dbConf,
		UMASKConf:       templates.InitramfsUMASKConf,
		NetIP:           netInfo.IP,
		NetGateway:      netInfo.Gateway,
		NetMask:         prefixToNetmask(netInfo.Prefix),
		NetHostname:     netInfo.Hostname,
		NetInterface:    netInfo.Interface,
	}, nil
}

// renderWGConfig renders the WireGuard server INI config.
func renderWGConfig(cfg *config.Config, keys *keygen.Keys) (string, error) {
	wgServerCfg := templates.WireGuardServerConfig{
		Address:        cfg.WireGuard.ServerIP,
		PrivateKey:     keys.ServerWGPrivate,
		ListenPort:     cfg.WireGuard.Port,
		PeerPublicKey:  keys.ClientWGPublic,
		PeerAllowedIPs: cfg.WGClientTunnelIP() + "/32",
	}
	out, err := wgServerCfg.MarshalINI()
	if err != nil {
		return "", fmt.Errorf("step 5 render WireGuard config: %w", err)
	}
	return out, nil
}

// parseSetupResult extracts the dropbear public key from JSON script output.
func parseSetupResult(out string) (string, error) {
	// The script may emit progress lines to stderr but still include JSON on
	// stdout; find the last line that starts with '{'.
	jsonLine := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "{") {
			jsonLine = line
		}
	}
	if jsonLine == "" {
		return "", fmt.Errorf("setup script produced no JSON output; got:\n%s", out)
	}
	var result setupResult
	if err := json.Unmarshal([]byte(jsonLine), &result); err != nil {
		return "", fmt.Errorf("parse setup script JSON: %w", err)
	}
	if result.DropbearPubKey == "" {
		return "", fmt.Errorf("setup script JSON missing dropbear_pub_key; got: %s", jsonLine)
	}
	return result.DropbearPubKey, nil
}

// savePinnedKey writes the Dropbear host public key to outputDir.
func savePinnedKey(outputDir, pubKey string) error {
	pinnedPath := filepath.Join(outputDir, "dropbear_host_key.pub")
	if err := os.WriteFile(pinnedPath, []byte(pubKey+"\n"), 0644); err != nil {
		return fmt.Errorf("save dropbear host key: %w", err)
	}
	fmt.Printf("[ubo]   dropbear host key saved to %s\n", pinnedPath)
	return nil
}

// validateGrubNetFields ensures the network values that get interpolated into
// the GRUB ip= kernel parameter are well-formed. The interface name is already
// validated during detection; here we guard the IP, gateway, and hostname.
func validateGrubNetFields(info *NetworkInfo) error {
	if net.ParseIP(info.IP) == nil {
		return fmt.Errorf("detected IP %q is not a valid address; set network.ip in config", info.IP)
	}
	if net.ParseIP(info.Gateway) == nil {
		return fmt.Errorf("detected gateway %q is not a valid address", info.Gateway)
	}
	if !isValidHostname(info.Hostname) {
		return fmt.Errorf("detected hostname %q contains unexpected characters", info.Hostname)
	}
	return nil
}

// stepDetectNetwork runs step 1: detect and report the remote network config.
func stepDetectNetwork(ctx context.Context, client *remote.Client, cfg *config.Config) (*NetworkInfo, error) {
	step(1, "detecting remote network configuration")
	netInfo, err := detectNetwork(ctx, client, cfg)
	if err != nil {
		return nil, fmt.Errorf("step 1 detect network: %w", err)
	}
	fmt.Printf("[ubo]   interface=%s ip=%s/%d gateway=%s hostname=%s\n",
		netInfo.Interface, netInfo.IP, netInfo.Prefix, netInfo.Gateway, netInfo.Hostname)
	logTopology(netInfo)
	return netInfo, nil
}

// detectNetwork determines the remote network configuration.
// Values in cfg.Network override auto-detection.
func detectNetwork(ctx context.Context, client *remote.Client, cfg *config.Config) (*NetworkInfo, error) {
	info := &NetworkInfo{
		Interface: cfg.Network.Interface,
	}

	if err := applyConfigIP(info, cfg.Network.IP); err != nil {
		return nil, err
	}

	if err := parseDefaultRoute(ctx, client, info); err != nil {
		return nil, err
	}

	if err := validateInterface(info); err != nil {
		return nil, err
	}

	// Some systems omit the src token from the default route (e.g. hosts where
	// the gateway is in-subnet). Fall back to ip -4 addr to find both IP and
	// prefix from the interface address, then let detectPrefix refine if needed.
	if info.IP == "" {
		fillIPFromAddr(ctx, client, info)
	}

	detectPrefix(ctx, client, info)
	detectHostname(ctx, client, info)
	detectInterfaceTopology(ctx, client, info)

	return info, validateNetworkInfo(info)
}

// applyConfigIP fills info.IP and info.Prefix from a config CIDR (if non-empty).
func applyConfigIP(info *NetworkInfo, cfgIP string) error {
	if cfgIP == "" {
		return nil
	}
	ip, ipNet, err := net.ParseCIDR(cfgIP)
	if err != nil {
		return fmt.Errorf("invalid network.ip %q: %w", cfgIP, err)
	}
	info.IP = ip.String()
	ones, _ := ipNet.Mask.Size()
	info.Prefix = ones
	return nil
}

// validateInterface ensures the interface was detected and has a safe name.
func validateInterface(info *NetworkInfo) error {
	if info.Interface == "" {
		return fmt.Errorf("could not determine network interface; set network.interface in config")
	}
	if !isValidInterfaceName(info.Interface) {
		return fmt.Errorf("detected interface name %q contains unexpected characters; set network.interface in config", info.Interface)
	}
	return nil
}

// validateNetworkInfo ensures IP and Gateway were determined.
func validateNetworkInfo(info *NetworkInfo) error {
	if info.IP == "" {
		return fmt.Errorf("could not determine IP address; set network.ip in config")
	}
	if info.Gateway == "" {
		return fmt.Errorf("could not determine default gateway from the remote routing table")
	}
	return nil
}

// parseDefaultRoute runs `ip route show default` and fills any unset
// Gateway/Interface/IP fields on info from its output.
// Example line: "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.100 ..."
func parseDefaultRoute(ctx context.Context, client *remote.Client, info *NetworkInfo) error {
	routeOut, err := runCommand(ctx, client, "ip route show default")
	if err != nil {
		return fmt.Errorf("ip route: %w", err)
	}
	for _, line := range strings.Split(routeOut, "\n") {
		parts := strings.Fields(line)
		for i, p := range parts {
			applyRouteToken(info, parts, i, p)
		}
	}
	return nil
}

// applyRouteToken sets the matching info field for token p at index i if that
// field is still unset and a value follows.
func applyRouteToken(info *NetworkInfo, parts []string, i int, p string) {
	if i+1 >= len(parts) {
		return
	}
	field := routeFieldFor(info, p)
	if field != nil && *field == "" {
		*field = parts[i+1]
	}
}

// routeFieldFor returns a pointer to the info field associated with route
// keyword p, or nil if p is not a recognized keyword.
func routeFieldFor(info *NetworkInfo, p string) *string {
	switch p {
	case "via":
		return &info.Gateway
	case "dev":
		return &info.Interface
	case "src":
		return &info.IP
	}
	return nil
}

// fillIPFromAddr fills info.IP (and info.Prefix) from `ip -4 addr show dev`
// when the default route lacked a `src` token. It takes the first inet address
// on the interface; if no address is found the fields are left unchanged so the
// caller's validateNetworkInfo() surfaces a clear error.
func fillIPFromAddr(ctx context.Context, client *remote.Client, info *NetworkInfo) {
	if info.Interface == "" {
		return
	}
	out, err := runCommand(ctx, client, "ip -4 addr show dev "+info.Interface)
	if err != nil {
		return
	}
	ip, prefix := firstInetAddr(out)
	if ip != "" {
		info.IP = ip
		info.Prefix = prefix
	}
}

// firstInetAddr returns the IP string and prefix length of the first inet
// address found in `ip addr` output, or ("", 0) if none is present.
func firstInetAddr(out string) (string, int) {
	re := regexp.MustCompile(`inet (\d+\.\d+\.\d+\.\d+/\d+)`)
	for _, m := range re.FindAllStringSubmatch(out, 1) {
		addr, ipNet, err := net.ParseCIDR(m[1])
		if err != nil {
			continue
		}
		ones, _ := ipNet.Mask.Size()
		return addr.String(), ones
	}
	return "", 0
}

// detectPrefix fills info.Prefix from `ip -4 addr` when unset, falling back to /24.
func detectPrefix(ctx context.Context, client *remote.Client, info *NetworkInfo) {
	if info.Prefix != 0 || info.IP == "" {
		return
	}
	if addrOut, addrErr := runCommand(ctx, client, "ip -4 addr show dev "+info.Interface); addrErr == nil {
		info.Prefix = prefixForIP(addrOut, info.IP)
	}
	if info.Prefix == 0 {
		fmt.Printf("[ubo]   warning: could not detect network prefix length, assuming /24\n")
		info.Prefix = 24
	}
}

// prefixForIP scans `ip addr` output for the inet line matching ip and returns
// its prefix length, or 0 if none matches.
func prefixForIP(addrOut, ip string) int {
	re := regexp.MustCompile(`inet (\d+\.\d+\.\d+\.\d+/\d+)`)
	for _, m := range re.FindAllStringSubmatch(addrOut, -1) {
		addrIP, ipNet, parseErr := net.ParseCIDR(m[1])
		if parseErr == nil && addrIP.String() == ip {
			ones, _ := ipNet.Mask.Size()
			return ones
		}
	}
	return 0
}

// detectHostname fills info.Hostname, defaulting to "server" on failure/empty.
func detectHostname(ctx context.Context, client *remote.Client, info *NetworkInfo) {
	hostnameOut, hostnameErr := runCommand(ctx, client, "hostname")
	if hostnameErr != nil {
		fmt.Printf("[ubo]   warning: hostname detection failed, using fallback \"server\"\n")
	}
	info.Hostname = strings.TrimSpace(hostnameOut)
	if info.Hostname == "" {
		info.Hostname = "server"
	}
}

// detectInterfaceTopology detects whether the network interface is a VLAN,
// bond, or bridge, and fills the corresponding NetworkInfo fields.
func detectInterfaceTopology(ctx context.Context, client *remote.Client, info *NetworkInfo) {
	detectVLAN(ctx, client, info)
	detectBond(ctx, client, info)
	detectBondMode(ctx, client, info)
	detectVLANBond(ctx, client, info)
	detectBridge(ctx, client, info)
}

// vlanParentRe matches the "@parent:" portion of an `ip -d link show` line.
var vlanParentRe = regexp.MustCompile(`@(\S+?):`)

// vlanIDRe matches the VLAN id from `ip -d link show` detailed output.
var vlanIDRe = regexp.MustCompile(`\bvlan\b.*\bid\s+(\d+)`)

// detectVLAN checks whether the interface is an 802.1Q VLAN and fills
// info.VLANPhysdev and info.VLANID when it is.
func detectVLAN(ctx context.Context, client *remote.Client, info *NetworkInfo) {
	out, err := runCommand(ctx, client, "ip -d link show "+info.Interface+" 2>/dev/null")
	if err != nil {
		return
	}
	physdev, id := parseVLANLink(out)
	if physdev != "" && id > 0 {
		info.VLANPhysdev = physdev
		info.VLANID = id
	}
}

// parseVLANLink extracts the parent device and VLAN ID from `ip -d link show` output.
func parseVLANLink(out string) (physdev string, id int) {
	if m := vlanParentRe.FindStringSubmatch(out); m != nil {
		physdev = strings.TrimSpace(m[1])
	}
	if m := vlanIDRe.FindStringSubmatch(out); m != nil {
		fmt.Sscanf(m[1], "%d", &id)
	}
	return
}

// detectBond checks whether the interface is a bonding master and fills
// info.BondSlaves with the slave interface names when it is.
func detectBond(ctx context.Context, client *remote.Client, info *NetworkInfo) {
	out, err := runCommand(ctx, client, "cat /sys/class/net/"+info.Interface+"/bonding/slaves 2>/dev/null")
	if err != nil {
		return
	}
	slaves := strings.Fields(strings.TrimSpace(out))
	if len(slaves) > 0 {
		info.BondSlaves = slaves
	}
}

// detectBondMode reads the bonding mode from sysfs and fills info.BondMode
// (e.g. "active-backup"). Only runs when info.BondSlaves is non-empty.
func detectBondMode(ctx context.Context, client *remote.Client, info *NetworkInfo) {
	if len(info.BondSlaves) == 0 {
		return
	}
	out, err := runCommand(ctx, client, "cat /sys/class/net/"+info.Interface+"/bonding/mode 2>/dev/null")
	if err != nil {
		return
	}
	// sysfs output is "mode-name N", e.g. "active-backup 1"; take first word.
	if f := strings.Fields(strings.TrimSpace(out)); len(f) > 0 {
		info.BondMode = f[0]
	}
}

// detectVLANBond checks whether the VLAN's parent device is itself a bond.
// If so, it copies the bond slaves and mode from the parent into info so that
// the initramfs script can set up bond→VLAN stacking.
func detectVLANBond(ctx context.Context, client *remote.Client, info *NetworkInfo) {
	if info.VLANPhysdev == "" {
		return
	}
	physInfo := &NetworkInfo{Interface: info.VLANPhysdev}
	detectBond(ctx, client, physInfo)
	detectBondMode(ctx, client, physInfo)
	if len(physInfo.BondSlaves) > 0 {
		info.BondSlaves = physInfo.BondSlaves
		info.BondMode = physInfo.BondMode
	}
}

// detectBridge checks whether the interface is a bridge and fills
// info.BridgePorts with the port interface names when it is.
func detectBridge(ctx context.Context, client *remote.Client, info *NetworkInfo) {
	out, err := runCommand(ctx, client, "ls /sys/class/net/"+info.Interface+"/brif/ 2>/dev/null")
	if err != nil {
		return
	}
	ports := strings.Fields(strings.TrimSpace(out))
	if len(ports) > 0 {
		info.BridgePorts = ports
	}
}

// logTopology prints detected interface topology to stdout.
func logTopology(info *NetworkInfo) {
	if info.VLANPhysdev != "" {
		fmt.Printf("[ubo]   VLAN id=%d physdev=%s\n", info.VLANID, info.VLANPhysdev)
	}
	if len(info.BondSlaves) > 0 {
		mode := info.BondMode
		if mode == "" {
			mode = "unknown"
		}
		fmt.Printf("[ubo]   bond mode=%s slaves=%s\n", mode, strings.Join(info.BondSlaves, ","))
	}
	if len(info.BridgePorts) > 0 {
		fmt.Printf("[ubo]   bridge ports=%s\n", strings.Join(info.BridgePorts, ","))
	}
}

// detectDropbearPaths returns the dropbear-initramfs config directory and host key path.
func detectDropbearPaths(ctx context.Context, client *remote.Client) (*dropbearPaths, error) {
	out, err := runCommand(ctx, client,
		`if [ -d /etc/dropbear/initramfs ]; then echo /etc/dropbear/initramfs; `+
			`elif [ -d /etc/dropbear-initramfs ]; then echo /etc/dropbear-initramfs; `+
			`else echo NOTFOUND; fi`)
	if err != nil {
		return nil, err
	}
	dir := strings.TrimSpace(out)
	if dir == "NOTFOUND" {
		return nil, fmt.Errorf("dropbear-initramfs config directory not found; is the package installed?")
	}
	return &dropbearPaths{
		ConfigDir:   dir,
		HostKeyFile: dir + "/dropbear_ed25519_host_key",
	}, nil
}

// generateDropbearHostKey regenerates the Dropbear ed25519 host key and returns
// its public key in authorized_keys format (e.g. "ssh-ed25519 AAAA...").
// Both stdout and stderr of the key-generation command are suppressed (they
// contain only status/progress text, not the key itself). The `-y` read-back
// redirects stderr to /dev/null so only the public key line reaches stdout.
func generateDropbearHostKey(ctx context.Context, client *remote.Client, keyFile string) (string, error) {
	runCommand(ctx, client, "rm -f "+keyFile) //nolint:errcheck

	if _, err := runCommand(ctx, client, "dropbearkey -t ed25519 -f "+keyFile+" >/dev/null 2>&1"); err != nil {
		return "", fmt.Errorf("dropbearkey: %w", err)
	}

	out, err := runCommand(ctx, client, "dropbearkey -y -f "+keyFile+" 2>/dev/null")
	if err != nil {
		return "", fmt.Errorf("dropbearkey -y: %w", err)
	}

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ssh-") {
			return line, nil
		}
	}
	return "", fmt.Errorf("could not extract public key from dropbearkey -y output")
}

// configureGrub adds the ip= kernel parameter to GRUB_CMDLINE_LINUX for
// initramfs static networking, then runs update-grub.
func configureGrub(ctx context.Context, client *remote.Client, netInfo *NetworkInfo) error {
	grubPath := "/etc/default/grub"
	content, err := readFile(client, grubPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", grubPath, err)
	}

	netmask := prefixToNetmask(netInfo.Prefix)
	ipParam := fmt.Sprintf("ip=%s::%s:%s:%s:%s:none",
		netInfo.IP, netInfo.Gateway, netmask, netInfo.Hostname, netInfo.Interface)

	updated, changed := updateGrubContent(content, ipParam)
	if !changed {
		fmt.Printf("[ubo]   GRUB_CMDLINE_LINUX already contains ip=; skipping\n")
		return nil
	}

	if err := writeFile(client, grubPath, updated, 0644); err != nil {
		return fmt.Errorf("write %s: %w", grubPath, err)
	}
	if _, err := runCommand(ctx, client, "update-grub 2>&1"); err != nil {
		return fmt.Errorf("update-grub: %w", err)
	}
	fmt.Printf("[ubo]   added to GRUB_CMDLINE_LINUX: %s\n", ipParam)
	return nil
}

// updateGrubContent appends ipParam to GRUB_CMDLINE_LINUX in content.
// Returns (updatedContent, changed). changed is false if ip= already exists
// or the line was not found (in which case it is appended as a new line).
func updateGrubContent(content, ipParam string) (string, bool) {
	re := regexp.MustCompile(`(?m)^(GRUB_CMDLINE_LINUX=")([^"]*)(")`)

	if !re.MatchString(content) {
		// Line absent — append it
		return content + fmt.Sprintf("\nGRUB_CMDLINE_LINUX=\"%s\"\n", ipParam), true
	}

	alreadySet := false
	updated := re.ReplaceAllStringFunc(content, func(match string) string {
		m := re.FindStringSubmatch(match)
		existing := m[2]
		if cmdlineHasIPParam(existing) {
			alreadySet = true
			return match
		}
		newVal := strings.TrimSpace(existing + " " + ipParam)
		return m[1] + newVal + m[3]
	})

	if alreadySet {
		return content, false
	}
	return updated, true
}

// cmdlineHasIPParam reports whether a kernel cmdline already contains an `ip=`
// parameter as a whole token. A plain substring check would false-match params
// like `gossip=` or `skip=`, causing a needed ip= to be skipped.
func cmdlineHasIPParam(cmdline string) bool {
	for _, f := range strings.Fields(cmdline) {
		if strings.HasPrefix(f, "ip=") {
			return true
		}
	}
	return false
}

// prefixToNetmask converts a CIDR prefix length to a dotted-decimal netmask string.
func prefixToNetmask(prefix int) string {
	mask := net.CIDRMask(prefix, 32)
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}

// isValidInterfaceName returns true if name looks like a real Linux interface name.
// Linux allows up to 15 characters; we allow alphanumeric, hyphen, underscore, dot.
func isValidInterfaceName(name string) bool {
	if name == "" || len(name) > 15 {
		return false
	}
	for _, c := range name {
		if !isValidInterfaceChar(c) {
			return false
		}
	}
	return true
}

// charRange is an inclusive rune range.
type charRange struct{ lo, hi rune }

// validInterfaceRanges enumerates the rune ranges allowed in an interface name.
var validInterfaceRanges = []charRange{
	{'a', 'z'},
	{'A', 'Z'},
	{'0', '9'},
	{'-', '-'},
	{'_', '_'},
	{'.', '.'},
}

// isValidInterfaceChar reports whether c is allowed in an interface name.
func isValidInterfaceChar(c rune) bool {
	for _, r := range validInterfaceRanges {
		if c >= r.lo && c <= r.hi {
			return true
		}
	}
	return false
}

// validHostnameRanges enumerates the rune ranges allowed in a hostname that is
// embedded in the GRUB ip= kernel parameter.
var validHostnameRanges = []charRange{
	{'a', 'z'},
	{'A', 'Z'},
	{'0', '9'},
	{'-', '-'},
	{'.', '.'},
}

// isValidHostname returns true if name is a plausible hostname (letters, digits,
// hyphen, dot; max 63 chars) safe to place in the GRUB ip= parameter.
func isValidHostname(name string) bool {
	if name == "" || len(name) > 63 {
		return false
	}
	for _, c := range name {
		if !isValidHostnameChar(c) {
			return false
		}
	}
	return true
}

// isValidHostnameChar reports whether c is allowed in a hostname.
func isValidHostnameChar(c rune) bool {
	for _, r := range validHostnameRanges {
		if c >= r.lo && c <= r.hi {
			return true
		}
	}
	return false
}
