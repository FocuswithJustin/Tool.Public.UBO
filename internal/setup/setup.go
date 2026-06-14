package setup

import (
	"context"
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

func step(n int, msg string) {
	fmt.Printf("[ubo] step %d/%d: %s\n", n, totalSteps, msg)
}

// NetworkInfo holds the detected network configuration of the remote host.
type NetworkInfo struct {
	Interface string
	IP        string
	Prefix    int
	Gateway   string
	Hostname  string
}

// dropbearPaths holds the detected dropbear-initramfs config directory and key file.
type dropbearPaths struct {
	ConfigDir   string
	HostKeyFile string
}

// Configure runs all 11 setup steps on the remote host.
// It saves the Dropbear host public key to outputDir/dropbear_host_key.pub.
func Configure(ctx context.Context, client *remote.Client, cfg *config.Config, keys *keygen.Keys, outputDir string) error {
	netInfo, err := stepDetectNetwork(ctx, client, cfg)
	if err != nil {
		return err
	}

	if err := stepInstallPackages(ctx, client); err != nil {
		return err
	}

	dbPaths, err := stepGenerateHostKey(ctx, client, outputDir)
	if err != nil {
		return err
	}

	if err := stepWriteConfigs(client, cfg, keys, dbPaths); err != nil {
		return err
	}

	return stepGrubAndInitramfs(ctx, client, netInfo)
}

// stepWriteConfigs runs steps 4-9: report the dropbear config dir then write the
// WireGuard config, initramfs hook/script, and Dropbear authorized_keys/config.
func stepWriteConfigs(client *remote.Client, cfg *config.Config, keys *keygen.Keys, dbPaths *dropbearPaths) error {
	// Step 4: Report detected dropbear config path
	step(4, fmt.Sprintf("using dropbear config dir: %s", dbPaths.ConfigDir))

	if err := stepWriteWireGuardConfig(client, cfg, keys); err != nil {
		return err
	}

	if err := stepWriteInitramfsHook(client); err != nil {
		return err
	}

	if err := stepWriteInitramfsScript(client, cfg); err != nil {
		return err
	}

	return stepWriteDropbear(client, cfg, keys, dbPaths)
}

// stepGrubAndInitramfs runs steps 10 and 11: configure GRUB and rebuild initramfs.
func stepGrubAndInitramfs(ctx context.Context, client *remote.Client, netInfo *NetworkInfo) error {
	// Step 10: Configure GRUB for initramfs networking
	step(10, "configuring GRUB for initramfs networking")
	if err := configureGrub(ctx, client, netInfo); err != nil {
		return fmt.Errorf("step 10 configure GRUB: %w", err)
	}

	// Step 11: Rebuild initramfs
	step(11, "rebuilding initramfs (this may take a minute)")
	if _, err := runCommand(ctx, client, "update-initramfs -u -k all"); err != nil {
		return fmt.Errorf("step 11 update-initramfs: %w", err)
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
	return netInfo, nil
}

// stepInstallPackages runs step 2: install dropbear-initramfs and wireguard-tools.
func stepInstallPackages(ctx context.Context, client *remote.Client) error {
	step(2, "installing dropbear-initramfs and wireguard-tools")
	installCmd := "DEBIAN_FRONTEND=noninteractive apt-get update -qq && " +
		"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dropbear-initramfs wireguard-tools"
	if _, err := runCommand(ctx, client, installCmd); err != nil {
		return fmt.Errorf("step 2 install packages: %w", err)
	}
	return nil
}

// stepGenerateHostKey runs step 3: detect dropbear paths, regenerate the host
// key, and pin its public key under outputDir.
func stepGenerateHostKey(ctx context.Context, client *remote.Client, outputDir string) (*dropbearPaths, error) {
	step(3, "generating Dropbear host key")
	dbPaths, err := detectDropbearPaths(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("step 3 detect dropbear paths: %w", err)
	}
	hostPubKey, err := generateDropbearHostKey(ctx, client, dbPaths.HostKeyFile)
	if err != nil {
		return nil, fmt.Errorf("step 3 generate dropbear host key: %w", err)
	}
	pinnedPath := filepath.Join(outputDir, "dropbear_host_key.pub")
	if err := os.WriteFile(pinnedPath, []byte(hostPubKey+"\n"), 0644); err != nil {
		return nil, fmt.Errorf("save dropbear host key: %w", err)
	}
	fmt.Printf("[ubo]   dropbear host key saved to %s\n", pinnedPath)
	return dbPaths, nil
}

// stepWriteWireGuardConfig runs step 5: render and write the WireGuard server config.
func stepWriteWireGuardConfig(client *remote.Client, cfg *config.Config, keys *keygen.Keys) error {
	step(5, "writing WireGuard server config")
	wgServerCfg := templates.WireGuardServerConfig{
		Address:        cfg.WireGuard.ServerIP,
		PrivateKey:     keys.ServerWGPrivate,
		ListenPort:     cfg.WireGuard.Port,
		PeerPublicKey:  keys.ClientWGPublic,
		PeerAllowedIPs: cfg.WGClientTunnelIP() + "/32",
	}
	wgServerINI, err := wgServerCfg.MarshalINI()
	if err != nil {
		return fmt.Errorf("step 5 render WireGuard config: %w", err)
	}
	if err := writeFile(client, "/etc/wireguard/wg-initramfs.conf", wgServerINI, 0600); err != nil {
		return fmt.Errorf("step 5 write WireGuard config: %w", err)
	}
	return nil
}

// stepWriteInitramfsHook runs step 6: write the initramfs WireGuard hook.
func stepWriteInitramfsHook(client *remote.Client) error {
	step(6, "writing initramfs WireGuard hook")
	if err := writeFileExec(client, "/etc/initramfs-tools/hooks/wireguard", templates.InitramfsHookTmpl); err != nil {
		return fmt.Errorf("step 6 write initramfs hook: %w", err)
	}
	return nil
}

// stepWriteInitramfsScript runs step 7: render and write the initramfs startup script.
func stepWriteInitramfsScript(client *remote.Client, cfg *config.Config) error {
	step(7, "writing initramfs WireGuard startup script")
	initScript, err := templates.RenderInitramfsScript(templates.InitramfsScriptData{
		ServerIP: cfg.WireGuard.ServerIP,
	})
	if err != nil {
		return fmt.Errorf("step 7 render initramfs script: %w", err)
	}
	if err := writeFileExec(client, "/etc/initramfs-tools/scripts/init-premount/wireguard", initScript); err != nil {
		return fmt.Errorf("step 7 write initramfs script: %w", err)
	}
	return nil
}

// stepWriteDropbear runs steps 8 and 9: write Dropbear authorized_keys and config.
func stepWriteDropbear(client *remote.Client, cfg *config.Config, keys *keygen.Keys, dbPaths *dropbearPaths) error {
	// Step 8: Write Dropbear authorized_keys
	step(8, "configuring Dropbear authorized keys")
	authKeysPath := dbPaths.ConfigDir + "/authorized_keys"
	if err := writeFile(client, authKeysPath, keys.ClientSSHPubKey+"\n", 0600); err != nil {
		return fmt.Errorf("step 8 write authorized_keys: %w", err)
	}

	// Step 9: Write Dropbear config
	step(9, "configuring Dropbear options")
	dbConf, err := templates.RenderDropbearConfig(templates.DropbearConfigData{
		ServerTunnelIP: cfg.WGServerTunnelIP(),
		DropbearPort:   cfg.Dropbear.Port,
	})
	if err != nil {
		return fmt.Errorf("step 9 render dropbear config: %w", err)
	}
	if err := writeFile(client, dbPaths.ConfigDir+"/dropbear.conf", dbConf, 0644); err != nil {
		return fmt.Errorf("step 9 write dropbear config: %w", err)
	}
	return nil
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

	detectPrefix(ctx, client, info)
	detectHostname(ctx, client, info)

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

// detectPrefix fills info.Prefix from `ip addr` when unset, falling back to /24.
func detectPrefix(ctx context.Context, client *remote.Client, info *NetworkInfo) {
	if info.Prefix != 0 || info.IP == "" {
		return
	}
	if addrOut, addrErr := runCommand(ctx, client, "ip addr show dev "+info.Interface); addrErr == nil {
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
func generateDropbearHostKey(ctx context.Context, client *remote.Client, keyFile string) (string, error) {
	runCommand(ctx, client, "rm -f "+keyFile) //nolint:errcheck

	if _, err := runCommand(ctx, client, "dropbearkey -t ed25519 -f "+keyFile); err != nil {
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
	return "", fmt.Errorf("could not extract public key from dropbearkey output:\n%s", out)
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
