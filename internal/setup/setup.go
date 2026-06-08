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

	gossh "golang.org/x/crypto/ssh"
)

const totalSteps = 11

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
func Configure(ctx context.Context, client *gossh.Client, cfg *config.Config, keys *keygen.Keys, outputDir string) error {
	// Step 1: Detect network
	step(1, "detecting remote network configuration")
	netInfo, err := detectNetwork(ctx, client, cfg)
	if err != nil {
		return fmt.Errorf("step 1 detect network: %w", err)
	}
	fmt.Printf("[ubo]   interface=%s ip=%s/%d gateway=%s hostname=%s\n",
		netInfo.Interface, netInfo.IP, netInfo.Prefix, netInfo.Gateway, netInfo.Hostname)

	// Step 2: Install packages
	step(2, "installing dropbear-initramfs and wireguard-tools")
	installCmd := "DEBIAN_FRONTEND=noninteractive apt-get update -qq && " +
		"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dropbear-initramfs wireguard-tools"
	if _, err := remote.RunCommand(ctx, client, installCmd); err != nil {
		return fmt.Errorf("step 2 install packages: %w", err)
	}

	// Step 3: Detect dropbear paths and generate host key
	step(3, "generating Dropbear host key")
	dbPaths, err := detectDropbearPaths(ctx, client)
	if err != nil {
		return fmt.Errorf("step 3 detect dropbear paths: %w", err)
	}
	hostPubKey, err := generateDropbearHostKey(ctx, client, dbPaths.HostKeyFile)
	if err != nil {
		return fmt.Errorf("step 3 generate dropbear host key: %w", err)
	}
	pinnedPath := filepath.Join(outputDir, "dropbear_host_key.pub")
	if err := os.WriteFile(pinnedPath, []byte(hostPubKey+"\n"), 0644); err != nil {
		return fmt.Errorf("save dropbear host key: %w", err)
	}
	fmt.Printf("[ubo]   dropbear host key saved to %s\n", pinnedPath)

	// Step 4: Report detected dropbear config path
	step(4, fmt.Sprintf("using dropbear config dir: %s", dbPaths.ConfigDir))

	// Step 5: Write WireGuard server config
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
	if err := remote.WriteFile(client, "/etc/wireguard/wg-initramfs.conf", wgServerINI, 0600); err != nil {
		return fmt.Errorf("step 5 write WireGuard config: %w", err)
	}

	// Step 6: Write initramfs hook
	step(6, "writing initramfs WireGuard hook")
	if err := remote.WriteFileExec(client, "/etc/initramfs-tools/hooks/wireguard", templates.InitramfsHookTmpl); err != nil {
		return fmt.Errorf("step 6 write initramfs hook: %w", err)
	}

	// Step 7: Write initramfs script
	step(7, "writing initramfs WireGuard startup script")
	initScript, err := templates.RenderInitramfsScript(templates.InitramfsScriptData{
		ServerIP: cfg.WireGuard.ServerIP,
	})
	if err != nil {
		return fmt.Errorf("step 7 render initramfs script: %w", err)
	}
	if err := remote.WriteFileExec(client, "/etc/initramfs-tools/scripts/init-premount/wireguard", initScript); err != nil {
		return fmt.Errorf("step 7 write initramfs script: %w", err)
	}

	// Step 8: Write Dropbear authorized_keys
	step(8, "configuring Dropbear authorized keys")
	authKeysPath := dbPaths.ConfigDir + "/authorized_keys"
	if err := remote.WriteFile(client, authKeysPath, keys.ClientSSHPubKey+"\n", 0600); err != nil {
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
	if err := remote.WriteFile(client, dbPaths.ConfigDir+"/dropbear.conf", dbConf, 0644); err != nil {
		return fmt.Errorf("step 9 write dropbear config: %w", err)
	}

	// Step 10: Configure GRUB for initramfs networking
	step(10, "configuring GRUB for initramfs networking")
	if err := configureGrub(ctx, client, netInfo); err != nil {
		return fmt.Errorf("step 10 configure GRUB: %w", err)
	}

	// Step 11: Rebuild initramfs
	step(11, "rebuilding initramfs (this may take a minute)")
	if _, err := remote.RunCommand(ctx, client, "update-initramfs -u -k all"); err != nil {
		return fmt.Errorf("step 11 update-initramfs: %w", err)
	}

	return nil
}

// detectNetwork determines the remote network configuration.
// Values in cfg.Network override auto-detection.
func detectNetwork(ctx context.Context, client *gossh.Client, cfg *config.Config) (*NetworkInfo, error) {
	info := &NetworkInfo{
		Interface: cfg.Network.Interface,
	}

	if cfg.Network.IP != "" {
		ip, ipNet, err := net.ParseCIDR(cfg.Network.IP)
		if err != nil {
			return nil, fmt.Errorf("invalid network.ip %q: %w", cfg.Network.IP, err)
		}
		info.IP = ip.String()
		ones, _ := ipNet.Mask.Size()
		info.Prefix = ones
	}

	// Parse default route: "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.100 ..."
	routeOut, err := remote.RunCommand(ctx, client, "ip route show default")
	if err != nil {
		return nil, fmt.Errorf("ip route: %w", err)
	}
	for _, line := range strings.Split(routeOut, "\n") {
		parts := strings.Fields(line)
		for i, p := range parts {
			if p == "via" && i+1 < len(parts) && info.Gateway == "" {
				info.Gateway = parts[i+1]
			}
			if p == "dev" && i+1 < len(parts) && info.Interface == "" {
				info.Interface = parts[i+1]
			}
			if p == "src" && i+1 < len(parts) && info.IP == "" {
				info.IP = parts[i+1]
			}
		}
	}

	if info.Interface == "" {
		return nil, fmt.Errorf("could not determine network interface; set network.interface in config")
	}

	// Get prefix length from ip addr if not already set
	if info.Prefix == 0 && info.IP != "" {
		addrOut, addrErr := remote.RunCommand(ctx, client, "ip addr show dev "+info.Interface)
		if addrErr == nil {
			re := regexp.MustCompile(`inet (\d+\.\d+\.\d+\.\d+/\d+)`)
			for _, m := range re.FindAllStringSubmatch(addrOut, -1) {
				addrIP, ipNet, parseErr := net.ParseCIDR(m[1])
				if parseErr == nil && addrIP.String() == info.IP {
					ones, _ := ipNet.Mask.Size()
					info.Prefix = ones
					break
				}
			}
		}
		if info.Prefix == 0 {
			info.Prefix = 24
		}
	}

	hostnameOut, _ := remote.RunCommand(ctx, client, "hostname")
	info.Hostname = strings.TrimSpace(hostnameOut)
	if info.Hostname == "" {
		info.Hostname = "server"
	}

	if info.IP == "" {
		return nil, fmt.Errorf("could not determine IP address; set network.ip in config")
	}
	if info.Gateway == "" {
		return nil, fmt.Errorf("could not determine gateway; set network.ip in config")
	}

	return info, nil
}

// detectDropbearPaths returns the dropbear-initramfs config directory and host key path.
func detectDropbearPaths(ctx context.Context, client *gossh.Client) (*dropbearPaths, error) {
	out, err := remote.RunCommand(ctx, client,
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
func generateDropbearHostKey(ctx context.Context, client *gossh.Client, keyFile string) (string, error) {
	remote.RunCommand(ctx, client, "rm -f "+keyFile) //nolint:errcheck

	if _, err := remote.RunCommand(ctx, client, "dropbearkey -t ed25519 -f "+keyFile); err != nil {
		return "", fmt.Errorf("dropbearkey: %w", err)
	}

	out, err := remote.RunCommand(ctx, client, "dropbearkey -y -f "+keyFile+" 2>/dev/null")
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
func configureGrub(ctx context.Context, client *gossh.Client, netInfo *NetworkInfo) error {
	grubPath := "/etc/default/grub"
	content, err := remote.ReadFile(client, grubPath)
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

	if err := remote.WriteFile(client, grubPath, updated, 0644); err != nil {
		return fmt.Errorf("write %s: %w", grubPath, err)
	}
	if _, err := remote.RunCommand(ctx, client, "update-grub 2>&1"); err != nil {
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
		if strings.Contains(existing, "ip=") {
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

// prefixToNetmask converts a CIDR prefix length to a dotted-decimal netmask string.
func prefixToNetmask(prefix int) string {
	mask := net.CIDRMask(prefix, 32)
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}
