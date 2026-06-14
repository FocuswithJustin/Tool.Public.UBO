package config

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
)

// Config holds the full ubo.toml configuration.
type Config struct {
	Host      string     `toml:"host"`
	SSH       SSHConfig  `toml:"ssh"`
	WireGuard WGConfig   `toml:"wireguard"`
	Dropbear  DBConfig   `toml:"dropbear"`
	Output    OutConfig  `toml:"output"`
	Network   NetConfig  `toml:"network"`
	LUKS      LUKSConfig `toml:"luks"`
}

type SSHConfig struct {
	User string `toml:"user"`
	Port int    `toml:"port"`
	Key  string `toml:"key"`
	Sudo bool   `toml:"sudo"`
}

type WGConfig struct {
	Port     int    `toml:"port"`
	ServerIP string `toml:"server_ip"`
	ClientIP string `toml:"client_ip"`
}

type DBConfig struct {
	Port int `toml:"port"`
}

type OutConfig struct {
	Dir string `toml:"dir"`
}

type NetConfig struct {
	Interface string `toml:"interface"`
	IP        string `toml:"ip"`
}

type LUKSConfig struct {
	Device string `toml:"device"`
}

// Default returns a Config with all defaults filled in.
func Default() *Config {
	return &Config{
		SSH: SSHConfig{
			User: "root",
			Port: 22,
		},
		WireGuard: WGConfig{
			Port:     51820,
			ServerIP: "10.42.0.1/24",
			ClientIP: "10.42.0.2/32",
		},
		Dropbear: DBConfig{
			Port: 22,
		},
	}
}

// Load reads and parses the config file at path, filling defaults for unset fields.
func Load(path string) (*Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load config %s: %w", path, err)
	}
	if err := parseTOML(data, cfg); err != nil {
		return nil, fmt.Errorf("load config %s: %w", path, err)
	}
	return cfg, nil
}

// Validate returns an error if required fields are missing or invalid.
func (c *Config) Validate() error {
	for _, check := range []func(*Config) error{
		validateHost,
		validateSSH,
		validateWireGuard,
		validateDropbear,
		validateLUKS,
	} {
		if err := check(c); err != nil {
			return err
		}
	}
	return nil
}

func validateHost(c *Config) error {
	if c.Host == "" {
		return fmt.Errorf("host is required")
	}
	return nil
}

func validateSSH(c *Config) error {
	if c.SSH.User == "" {
		return fmt.Errorf("ssh.user is required")
	}
	return validatePort("ssh.port", c.SSH.Port)
}

func validateWireGuard(c *Config) error {
	if err := validatePort("wireguard.port", c.WireGuard.Port); err != nil {
		return err
	}
	if _, _, err := net.ParseCIDR(c.WireGuard.ServerIP); err != nil {
		return fmt.Errorf("wireguard.server_ip invalid CIDR: %w", err)
	}
	if _, _, err := net.ParseCIDR(c.WireGuard.ClientIP); err != nil {
		return fmt.Errorf("wireguard.client_ip invalid CIDR: %w", err)
	}
	return validateTunnelTopology(c)
}

// validateTunnelTopology rejects WireGuard configs whose server and client
// tunnel IPs collide or whose client IP falls outside the server tunnel network
// — either is a misconfiguration that yields an unreachable Dropbear.
func validateTunnelTopology(c *Config) error {
	serverIP, serverNet, err := net.ParseCIDR(c.WireGuard.ServerIP)
	if err != nil {
		return fmt.Errorf("wireguard.server_ip invalid CIDR: %w", err)
	}
	clientIP, _, err := net.ParseCIDR(c.WireGuard.ClientIP)
	if err != nil {
		return fmt.Errorf("wireguard.client_ip invalid CIDR: %w", err)
	}
	if serverIP.Equal(clientIP) {
		return fmt.Errorf("wireguard.server_ip and wireguard.client_ip must be different addresses")
	}
	if !serverNet.Contains(clientIP) {
		return fmt.Errorf("wireguard.client_ip %s is not within the server tunnel network %s", clientIP, serverNet)
	}
	return nil
}

func validateDropbear(c *Config) error {
	return validatePort("dropbear.port", c.Dropbear.Port)
}

// luksDevicePattern matches an absolute /dev path made only of characters that
// are safe to embed in a shell command. luks.device is interpolated into the
// remote `cryptsetup luksChangeKey` command; restricting it here prevents shell
// metacharacters ($()/backticks/spaces/quotes) from being smuggled in.
var luksDevicePattern = regexp.MustCompile(`^/dev/[A-Za-z0-9/_.:=-]+$`)

// validateLUKS checks that luks.device, when set, is a plausible and shell-safe
// /dev path. An empty device is valid (it is auto-detected from /etc/crypttab).
func validateLUKS(c *Config) error {
	if c.LUKS.Device == "" {
		return nil
	}
	if !luksDevicePattern.MatchString(c.LUKS.Device) {
		return fmt.Errorf("luks.device %q must be an absolute /dev path using only letters, digits, and /._:=-", c.LUKS.Device)
	}
	return nil
}

// validatePort checks that port is within the valid 1–65535 range.
func validatePort(name string, port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("%s must be 1–65535", name)
	}
	return nil
}

// OutputDir returns the configured output directory, defaulting to ./ubo-<host>.
// Colons and brackets are stripped from the host so IPv6 addresses produce a
// valid directory name (e.g. "[::1]" → "ubo---1").
func (c *Config) OutputDir() string {
	if c.Output.Dir != "" {
		return c.Output.Dir
	}
	host := strings.NewReplacer(":", "-", "[", "", "]", "").Replace(c.Host)
	return "ubo-" + host
}

// WGServerTunnelIP returns the IP portion of wireguard.server_ip (without prefix).
func (c *Config) WGServerTunnelIP() string {
	ip, _, _ := net.ParseCIDR(c.WireGuard.ServerIP)
	if ip == nil {
		return ""
	}
	return ip.String()
}

// WGClientTunnelIP returns the IP portion of wireguard.client_ip (without prefix).
func (c *Config) WGClientTunnelIP() string {
	ip, _, _ := net.ParseCIDR(c.WireGuard.ClientIP)
	if ip == nil {
		return ""
	}
	return ip.String()
}

// DefaultTemplate is written by "ubo init".
const DefaultTemplate = `# UBO Configuration — Unlock Before Operation
# Edit with: ubo configure

# Remote host to configure
host = "192.168.1.100"

[ssh]
user = "root"
port = 22
key  = ""   # path to SSH private key; empty = use agent / default keys
sudo = false   # true = run remote setup via passwordless sudo (for non-root sudo-group users)

[wireguard]
port      = 51820
server_ip = "10.42.0.1/24"   # server WireGuard tunnel IP (CIDR)
client_ip = "10.42.0.2/32"   # client WireGuard tunnel IP (CIDR)

[dropbear]
port = 22

[output]
dir = ""   # empty = auto: ./ubo-<host>/

[network]
# Leave empty to auto-detect from the remote system's routing table
interface = ""
ip        = ""   # static IP/CIDR for initramfs (e.g. "192.168.1.100/24")

[luks]
device = ""   # LUKS block device (e.g. "/dev/sda3"); auto-detected from /etc/crypttab if empty
`
