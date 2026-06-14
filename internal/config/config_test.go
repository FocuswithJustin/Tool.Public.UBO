package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDefault(t *testing.T) {
	c := Default()
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"SSH.User", c.SSH.User, "root"},
		{"SSH.Port", strconv.Itoa(c.SSH.Port), "22"},
		{"WireGuard.Port", strconv.Itoa(c.WireGuard.Port), "51820"},
		{"WireGuard.ServerIP", c.WireGuard.ServerIP, "10.42.0.1/24"},
		{"WireGuard.ClientIP", c.WireGuard.ClientIP, "10.42.0.2/32"},
		{"Dropbear.Port", strconv.Itoa(c.Dropbear.Port), "22"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %q; want %q", tc.name, tc.got, tc.want)
		}
	}
}

func TestValidate_valid(t *testing.T) {
	c := Default()
	c.Host = "192.168.1.100"
	if err := c.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_missingHost(t *testing.T) {
	c := Default()
	c.Host = ""
	if err := c.Validate(); err == nil {
		t.Error("expected error for missing host")
	}
}

func TestValidate_badSSHPort(t *testing.T) {
	c := Default()
	c.Host = "host"
	c.SSH.Port = 0
	if err := c.Validate(); err == nil {
		t.Error("expected error for port 0")
	}
	c.SSH.Port = 99999
	if err := c.Validate(); err == nil {
		t.Error("expected error for port > 65535")
	}
}

func TestValidate_badWGIP(t *testing.T) {
	c := Default()
	c.Host = "host"
	c.WireGuard.ServerIP = "not-a-cidr"
	if err := c.Validate(); err == nil {
		t.Error("expected error for invalid server CIDR")
	}

	c2 := Default()
	c2.Host = "host"
	c2.WireGuard.ClientIP = "10.0.0.999/32"
	if err := c2.Validate(); err == nil {
		t.Error("expected error for invalid client CIDR")
	}
}

func TestValidate_emptySSHUser(t *testing.T) {
	c := Default()
	c.Host = "host"
	c.SSH.User = ""
	if err := c.Validate(); err == nil {
		t.Error("expected error for empty ssh.user")
	}
}

// TestValidate_table exercises each boolean sub-condition of every Validate
// decision independently (MC/DC spirit). For each port range check
// (port <= 0 || port > 65535) we provide a low value that trips only the
// first operand, a high value that trips only the second operand, and the
// valid boundary values (1 and 65535) where neither operand is true.
func TestValidate_table(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"valid baseline", func(c *Config) {}, false},
		{"missing host", func(c *Config) { c.Host = "" }, true},
		{"empty ssh.user", func(c *Config) { c.SSH.User = "" }, true},

		// ssh.port: first operand (<= 0)
		{"ssh.port zero", func(c *Config) { c.SSH.Port = 0 }, true},
		{"ssh.port negative", func(c *Config) { c.SSH.Port = -1 }, true},
		// ssh.port: second operand (> 65535)
		{"ssh.port too high", func(c *Config) { c.SSH.Port = 65536 }, true},
		// ssh.port: valid boundaries (neither operand true)
		{"ssh.port low boundary", func(c *Config) { c.SSH.Port = 1 }, false},
		{"ssh.port high boundary", func(c *Config) { c.SSH.Port = 65535 }, false},

		// wireguard.port: first operand (<= 0)
		{"wg.port zero", func(c *Config) { c.WireGuard.Port = 0 }, true},
		{"wg.port negative", func(c *Config) { c.WireGuard.Port = -5 }, true},
		// wireguard.port: second operand (> 65535)
		{"wg.port too high", func(c *Config) { c.WireGuard.Port = 70000 }, true},
		// wireguard.port: valid boundaries
		{"wg.port low boundary", func(c *Config) { c.WireGuard.Port = 1 }, false},
		{"wg.port high boundary", func(c *Config) { c.WireGuard.Port = 65535 }, false},

		// server CIDR
		{"server CIDR invalid", func(c *Config) { c.WireGuard.ServerIP = "not-a-cidr" }, true},
		{"server CIDR empty", func(c *Config) { c.WireGuard.ServerIP = "" }, true},

		// client CIDR
		{"client CIDR invalid", func(c *Config) { c.WireGuard.ClientIP = "10.0.0.999/32" }, true},
		{"client CIDR empty", func(c *Config) { c.WireGuard.ClientIP = "" }, true},

		// dropbear.port: first operand (<= 0)
		{"dropbear.port zero", func(c *Config) { c.Dropbear.Port = 0 }, true},
		{"dropbear.port negative", func(c *Config) { c.Dropbear.Port = -1 }, true},
		// dropbear.port: second operand (> 65535)
		{"dropbear.port too high", func(c *Config) { c.Dropbear.Port = 65536 }, true},
		// dropbear.port: valid boundaries
		{"dropbear.port low boundary", func(c *Config) { c.Dropbear.Port = 1 }, false},
		{"dropbear.port high boundary", func(c *Config) { c.Dropbear.Port = 65535 }, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Default()
			c.Host = "192.168.1.100"
			tt.mutate(c)
			err := c.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("Validate() = nil; want error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Validate() = %v; want nil", err)
			}
		})
	}
}

func TestOutputDir_auto(t *testing.T) {
	c := Default()
	c.Host = "192.168.1.1"
	if got := c.OutputDir(); got != "ubo-192.168.1.1" {
		t.Errorf("OutputDir() = %q; want ubo-192.168.1.1", got)
	}
}

func TestOutputDir_explicit(t *testing.T) {
	c := Default()
	c.Host = "host"
	c.Output.Dir = "/tmp/myoutput"
	if got := c.OutputDir(); got != "/tmp/myoutput" {
		t.Errorf("OutputDir() = %q; want /tmp/myoutput", got)
	}
}

func TestWGServerTunnelIP(t *testing.T) {
	c := Default()
	c.WireGuard.ServerIP = "10.42.0.1/24"
	if got := c.WGServerTunnelIP(); got != "10.42.0.1" {
		t.Errorf("WGServerTunnelIP() = %q; want 10.42.0.1", got)
	}
}

func TestWGClientTunnelIP(t *testing.T) {
	c := Default()
	c.WireGuard.ClientIP = "10.42.0.2/32"
	if got := c.WGClientTunnelIP(); got != "10.42.0.2" {
		t.Errorf("WGClientTunnelIP() = %q; want 10.42.0.2", got)
	}
}

func TestWGServerTunnelIP_invalid(t *testing.T) {
	// Invalid/empty CIDR -> ParseCIDR yields nil ip -> empty string.
	for _, in := range []string{"", "garbage", "10.0.0.1"} {
		c := Default()
		c.WireGuard.ServerIP = in
		if got := c.WGServerTunnelIP(); got != "" {
			t.Errorf("WGServerTunnelIP(%q) = %q; want empty", in, got)
		}
	}
}

func TestWGClientTunnelIP_invalid(t *testing.T) {
	for _, in := range []string{"", "garbage", "10.0.0.2"} {
		c := Default()
		c.WireGuard.ClientIP = in
		if got := c.WGClientTunnelIP(); got != "" {
			t.Errorf("WGClientTunnelIP(%q) = %q; want empty", in, got)
		}
	}
}

func TestLoad_malformedTOML(t *testing.T) {
	// Syntactically invalid TOML should exercise the DecodeFile error path
	// (distinct from the missing-file case).
	f, err := os.CreateTemp(t.TempDir(), "*.toml")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("this is = = not valid toml [[[")
	f.Close()

	if _, err := Load(f.Name()); err == nil {
		t.Error("expected error loading malformed TOML")
	}
}

func TestLoad_valid(t *testing.T) {
	toml := `
host = "10.0.0.5"
[ssh]
user = "admin"
port = 2222
[wireguard]
port = 51820
server_ip = "10.99.0.1/24"
client_ip = "10.99.0.2/32"
[dropbear]
port = 2222
`
	f, err := os.CreateTemp(t.TempDir(), "*.toml")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(toml)
	f.Close()

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Host != "10.0.0.5" {
		t.Errorf("Host = %q; want 10.0.0.5", cfg.Host)
	}
	if cfg.SSH.User != "admin" {
		t.Errorf("SSH.User = %q; want admin", cfg.SSH.User)
	}
	if cfg.SSH.Port != 2222 {
		t.Errorf("SSH.Port = %d; want 2222", cfg.SSH.Port)
	}
}

func TestLoad_missingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nonexistent.toml"))
	if err == nil {
		t.Error("expected error loading nonexistent file")
	}
}

func TestLoad_defaults_preserved(t *testing.T) {
	// A minimal config file should leave unspecified fields at their defaults
	toml := `host = "10.0.0.1"`
	f, err := os.CreateTemp(t.TempDir(), "*.toml")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(toml)
	f.Close()

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SSH.User != "root" {
		t.Errorf("SSH.User = %q; want default root", cfg.SSH.User)
	}
	if cfg.WireGuard.Port != 51820 {
		t.Errorf("WireGuard.Port = %d; want default 51820", cfg.WireGuard.Port)
	}
}

func TestDefaultTemplate_isValidTOML(t *testing.T) {
	// Ensure the template parses without errors after replacing the placeholder host
	f, err := os.CreateTemp(t.TempDir(), "*.toml")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(DefaultTemplate)
	f.Close()

	if _, err := Load(f.Name()); err != nil {
		t.Errorf("DefaultTemplate failed to parse: %v", err)
	}
}

func TestOutputDir_colonInHost(t *testing.T) {
	c := Default()
	c.Host = "[::1]"
	got := c.OutputDir()
	if strings.Contains(got, ":") {
		t.Errorf("OutputDir() = %q; should not contain colon", got)
	}
	if strings.Contains(got, "[") || strings.Contains(got, "]") {
		t.Errorf("OutputDir() = %q; should not contain brackets", got)
	}
}
