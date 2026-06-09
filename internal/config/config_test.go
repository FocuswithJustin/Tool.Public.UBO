package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefault(t *testing.T) {
	c := Default()
	if c.SSH.User != "root" {
		t.Errorf("SSH.User = %q; want root", c.SSH.User)
	}
	if c.SSH.Port != 22 {
		t.Errorf("SSH.Port = %d; want 22", c.SSH.Port)
	}
	if c.WireGuard.Port != 51820 {
		t.Errorf("WireGuard.Port = %d; want 51820", c.WireGuard.Port)
	}
	if c.WireGuard.ServerIP != "10.42.0.1/24" {
		t.Errorf("WireGuard.ServerIP = %q; want 10.42.0.1/24", c.WireGuard.ServerIP)
	}
	if c.WireGuard.ClientIP != "10.42.0.2/32" {
		t.Errorf("WireGuard.ClientIP = %q; want 10.42.0.2/32", c.WireGuard.ClientIP)
	}
	if c.Dropbear.Port != 22 {
		t.Errorf("Dropbear.Port = %d; want 22", c.Dropbear.Port)
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
