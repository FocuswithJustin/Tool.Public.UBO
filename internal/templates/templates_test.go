package templates

import (
	"strings"
	"testing"
)

// ── WireGuardServerConfig ─────────────────────────────────────────────────────

func TestWireGuardServerConfig_MarshalINI_valid(t *testing.T) {
	cfg := WireGuardServerConfig{
		Address:        "10.42.0.1/24",
		PrivateKey:     "serverPrivKey==",
		ListenPort:     51820,
		PeerPublicKey:  "clientPubKey==",
		PeerAllowedIPs: "10.42.0.2/32",
	}
	ini, err := cfg.MarshalINI()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"[Interface]",
		"Address = 10.42.0.1/24",
		"PrivateKey = serverPrivKey==",
		"ListenPort = 51820",
		"[Peer]",
		"PublicKey = clientPubKey==",
		"AllowedIPs = 10.42.0.2/32",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(ini, want) {
			t.Errorf("MarshalINI missing %q\ngot:\n%s", want, ini)
		}
	}
}

func TestWireGuardServerConfig_MarshalINI_missingFields(t *testing.T) {
	cases := []struct {
		name string
		cfg  WireGuardServerConfig
	}{
		{"no Address", WireGuardServerConfig{PrivateKey: "k", ListenPort: 1, PeerPublicKey: "p", PeerAllowedIPs: "0.0.0.0/0"}},
		{"no PrivateKey", WireGuardServerConfig{Address: "1.1.1.1/32", ListenPort: 1, PeerPublicKey: "p", PeerAllowedIPs: "0.0.0.0/0"}},
		{"no ListenPort", WireGuardServerConfig{Address: "1.1.1.1/32", PrivateKey: "k", PeerPublicKey: "p", PeerAllowedIPs: "0.0.0.0/0"}},
		{"no PeerPublicKey", WireGuardServerConfig{Address: "1.1.1.1/32", PrivateKey: "k", ListenPort: 1, PeerAllowedIPs: "0.0.0.0/0"}},
		{"no PeerAllowedIPs", WireGuardServerConfig{Address: "1.1.1.1/32", PrivateKey: "k", ListenPort: 1, PeerPublicKey: "p"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.cfg.MarshalINI(); err == nil {
				t.Error("expected error for missing field")
			}
		})
	}
}

// ── WireGuardClientConfig ─────────────────────────────────────────────────────

func TestWireGuardClientConfig_MarshalINI_valid(t *testing.T) {
	cfg := WireGuardClientConfig{
		PrivateKey:      "clientPrivKey==",
		Address:         "10.42.0.2/32",
		ServerPublicKey: "serverPubKey==",
		ServerEndpoint:  "1.2.3.4:51820",
		AllowedIPs:      "10.42.0.1/32",
	}
	ini, err := cfg.MarshalINI()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"[Interface]",
		"PrivateKey = clientPrivKey==",
		"Address = 10.42.0.2/32",
		"[Peer]",
		"PublicKey = serverPubKey==",
		"Endpoint = 1.2.3.4:51820",
		"AllowedIPs = 10.42.0.1/32",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(ini, want) {
			t.Errorf("MarshalINI missing %q\ngot:\n%s", want, ini)
		}
	}
}

func TestWireGuardClientConfig_MarshalINI_missingFields(t *testing.T) {
	base := WireGuardClientConfig{
		PrivateKey: "k", Address: "1.1.1.1/32",
		ServerPublicKey: "p", ServerEndpoint: "h:1", AllowedIPs: "0.0.0.0/0",
	}
	cases := []struct {
		name  string
		mutate func(*WireGuardClientConfig)
	}{
		{"no PrivateKey", func(c *WireGuardClientConfig) { c.PrivateKey = "" }},
		{"no Address", func(c *WireGuardClientConfig) { c.Address = "" }},
		{"no ServerPublicKey", func(c *WireGuardClientConfig) { c.ServerPublicKey = "" }},
		{"no ServerEndpoint", func(c *WireGuardClientConfig) { c.ServerEndpoint = "" }},
		{"no AllowedIPs", func(c *WireGuardClientConfig) { c.AllowedIPs = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			if _, err := cfg.MarshalINI(); err == nil {
				t.Error("expected error for missing field")
			}
		})
	}
}

// ── RenderInitramfsScript ─────────────────────────────────────────────────────

func TestRenderInitramfsScript(t *testing.T) {
	got, err := RenderInitramfsScript(InitramfsScriptData{ServerIP: "10.42.0.1/24"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "ip addr add 10.42.0.1/24 dev wg0") {
		t.Errorf("missing ip addr line, got:\n%s", got)
	}
	if !strings.HasPrefix(got, "#!/bin/sh") {
		t.Errorf("script should start with #!/bin/sh, got:\n%s", got)
	}
}

func TestRenderInitramfsScript_emptyServerIP(t *testing.T) {
	if _, err := RenderInitramfsScript(InitramfsScriptData{}); err == nil {
		t.Error("expected error for empty ServerIP")
	}
}

// ── RenderDropbearConfig ──────────────────────────────────────────────────────

func TestRenderDropbearConfig(t *testing.T) {
	got, err := RenderDropbearConfig(DropbearConfigData{
		ServerTunnelIP: "10.42.0.1",
		DropbearPort:   22,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "-p 10.42.0.1:22") {
		t.Errorf("missing -p flag in config, got: %s", got)
	}
	if !strings.Contains(got, "-s") {
		t.Errorf("missing -s (no password) flag in config, got: %s", got)
	}
}

func TestRenderDropbearConfig_missingFields(t *testing.T) {
	if _, err := RenderDropbearConfig(DropbearConfigData{DropbearPort: 22}); err == nil {
		t.Error("expected error for empty ServerTunnelIP")
	}
	if _, err := RenderDropbearConfig(DropbearConfigData{ServerTunnelIP: "10.42.0.1"}); err == nil {
		t.Error("expected error for zero DropbearPort")
	}
}

// ── RenderReadme ──────────────────────────────────────────────────────────────

func TestRenderReadme(t *testing.T) {
	got, err := RenderReadme(ReadmeTmplData{
		ServerTunnelIP: "10.42.0.1",
		DropbearPort:   22,
		ConfigPath:     "ubo.toml",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "10.42.0.1") {
		t.Errorf("missing server tunnel IP in README, got:\n%s", got)
	}
	if !strings.Contains(got, "cryptroot-unlock") {
		t.Errorf("missing cryptroot-unlock in README, got:\n%s", got)
	}
	if !strings.Contains(got, "ubo.toml") {
		t.Errorf("missing config path in README, got:\n%s", got)
	}
}

// ── InitramfsHookTmpl ─────────────────────────────────────────────────────────

func TestInitramfsHookTmpl(t *testing.T) {
	if !strings.Contains(InitramfsHookTmpl, "copy_exec /usr/bin/wg") {
		t.Error("hook missing copy_exec for wg")
	}
	if !strings.Contains(InitramfsHookTmpl, "manual_add_modules wireguard") {
		t.Error("hook missing manual_add_modules wireguard")
	}
	if !strings.HasPrefix(InitramfsHookTmpl, "#!/bin/sh") {
		t.Error("hook should start with #!/bin/sh")
	}
}
