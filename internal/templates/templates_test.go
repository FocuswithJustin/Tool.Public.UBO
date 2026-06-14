package templates

import (
	"bytes"
	"strings"
	"testing"
	"text/template"
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
	// `wg setconf` rejects the wg-quick-only Address key, so the server config
	// (consumed by setconf in initramfs) must not contain it.
	if strings.Contains(ini, "Address") {
		t.Errorf("server MarshalINI must not contain Address (wg setconf rejects it)\ngot:\n%s", ini)
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
		name   string
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

// validScriptData returns a fully-populated InitramfsScriptData for tests.
func validScriptData() InitramfsScriptData {
	return InitramfsScriptData{
		ServerIP:  "10.42.0.1/24",
		GatewayIP: "192.168.1.1",
		Interface: "eth0",
	}
}

func TestRenderInitramfsScript(t *testing.T) {
	got, err := RenderInitramfsScript(validScriptData())
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

func TestRenderInitramfsScript_invalidCIDR(t *testing.T) {
	d := validScriptData()
	d.ServerIP = "not-a-cidr"
	_, err := RenderInitramfsScript(d)
	if err == nil || !strings.Contains(err.Error(), "not a valid CIDR") {
		t.Errorf("expected CIDR error, got %v", err)
	}
}

func TestRenderInitramfsScript_missingGateway(t *testing.T) {
	d := validScriptData()
	d.GatewayIP = ""
	if _, err := RenderInitramfsScript(d); err == nil || !strings.Contains(err.Error(), "GatewayIP is required") {
		t.Errorf("expected GatewayIP error, got %v", err)
	}
}

func TestRenderInitramfsScript_invalidGateway(t *testing.T) {
	d := validScriptData()
	d.GatewayIP = "not-an-ip"
	if _, err := RenderInitramfsScript(d); err == nil || !strings.Contains(err.Error(), "not a valid IP") {
		t.Errorf("expected invalid gateway error, got %v", err)
	}
}

func TestRenderInitramfsScript_missingInterface(t *testing.T) {
	d := validScriptData()
	d.Interface = ""
	if _, err := RenderInitramfsScript(d); err == nil || !strings.Contains(err.Error(), "Interface is required") {
		t.Errorf("expected Interface error, got %v", err)
	}
}

func TestRenderInitramfsScript_onlinkFallback(t *testing.T) {
	got, err := RenderInitramfsScript(validScriptData())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "ip route add 192.168.1.1/32 dev eth0 onlink") {
		t.Errorf("missing onlink host route, got:\n%s", got)
	}
	if !strings.Contains(got, "ip route add default via 192.168.1.1") {
		t.Errorf("missing default route via gateway, got:\n%s", got)
	}
}

func TestRenderInitramfsScript_setE(t *testing.T) {
	got, err := RenderInitramfsScript(validScriptData())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "set -e") {
		t.Errorf("script missing 'set -e' (M2 fail-closed): %s", got)
	}
}

func TestRenderInitramfsScript_noAndBreak(t *testing.T) {
	// The route-wait loop must use `if ... fi; break` so grep's non-zero exit
	// (route not yet present) does not trigger set -e (audit M1/M2).
	got, err := RenderInitramfsScript(validScriptData())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(got, "&& break") {
		t.Error("script must not use '&& break' in route-wait loop (breaks under set -e)")
	}
	if !strings.Contains(got, "if ip route") {
		t.Error("script should use 'if ip route ...' pattern for route-wait loop")
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
	if !strings.Contains(InitramfsHookTmpl, "copy_exec /usr/sbin/mdadm") {
		t.Error("hook missing copy_exec for mdadm (needed for LUKS-on-RAID)")
	}
	if !strings.Contains(InitramfsHookTmpl, "manual_add_modules md_mod raid1") {
		t.Error("hook missing manual_add_modules for RAID modules")
	}
	if !strings.HasPrefix(InitramfsHookTmpl, "#!/bin/sh") {
		t.Error("hook should start with #!/bin/sh")
	}
}

// ── Exact-output assertions (strengthen branch independence) ──────────────────

func TestWireGuardServerConfig_MarshalINI_exactOutput(t *testing.T) {
	cfg := WireGuardServerConfig{
		Address:        "10.42.0.1/24",
		PrivateKey:     "serverPrivKey==",
		ListenPort:     51820,
		PeerPublicKey:  "clientPubKey==",
		PeerAllowedIPs: "10.42.0.2/32",
	}
	got, err := cfg.MarshalINI()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "[Interface]\n" +
		"PrivateKey = serverPrivKey==\n" +
		"ListenPort = 51820\n" +
		"\n[Peer]\n" +
		"PublicKey = clientPubKey==\n" +
		"AllowedIPs = 10.42.0.2/32\n" +
		"PersistentKeepalive = 25\n"
	if got != want {
		t.Errorf("MarshalINI output mismatch\n got:\n%q\nwant:\n%q", got, want)
	}
}

func TestWireGuardClientConfig_MarshalINI_exactOutput(t *testing.T) {
	cfg := WireGuardClientConfig{
		PrivateKey:      "clientPrivKey==",
		Address:         "10.42.0.2/32",
		ServerPublicKey: "serverPubKey==",
		ServerEndpoint:  "1.2.3.4:51820",
		AllowedIPs:      "10.42.0.1/32",
	}
	got, err := cfg.MarshalINI()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "[Interface]\n" +
		"PrivateKey = clientPrivKey==\n" +
		"Address = 10.42.0.2/32\n" +
		"\n[Peer]\n" +
		"PublicKey = serverPubKey==\n" +
		"Endpoint = 1.2.3.4:51820\n" +
		"AllowedIPs = 10.42.0.1/32\n" +
		"PersistentKeepalive = 25\n"
	if got != want {
		t.Errorf("MarshalINI output mismatch\n got:\n%q\nwant:\n%q", got, want)
	}
}

// ── Error-message assertions for each validation branch ───────────────────────
// These pin each guard clause to its own field so the branches are exercised
// independently (MC/DC spirit), not just "some error occurred".

func TestWireGuardServerConfig_MarshalINI_errorMessages(t *testing.T) {
	cases := []struct {
		name string
		cfg  WireGuardServerConfig
		want string
	}{
		{"no Address", WireGuardServerConfig{PrivateKey: "k", ListenPort: 1, PeerPublicKey: "p", PeerAllowedIPs: "0.0.0.0/0"}, "Address is required"},
		{"no PrivateKey", WireGuardServerConfig{Address: "1.1.1.1/32", ListenPort: 1, PeerPublicKey: "p", PeerAllowedIPs: "0.0.0.0/0"}, "PrivateKey is required"},
		{"no ListenPort", WireGuardServerConfig{Address: "1.1.1.1/32", PrivateKey: "k", PeerPublicKey: "p", PeerAllowedIPs: "0.0.0.0/0"}, "ListenPort is required"},
		{"no PeerPublicKey", WireGuardServerConfig{Address: "1.1.1.1/32", PrivateKey: "k", ListenPort: 1, PeerAllowedIPs: "0.0.0.0/0"}, "PeerPublicKey is required"},
		{"no PeerAllowedIPs", WireGuardServerConfig{Address: "1.1.1.1/32", PrivateKey: "k", ListenPort: 1, PeerPublicKey: "p"}, "PeerAllowedIPs is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := tc.cfg.MarshalINI()
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			if s != "" {
				t.Errorf("expected empty string on error, got %q", s)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
}

func TestWireGuardClientConfig_MarshalINI_errorMessages(t *testing.T) {
	base := WireGuardClientConfig{
		PrivateKey: "k", Address: "1.1.1.1/32",
		ServerPublicKey: "p", ServerEndpoint: "h:1", AllowedIPs: "0.0.0.0/0",
	}
	cases := []struct {
		name   string
		mutate func(*WireGuardClientConfig)
		want   string
	}{
		{"no PrivateKey", func(c *WireGuardClientConfig) { c.PrivateKey = "" }, "PrivateKey is required"},
		{"no Address", func(c *WireGuardClientConfig) { c.Address = "" }, "Address is required"},
		{"no ServerPublicKey", func(c *WireGuardClientConfig) { c.ServerPublicKey = "" }, "ServerPublicKey is required"},
		{"no ServerEndpoint", func(c *WireGuardClientConfig) { c.ServerEndpoint = "" }, "ServerEndpoint is required"},
		{"no AllowedIPs", func(c *WireGuardClientConfig) { c.AllowedIPs = "" }, "AllowedIPs is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			s, err := cfg.MarshalINI()
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			if s != "" {
				t.Errorf("expected empty string on error, got %q", s)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
}

// ── Render error-branch independence ──────────────────────────────────────────

// RenderDropbearConfig has two independent validation guards. Verify each one
// fires on its own, with the other field populated.
func TestRenderDropbearConfig_errorMessages(t *testing.T) {
	if _, err := RenderDropbearConfig(DropbearConfigData{DropbearPort: 22}); err == nil ||
		!strings.Contains(err.Error(), "ServerTunnelIP is required") {
		t.Errorf("expected ServerTunnelIP error, got %v", err)
	}
	if _, err := RenderDropbearConfig(DropbearConfigData{ServerTunnelIP: "10.42.0.1"}); err == nil ||
		!strings.Contains(err.Error(), "DropbearPort is required") {
		t.Errorf("expected DropbearPort error, got %v", err)
	}
}

func TestRenderInitramfsScript_errorMessage(t *testing.T) {
	_, err := RenderInitramfsScript(InitramfsScriptData{})
	if err == nil || !strings.Contains(err.Error(), "ServerIP is required") {
		t.Errorf("expected ServerIP error, got %v", err)
	}
}

// ── RenderReadme: render with empty data succeeds (no validation guards) ──────

func TestRenderReadme_emptyData(t *testing.T) {
	got, err := RenderReadme(ReadmeTmplData{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Even with zero values the template must render its static prose.
	if !strings.Contains(got, "Remote LUKS Unlock Instructions") {
		t.Errorf("missing header in README, got:\n%s", got)
	}
	// Zero int renders as "0".
	if !strings.Contains(got, "-p 0 root@") {
		t.Errorf("expected zero DropbearPort to render as 0, got:\n%s", got)
	}
}

// ── Documentation: Parse/Execute error branches are unreachable ───────────────
//
// Each Render* function contains two error-return branches that the public API
// cannot trigger with the fixed package-level const templates:
//
//   1. template.Parse(<const>) — the templates are compile-time string
//      constants and are syntactically valid, so Parse never returns an error.
//   2. tmpl.Execute(&buf, <struct>) — Execute only errors on a failing method/
//      function call or (with Option("missingkey=error")) a missing map key.
//      These templates perform plain field access on concrete value structs and
//      register no functions, so Execute never returns an error.
//
// The two tests below lock in those invariants. They re-run Parse and Execute on
// the exact const templates to prove the success paths used by the Render
// functions hold; the error branches themselves remain (intentionally)
// unreachable dead-defensive code and are therefore documented, not forced.

func TestConstTemplates_ParseAndExecuteNeverError(t *testing.T) {
	cases := []struct {
		name string
		tmpl string
		data interface{}
	}{
		{"InitramfsScriptTmpl", InitramfsScriptTmpl, validScriptData()},
		{"DropbearConfigTmpl", DropbearConfigTmpl, DropbearConfigData{ServerTunnelIP: "10.42.0.1", DropbearPort: 22}},
		{"ReadmeTmpl", ReadmeTmpl, ReadmeTmplData{ServerTunnelIP: "10.42.0.1", DropbearPort: 22, ConfigPath: "ubo.toml"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := template.New(tc.name).Parse(tc.tmpl)
			if err != nil {
				t.Fatalf("const template %s failed to parse (should be impossible): %v", tc.name, err)
			}
			var buf bytes.Buffer
			if err := parsed.Execute(&buf, tc.data); err != nil {
				t.Fatalf("const template %s failed to execute (should be impossible): %v", tc.name, err)
			}
			if buf.Len() == 0 {
				t.Errorf("const template %s produced no output", tc.name)
			}
		})
	}
}
