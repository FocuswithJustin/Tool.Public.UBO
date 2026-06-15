package rootless

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// wgClientConfig holds the fields parsed from a wg-quick client .conf file.
type wgClientConfig struct {
	PrivateKey string // base64-encoded 32-byte key
	Address    string // e.g. "10.42.0.2/32"
	PeerPubKey string // base64-encoded 32-byte key
	Endpoint   string // host:port
	AllowedIPs string // e.g. "10.42.0.1/32"
}

// parseWGConfig reads a wg-quick INI config file and extracts the client fields.
// Unknown keys and comments are ignored.
func parseWGConfig(path string) (*wgClientConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open wg config: %w", err)
	}
	defer f.Close()

	cfg := &wgClientConfig{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		applyWGLine(cfg, strings.TrimSpace(sc.Text()))
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read wg config: %w", err)
	}
	return cfg, validateWGConfig(cfg)
}

// wgFieldSetters maps lowercase key names to field-setter functions.
var wgFieldSetters = map[string]func(*wgClientConfig, string){
	"privatekey": func(c *wgClientConfig, v string) { c.PrivateKey = v },
	"address":    func(c *wgClientConfig, v string) { c.Address = v },
	"publickey":  func(c *wgClientConfig, v string) { c.PeerPubKey = v },
	"endpoint":   func(c *wgClientConfig, v string) { c.Endpoint = v },
	"allowedips": func(c *wgClientConfig, v string) { c.AllowedIPs = v },
}

// applyWGLine applies a single key=value line to cfg, ignoring sections and comments.
func applyWGLine(cfg *wgClientConfig, line string) {
	if line == "" || line[0] == '#' || line[0] == '[' {
		return
	}
	k, v, ok := strings.Cut(line, "=")
	if !ok {
		return
	}
	if fn, found := wgFieldSetters[strings.TrimSpace(strings.ToLower(k))]; found {
		fn(cfg, strings.TrimSpace(v))
	}
}

// validateWGConfig returns an error if any required field is empty.
func validateWGConfig(cfg *wgClientConfig) error {
	type req struct {
		name string
		val  string
	}
	for _, r := range []req{
		{"PrivateKey", cfg.PrivateKey},
		{"Address", cfg.Address},
		{"PeerPubKey", cfg.PeerPubKey},
		{"Endpoint", cfg.Endpoint},
		{"AllowedIPs", cfg.AllowedIPs},
	} {
		if r.val == "" {
			return fmt.Errorf("wg config missing %s", r.name)
		}
	}
	return nil
}
