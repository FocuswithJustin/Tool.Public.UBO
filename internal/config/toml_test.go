package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseTOML_allFields(t *testing.T) {
	src := `
host = "1.2.3.4"
[ssh]
user = "bob"
port = 2200
key = "/home/bob/.ssh/id_ed25519"
[wireguard]
port = 51000
server_ip = "10.1.0.1/24"
client_ip = "10.1.0.2/32"
[dropbear]
port = 23
[output]
dir = "/var/ubo"
[network]
interface = "eth0"
ip = "192.168.0.5/24"
[luks]
device = "/dev/sda3"
`
	cfg := Default()
	if err := parseTOML([]byte(src), cfg); err != nil {
		t.Fatalf("parseTOML: %v", err)
	}
	if cfg.Host != "1.2.3.4" || cfg.SSH.User != "bob" || cfg.SSH.Port != 2200 ||
		cfg.SSH.Key != "/home/bob/.ssh/id_ed25519" || cfg.WireGuard.Port != 51000 ||
		cfg.WireGuard.ServerIP != "10.1.0.1/24" || cfg.WireGuard.ClientIP != "10.1.0.2/32" ||
		cfg.Dropbear.Port != 23 || cfg.Output.Dir != "/var/ubo" ||
		cfg.Network.Interface != "eth0" || cfg.Network.IP != "192.168.0.5/24" ||
		cfg.LUKS.Device != "/dev/sda3" {
		t.Errorf("unexpected parse result: %+v", cfg)
	}
}

func TestParseTOML_commentsAndBlanks(t *testing.T) {
	src := "# a comment\n   # indented comment\n\nhost = \"h\" # trailing\n"
	cfg := Default()
	if err := parseTOML([]byte(src), cfg); err != nil {
		t.Fatalf("parseTOML: %v", err)
	}
	if cfg.Host != "h" {
		t.Errorf("Host = %q; want h", cfg.Host)
	}
}

func TestParseTOML_escapes(t *testing.T) {
	cfg := Default()
	if err := parseTOML([]byte(`host = "a\"b\\c"`), cfg); err != nil {
		t.Fatalf("parseTOML: %v", err)
	}
	if cfg.Host != `a"b\c` {
		t.Errorf("Host = %q; want a\"b\\c", cfg.Host)
	}
}

func TestParseTOML_hashInString(t *testing.T) {
	cfg := Default()
	if err := parseTOML([]byte(`host = "a#b"`), cfg); err != nil {
		t.Fatalf("parseTOML: %v", err)
	}
	if cfg.Host != "a#b" {
		t.Errorf("Host = %q; want a#b", cfg.Host)
	}
}

func TestParseTOML_negativeInt(t *testing.T) {
	cfg := Default()
	if err := parseTOML([]byte("[ssh]\nport = -7"), cfg); err != nil {
		t.Fatalf("parseTOML: %v", err)
	}
	if cfg.SSH.Port != -7 {
		t.Errorf("SSH.Port = %d; want -7", cfg.SSH.Port)
	}
}

func TestParseTOML_errors(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"bad section no close", "[ssh"},
		{"bad section empty", "[]"},
		{"bad section nested bracket", "[a[b]]"},
		{"missing equals", "hostvalue"},
		{"empty key", "= \"x\""},
		{"key with space", "ssh port = 22"},
		{"unterminated string", `host = "abc`},
		{"unterminated escape", `host = "abc\`},
		{"invalid escape", `host = "a\nb"`},
		{"missing value", "host ="},
		{"missing value comment only", "host = # nope"},
		{"non-int for int", `[ssh]
port = "nope"`},
		{"string for int via bare", "[ssh]\nport = abc"},
		{"int for string", "host = 5"},
		{"trailing junk after string", `host = "x" y`},
		{"unknown section", "[bogus]\nx = 1"},
		{"unknown top key", "nope = \"x\""},
		{"unknown ssh key", "[ssh]\nbogus = 1"},
		{"unknown wireguard key", "[wireguard]\nbogus = 1"},
		{"unknown dropbear key", "[dropbear]\nbogus = 1"},
		{"unknown output key", "[output]\nbogus = 1"},
		{"unknown network key", "[network]\nbogus = 1"},
		{"unknown luks key", "[luks]\nbogus = 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			if err := parseTOML([]byte(tc.src), cfg); err == nil {
				t.Errorf("expected error for %q", tc.src)
			}
		})
	}
}

func TestParseTOML_typeMismatchPerField(t *testing.T) {
	// Hit the type-check error return for every field so each branch is covered.
	cases := []string{
		// strings given an integer
		"host = 1",
		"[ssh]\nuser = 1",
		"[ssh]\nkey = 1",
		"[wireguard]\nserver_ip = 1",
		"[wireguard]\nclient_ip = 1",
		"[output]\ndir = 1",
		"[network]\ninterface = 1",
		"[network]\nip = 1",
		"[luks]\ndevice = 1",
		// integers given a string
		"[ssh]\nport = \"x\"",
		"[wireguard]\nport = \"x\"",
		"[dropbear]\nport = \"x\"",
	}
	for _, src := range cases {
		t.Run(src, func(t *testing.T) {
			cfg := Default()
			if err := parseTOML([]byte(src), cfg); err == nil {
				t.Errorf("expected type error for %q", src)
			}
		})
	}
}

func TestParseTOML_assignAllStrings(t *testing.T) {
	// Exercise the success assignment path of every string field individually.
	cases := map[string]func(*Config) string{
		"[ssh]\nkey = \"k\"":             func(c *Config) string { return c.SSH.Key },
		"[output]\ndir = \"d\"":          func(c *Config) string { return c.Output.Dir },
		"[network]\ninterface = \"eth\"": func(c *Config) string { return c.Network.Interface },
		"[network]\nip = \"1.1.1.1/8\"":  func(c *Config) string { return c.Network.IP },
		"[luks]\ndevice = \"/dev/x\"":    func(c *Config) string { return c.LUKS.Device },
	}
	for src, get := range cases {
		cfg := Default()
		if err := parseTOML([]byte(src), cfg); err != nil {
			t.Fatalf("%q: %v", src, err)
		}
		if get(cfg) == "" {
			t.Errorf("%q: field not assigned", src)
		}
	}
}

func TestParseTOML_keyHash(t *testing.T) {
	// A '#' inside the key portion is invalid.
	cfg := Default()
	if err := parseTOML([]byte("ho#st = \"x\""), cfg); err == nil {
		t.Error("expected error for '#' in key")
	}
}

func TestMarshal_roundTrip(t *testing.T) {
	orig := &Config{
		Host: `host"with\stuff`,
		SSH:  SSHConfig{User: "u", Port: 2222, Key: "/k"},
		WireGuard: WGConfig{
			Port:     51820,
			ServerIP: "10.42.0.1/24",
			ClientIP: "10.42.0.2/32",
		},
		Dropbear: DBConfig{Port: 22},
		Output:   OutConfig{Dir: "/out"},
		Network:  NetConfig{Interface: "eth0", IP: "1.2.3.4/24"},
		LUKS:     LUKSConfig{Device: "/dev/sda3"},
	}
	data, err := Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := Default()
	if err := parseTOML(data, got); err != nil {
		t.Fatalf("re-parse: %v\n%s", err, data)
	}
	if *got != *orig {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, orig)
	}
}

func TestSave_roundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ubo.toml")
	orig := Default()
	orig.Host = "192.168.1.100"
	orig.LUKS.Device = "/dev/sda3"

	if err := Save(orig, path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("mode = %o; want 0644", info.Mode().Perm())
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if *loaded != *orig {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", loaded, orig)
	}
}

func TestSave_badDir(t *testing.T) {
	err := Save(Default(), filepath.Join(t.TempDir(), "no-such-dir", "ubo.toml"))
	if err == nil {
		t.Error("expected error saving into nonexistent directory")
	}
}

func TestSave_seamErrors(t *testing.T) {
	boom := errors.New("boom")
	dir := t.TempDir()
	path := filepath.Join(dir, "ubo.toml")

	restore := func() {
		marshalFunc = Marshal
		createTemp = os.CreateTemp
		writeFile = (*os.File).Write
		chmodFile = (*os.File).Chmod
		closeFile = (*os.File).Close
		renameFile = os.Rename
		removeFile = os.Remove
	}

	t.Run("marshal error", func(t *testing.T) {
		defer restore()
		marshalFunc = func(*Config) ([]byte, error) { return nil, boom }
		if err := Save(Default(), path); !errors.Is(err, boom) {
			t.Errorf("err = %v; want boom", err)
		}
	})

	t.Run("createTemp error", func(t *testing.T) {
		defer restore()
		createTemp = func(string, string) (*os.File, error) { return nil, boom }
		if err := Save(Default(), path); !errors.Is(err, boom) {
			t.Errorf("err = %v; want boom", err)
		}
	})

	t.Run("write error", func(t *testing.T) {
		defer restore()
		writeFile = func(*os.File, []byte) (int, error) { return 0, boom }
		if err := Save(Default(), path); !errors.Is(err, boom) {
			t.Errorf("err = %v; want boom", err)
		}
	})

	t.Run("chmod error", func(t *testing.T) {
		defer restore()
		chmodFile = func(*os.File, os.FileMode) error { return boom }
		if err := Save(Default(), path); !errors.Is(err, boom) {
			t.Errorf("err = %v; want boom", err)
		}
	})

	t.Run("close error", func(t *testing.T) {
		defer restore()
		closeFile = func(*os.File) error { return boom }
		if err := Save(Default(), path); !errors.Is(err, boom) {
			t.Errorf("err = %v; want boom", err)
		}
	})

	t.Run("rename error", func(t *testing.T) {
		defer restore()
		renameFile = func(string, string) error { return boom }
		if err := Save(Default(), path); !errors.Is(err, boom) {
			t.Errorf("err = %v; want boom", err)
		}
	})
}

func TestMarshal_quotesContainHash(t *testing.T) {
	// Ensure a quoted value containing '#' survives the round-trip and is not
	// truncated as a comment.
	c := Default()
	c.Host = "a#b#c"
	data, _ := Marshal(c)
	if !strings.Contains(string(data), `"a#b#c"`) {
		t.Errorf("marshal dropped hash: %s", data)
	}
	got := Default()
	if err := parseTOML(data, got); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if got.Host != "a#b#c" {
		t.Errorf("Host = %q; want a#b#c", got.Host)
	}
}
