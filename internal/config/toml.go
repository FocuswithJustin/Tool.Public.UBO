package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// This file implements a minimal TOML reader and writer for the fixed ubo
// configuration schema, using only the Go standard library.
//
// Supported subset:
//   - Blank lines and lines whose first non-whitespace character is '#' are
//     ignored (comments).
//   - Section headers: "[section]" optionally surrounded by whitespace.
//   - Key/value pairs: "key = value".
//   - String values are double-quoted with the basic escapes \" and \\.
//   - Integer values are bare decimal (optionally negative).
//   - A trailing inline comment is allowed after a value: an unquoted '#'
//     preceded by whitespace begins a comment. Inside a quoted string, '#'
//     is literal.
//
// Anything else (a non-blank, non-comment line that is neither a valid section
// header nor a valid key/value pair, a wrong-typed value, an unterminated
// string, etc.) is a parse error.

// parseTOML overlays the TOML in src onto cfg, leaving fields that are not
// present in src untouched (so callers can start from Default()).
func parseTOML(src []byte, cfg *Config) error {
	section := ""
	lines := strings.Split(string(src), "\n")
	for i, raw := range lines {
		lineNo := i + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") {
			name, err := parseSectionHeader(line)
			if err != nil {
				return fmt.Errorf("line %d: %w", lineNo, err)
			}
			section = name
			continue
		}

		key, val, err := parseKeyValue(line)
		if err != nil {
			return fmt.Errorf("line %d: %w", lineNo, err)
		}
		if err := assign(cfg, section, key, val); err != nil {
			return fmt.Errorf("line %d: %w", lineNo, err)
		}
	}
	return nil
}

// parseSectionHeader parses a "[name]" header and returns the section name.
func parseSectionHeader(line string) (string, error) {
	if !strings.HasSuffix(line, "]") {
		return "", fmt.Errorf("malformed section header %q", line)
	}
	name := strings.TrimSpace(line[1 : len(line)-1])
	if name == "" || strings.ContainsAny(name, "[]") {
		return "", fmt.Errorf("malformed section header %q", line)
	}
	return name, nil
}

// parseKeyValue splits a "key = value" line and decodes the value (string or
// int), honouring trailing inline comments outside of quoted strings.
func parseKeyValue(line string) (key string, val tomlValue, err error) {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return "", tomlValue{}, fmt.Errorf("expected key = value: %q", line)
	}
	key = strings.TrimSpace(line[:eq])
	if key == "" || strings.ContainsAny(key, " \t\"[]#") {
		return "", tomlValue{}, fmt.Errorf("invalid key %q", line[:eq])
	}
	rest := strings.TrimSpace(line[eq+1:])
	val, err = parseValue(rest)
	if err != nil {
		return "", tomlValue{}, err
	}
	return key, val, nil
}

// tomlValue is a decoded scalar: either a string or an int.
type tomlValue struct {
	isInt bool
	str   string
	i     int
}

// parseValue decodes a single value plus an optional trailing comment.
func parseValue(s string) (tomlValue, error) {
	if s == "" {
		return tomlValue{}, fmt.Errorf("missing value")
	}
	if s[0] == '"' {
		str, rest, err := parseQuoted(s)
		if err != nil {
			return tomlValue{}, err
		}
		if err := ensureCommentOnly(rest); err != nil {
			return tomlValue{}, err
		}
		return tomlValue{str: str}, nil
	}

	// Bare value (integer): a trailing inline comment starts at an unquoted '#'.
	tok := s
	if h := strings.IndexByte(s, '#'); h >= 0 {
		tok = s[:h]
	}
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return tomlValue{}, fmt.Errorf("missing value")
	}
	n, err := strconv.Atoi(tok)
	if err != nil {
		return tomlValue{}, fmt.Errorf("invalid value %q (expected quoted string or integer)", tok)
	}
	return tomlValue{isInt: true, i: n}, nil
}

// parseQuoted reads a double-quoted string starting at s[0]=='"' and returns
// the decoded string and the remainder of the line after the closing quote.
func parseQuoted(s string) (string, string, error) {
	var b strings.Builder
	i := 1
	for i < len(s) {
		c := s[i]
		switch c {
		case '\\':
			if i+1 >= len(s) {
				return "", "", fmt.Errorf("unterminated string")
			}
			switch s[i+1] {
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			default:
				return "", "", fmt.Errorf("invalid escape \\%c", s[i+1])
			}
			i += 2
		case '"':
			return b.String(), s[i+1:], nil
		default:
			b.WriteByte(c)
			i++
		}
	}
	return "", "", fmt.Errorf("unterminated string")
}

// ensureCommentOnly verifies that the text after a value is empty or a
// whitespace-led inline comment.
func ensureCommentOnly(rest string) error {
	trimmed := strings.TrimSpace(rest)
	if trimmed == "" {
		return nil
	}
	if strings.HasPrefix(trimmed, "#") {
		return nil
	}
	return fmt.Errorf("unexpected trailing text %q after value", trimmed)
}

// assign maps a (section, key) pair to the corresponding struct field.
func assign(cfg *Config, section, key string, v tomlValue) error {
	wantStr := func() (string, error) {
		if v.isInt {
			return "", fmt.Errorf("%s.%s expects a string", section, key)
		}
		return v.str, nil
	}
	wantInt := func() (int, error) {
		if !v.isInt {
			return 0, fmt.Errorf("%s.%s expects an integer", section, key)
		}
		return v.i, nil
	}

	switch section {
	case "":
		switch key {
		case "host":
			s, err := wantStr()
			if err != nil {
				return err
			}
			cfg.Host = s
		default:
			return fmt.Errorf("unknown key %q", key)
		}
	case "ssh":
		switch key {
		case "user":
			s, err := wantStr()
			if err != nil {
				return err
			}
			cfg.SSH.User = s
		case "port":
			n, err := wantInt()
			if err != nil {
				return err
			}
			cfg.SSH.Port = n
		case "key":
			s, err := wantStr()
			if err != nil {
				return err
			}
			cfg.SSH.Key = s
		default:
			return fmt.Errorf("unknown key %q in [ssh]", key)
		}
	case "wireguard":
		switch key {
		case "port":
			n, err := wantInt()
			if err != nil {
				return err
			}
			cfg.WireGuard.Port = n
		case "server_ip":
			s, err := wantStr()
			if err != nil {
				return err
			}
			cfg.WireGuard.ServerIP = s
		case "client_ip":
			s, err := wantStr()
			if err != nil {
				return err
			}
			cfg.WireGuard.ClientIP = s
		default:
			return fmt.Errorf("unknown key %q in [wireguard]", key)
		}
	case "dropbear":
		switch key {
		case "port":
			n, err := wantInt()
			if err != nil {
				return err
			}
			cfg.Dropbear.Port = n
		default:
			return fmt.Errorf("unknown key %q in [dropbear]", key)
		}
	case "output":
		switch key {
		case "dir":
			s, err := wantStr()
			if err != nil {
				return err
			}
			cfg.Output.Dir = s
		default:
			return fmt.Errorf("unknown key %q in [output]", key)
		}
	case "network":
		switch key {
		case "interface":
			s, err := wantStr()
			if err != nil {
				return err
			}
			cfg.Network.Interface = s
		case "ip":
			s, err := wantStr()
			if err != nil {
				return err
			}
			cfg.Network.IP = s
		default:
			return fmt.Errorf("unknown key %q in [network]", key)
		}
	case "luks":
		switch key {
		case "device":
			s, err := wantStr()
			if err != nil {
				return err
			}
			cfg.LUKS.Device = s
		default:
			return fmt.Errorf("unknown key %q in [luks]", key)
		}
	default:
		return fmt.Errorf("unknown section [%s]", section)
	}
	return nil
}

// Marshal renders c as TOML text (no comments) that Load can round-trip.
func Marshal(c *Config) ([]byte, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "host = %s\n", quote(c.Host))

	b.WriteString("\n[ssh]\n")
	fmt.Fprintf(&b, "user = %s\n", quote(c.SSH.User))
	fmt.Fprintf(&b, "port = %d\n", c.SSH.Port)
	fmt.Fprintf(&b, "key = %s\n", quote(c.SSH.Key))

	b.WriteString("\n[wireguard]\n")
	fmt.Fprintf(&b, "port = %d\n", c.WireGuard.Port)
	fmt.Fprintf(&b, "server_ip = %s\n", quote(c.WireGuard.ServerIP))
	fmt.Fprintf(&b, "client_ip = %s\n", quote(c.WireGuard.ClientIP))

	b.WriteString("\n[dropbear]\n")
	fmt.Fprintf(&b, "port = %d\n", c.Dropbear.Port)

	b.WriteString("\n[output]\n")
	fmt.Fprintf(&b, "dir = %s\n", quote(c.Output.Dir))

	b.WriteString("\n[network]\n")
	fmt.Fprintf(&b, "interface = %s\n", quote(c.Network.Interface))
	fmt.Fprintf(&b, "ip = %s\n", quote(c.Network.IP))

	b.WriteString("\n[luks]\n")
	fmt.Fprintf(&b, "device = %s\n", quote(c.LUKS.Device))

	return []byte(b.String()), nil
}

// quote double-quotes a string and escapes backslashes and double quotes.
func quote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

// Test seams over os file operations so tests can inject I/O failures without
// relying on platform-specific filesystem quirks. Production behavior is
// identical to calling the os.* functions directly.
var (
	createTemp  = os.CreateTemp
	writeFile   = (*os.File).Write
	chmodFile   = (*os.File).Chmod
	closeFile   = (*os.File).Close
	renameFile  = os.Rename
	removeFile  = os.Remove
	marshalFunc = Marshal
)

// Save writes c to path atomically (temp file in the same dir + os.Rename),
// with mode 0644.
func Save(c *Config, path string) error {
	data, err := marshalFunc(c)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := createTemp(dir, ".ubo-*.toml.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer removeFile(tmpName)

	if _, err := writeFile(tmp, data); err != nil {
		closeFile(tmp)
		return err
	}
	if err := chmodFile(tmp, 0644); err != nil {
		closeFile(tmp)
		return err
	}
	if err := closeFile(tmp); err != nil {
		return err
	}
	return renameFile(tmpName, path)
}
