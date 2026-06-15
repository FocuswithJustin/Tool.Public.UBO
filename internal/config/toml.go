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
		if err := parseLine(strings.TrimSpace(raw), cfg, &section); err != nil {
			return fmt.Errorf("line %d: %w", i+1, err)
		}
	}
	return nil
}

// parseLine processes one already-trimmed line, updating *section for headers
// and assigning into cfg for key/value pairs. Blank and comment lines are
// no-ops.
func parseLine(line string, cfg *Config, section *string) error {
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	if strings.HasPrefix(line, "[") {
		name, err := parseSectionHeader(line)
		if err != nil {
			return err
		}
		*section = name
		return nil
	}
	key, val, err := parseKeyValue(line)
	if err != nil {
		return err
	}
	return assign(cfg, *section, key, val)
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

// tomlValue is a decoded scalar: a string, an int, or a bool.
type tomlValue struct {
	isInt  bool
	isBool bool
	str    string
	i      int
	b      bool
}

// parseValue decodes a single value plus an optional trailing comment.
func parseValue(s string) (tomlValue, error) {
	if s == "" {
		return tomlValue{}, fmt.Errorf("missing value")
	}
	if s[0] == '"' {
		return parseStringValue(s)
	}
	if s[0] == 't' || s[0] == 'f' {
		return parseBoolValue(s)
	}
	return parseIntValue(s)
}

// parseBoolValue decodes a bare boolean value (true/false), stripping any
// trailing inline comment that starts at an unquoted '#'.
func parseBoolValue(s string) (tomlValue, error) {
	tok := s
	if h := strings.IndexByte(s, '#'); h >= 0 {
		tok = s[:h]
	}
	switch strings.TrimSpace(tok) {
	case "true":
		return tomlValue{isBool: true, b: true}, nil
	case "false":
		return tomlValue{isBool: true, b: false}, nil
	}
	return tomlValue{}, fmt.Errorf("invalid value %q (expected quoted string, integer, or boolean)", strings.TrimSpace(tok))
}

// parseStringValue decodes a quoted string value and any trailing comment.
func parseStringValue(s string) (tomlValue, error) {
	str, rest, err := parseQuoted(s)
	if err != nil {
		return tomlValue{}, err
	}
	if err := ensureCommentOnly(rest); err != nil {
		return tomlValue{}, err
	}
	return tomlValue{str: str}, nil
}

// parseIntValue decodes a bare integer value, stripping any trailing inline
// comment that starts at an unquoted '#'.
func parseIntValue(s string) (tomlValue, error) {
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
		switch s[i] {
		case '\\':
			decoded, err := unescape(s, i)
			if err != nil {
				return "", "", err
			}
			b.WriteByte(decoded)
			i += 2
		case '"':
			return b.String(), s[i+1:], nil
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	return "", "", fmt.Errorf("unterminated string")
}

// unescape decodes the escape sequence in s that begins with the backslash at
// index i, returning the literal byte it represents.
func unescape(s string, i int) (byte, error) {
	if i+1 >= len(s) {
		return 0, fmt.Errorf("unterminated string")
	}
	switch s[i+1] {
	case '"':
		return '"', nil
	case '\\':
		return '\\', nil
	default:
		return 0, fmt.Errorf("invalid escape \\%c", s[i+1])
	}
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

// fieldSetter applies a decoded value to one struct field, returning an error
// if the value has the wrong type for that field.
type fieldSetter func(cfg *Config, section, key string, v tomlValue) error

// strField builds a setter that stores a string into the field selected by get.
func strField(get func(*Config) *string) fieldSetter {
	return func(cfg *Config, section, key string, v tomlValue) error {
		if v.isInt || v.isBool {
			return fmt.Errorf("%s.%s expects a string", section, key)
		}
		*get(cfg) = v.str
		return nil
	}
}

// intField builds a setter that stores an int into the field selected by get.
func intField(get func(*Config) *int) fieldSetter {
	return func(cfg *Config, section, key string, v tomlValue) error {
		if !v.isInt {
			return fmt.Errorf("%s.%s expects an integer", section, key)
		}
		*get(cfg) = v.i
		return nil
	}
}

// boolField builds a setter that stores a bool into the field selected by get.
func boolField(get func(*Config) *bool) fieldSetter {
	return func(cfg *Config, section, key string, v tomlValue) error {
		if !v.isBool {
			return fmt.Errorf("%s.%s expects a boolean", section, key)
		}
		*get(cfg) = v.b
		return nil
	}
}

// schema maps each section to its known keys and their field setters.
var schema = map[string]map[string]fieldSetter{
	"": {
		"host": strField(func(c *Config) *string { return &c.Host }),
	},
	"ssh": {
		"user":       strField(func(c *Config) *string { return &c.SSH.User }),
		"port":       intField(func(c *Config) *int { return &c.SSH.Port }),
		"key":        strField(func(c *Config) *string { return &c.SSH.Key }),
		"sudo":       boolField(func(c *Config) *bool { return &c.SSH.Sudo }),
		"proxy_jump": strField(func(c *Config) *string { return &c.SSH.ProxyJump }),
	},
	"wireguard": {
		"port":      intField(func(c *Config) *int { return &c.WireGuard.Port }),
		"server_ip": strField(func(c *Config) *string { return &c.WireGuard.ServerIP }),
		"client_ip": strField(func(c *Config) *string { return &c.WireGuard.ClientIP }),
	},
	"dropbear": {
		"port": intField(func(c *Config) *int { return &c.Dropbear.Port }),
	},
	"output": {
		"dir": strField(func(c *Config) *string { return &c.Output.Dir }),
	},
	"network": {
		"interface": strField(func(c *Config) *string { return &c.Network.Interface }),
		"ip":        strField(func(c *Config) *string { return &c.Network.IP }),
	},
	"luks": {
		"device": strField(func(c *Config) *string { return &c.LUKS.Device }),
	},
}

// assign maps a (section, key) pair to the corresponding struct field.
func assign(cfg *Config, section, key string, v tomlValue) error {
	keys, ok := schema[section]
	if !ok {
		return fmt.Errorf("unknown section [%s]", section)
	}
	set, ok := keys[key]
	if !ok {
		return unknownKeyError(section, key)
	}
	return set(cfg, section, key, v)
}

// unknownKeyError formats the "unknown key" error, naming the section when set.
func unknownKeyError(section, key string) error {
	if section == "" {
		return fmt.Errorf("unknown key %q", key)
	}
	return fmt.Errorf("unknown key %q in [%s]", key, section)
}

// Marshal renders c as TOML text (no comments) that Load can round-trip.
func Marshal(c *Config) ([]byte, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "host = %s\n", quote(c.Host))

	b.WriteString("\n[ssh]\n")
	fmt.Fprintf(&b, "user = %s\n", quote(c.SSH.User))
	fmt.Fprintf(&b, "port = %d\n", c.SSH.Port)
	fmt.Fprintf(&b, "key = %s\n", quote(c.SSH.Key))
	fmt.Fprintf(&b, "sudo = %t\n", c.SSH.Sudo)
	fmt.Fprintf(&b, "proxy_jump = %s\n", quote(c.SSH.ProxyJump))

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
