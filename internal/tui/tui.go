// Package tui provides a simple, dependency-free interactive editor for the
// ubo configuration file. It prompts for each field on stdout and reads
// answers from stdin: an empty line keeps the current value, while a non-empty
// line replaces it.
package tui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"ubo/internal/config"
)

// fieldDef binds a label to config get/set functions for a single prompt.
// If isInt is true the answer must parse as an integer (the prompt re-asks
// until a valid integer is entered or the field is kept).
type fieldDef struct {
	label    string
	isInt    bool
	getValue func(*config.Config) string
	setValue func(*config.Config, string)
}

// fields lists every editable field in display order. The set and ordering
// match the previous editor: Host, SSH (User/Port/Key), WireGuard
// (Port/ServerIP/ClientIP), Dropbear (Port), Output (Dir), Network
// (Interface/IP), and LUKS (Device).
var fields = []fieldDef{
	{
		label:    "Host",
		getValue: func(c *config.Config) string { return c.Host },
		setValue: func(c *config.Config, v string) { c.Host = v },
	},
	{
		label:    "SSH User",
		getValue: func(c *config.Config) string { return c.SSH.User },
		setValue: func(c *config.Config, v string) { c.SSH.User = v },
	},
	{
		label: "SSH Port", isInt: true,
		getValue: func(c *config.Config) string { return strconv.Itoa(c.SSH.Port) },
		setValue: func(c *config.Config, v string) { c.SSH.Port, _ = strconv.Atoi(v) },
	},
	{
		label:    "SSH Key Path",
		getValue: func(c *config.Config) string { return c.SSH.Key },
		setValue: func(c *config.Config, v string) { c.SSH.Key = v },
	},
	{
		label:    "SSH ProxyJump",
		getValue: func(c *config.Config) string { return c.SSH.ProxyJump },
		setValue: func(c *config.Config, v string) { c.SSH.ProxyJump = v },
	},
	{
		label: "WireGuard Port", isInt: true,
		getValue: func(c *config.Config) string { return strconv.Itoa(c.WireGuard.Port) },
		setValue: func(c *config.Config, v string) { c.WireGuard.Port, _ = strconv.Atoi(v) },
	},
	{
		label:    "WG Server IP",
		getValue: func(c *config.Config) string { return c.WireGuard.ServerIP },
		setValue: func(c *config.Config, v string) { c.WireGuard.ServerIP = v },
	},
	{
		label:    "WG Client IP",
		getValue: func(c *config.Config) string { return c.WireGuard.ClientIP },
		setValue: func(c *config.Config, v string) { c.WireGuard.ClientIP = v },
	},
	{
		label: "Dropbear Port", isInt: true,
		getValue: func(c *config.Config) string { return strconv.Itoa(c.Dropbear.Port) },
		setValue: func(c *config.Config, v string) { c.Dropbear.Port, _ = strconv.Atoi(v) },
	},
	{
		label:    "Output Dir",
		getValue: func(c *config.Config) string { return c.Output.Dir },
		setValue: func(c *config.Config, v string) { c.Output.Dir = v },
	},
	{
		label:    "Network Interface",
		getValue: func(c *config.Config) string { return c.Network.Interface },
		setValue: func(c *config.Config, v string) { c.Network.Interface = v },
	},
	{
		label:    "Network IP",
		getValue: func(c *config.Config) string { return c.Network.IP },
		setValue: func(c *config.Config, v string) { c.Network.IP = v },
	},
	{
		label:    "LUKS Device",
		getValue: func(c *config.Config) string { return c.LUKS.Device },
		setValue: func(c *config.Config, v string) { c.LUKS.Device = v },
	},
}

// edit prompts for each field on out, reading answers from in. For each field
// it shows the label and the current value (e.g. "Host [192.168.1.100]: ").
// An empty line keeps the current value; a non-empty line replaces it.
// Surrounding whitespace is trimmed from answers. Integer fields re-prompt on
// a parse failure until a valid integer is entered or the value is kept. If in
// reaches EOF before all fields are answered, the remaining fields keep their
// current values and prompting stops. The (possibly modified) cfg is returned.
func edit(in io.Reader, out io.Writer, cfg *config.Config) (*config.Config, error) {
	r := bufio.NewReader(in)

	fmt.Fprintln(out, "UBO Configuration Editor")
	fmt.Fprintln(out, "Press Enter to keep the current value shown in [brackets].")
	fmt.Fprintln(out)

	for _, fd := range fields {
		eof, err := editField(r, out, cfg, fd)
		if err != nil {
			return nil, err
		}
		// Stop prompting once input is exhausted; remaining fields keep current.
		if eof {
			break
		}
	}

	return cfg, nil
}

// editField runs the prompt loop for a single field, updating cfg in place.
// It returns whether EOF was reached on the underlying reader, and any
// non-EOF read error. Integer fields re-prompt on a parse failure until a
// valid value is entered or input is exhausted.
func editField(r *bufio.Reader, out io.Writer, cfg *config.Config, fd fieldDef) (bool, error) {
	for {
		fmt.Fprintf(out, "%s [%s]: ", fd.label, fd.getValue(cfg))

		line, err := r.ReadString('\n')
		eof := err == io.EOF
		if err != nil && !eof {
			return false, err
		}

		answer := strings.TrimSpace(line)
		if answer == "" {
			// Empty line (or EOF with no input) keeps the current value.
			return eof, nil
		}

		if retry := applyAnswer(out, cfg, fd, answer, eof); retry {
			continue // re-prompt the same field
		}
		return eof, nil
	}
}

// applyAnswer validates and applies a non-empty answer to fd. It returns true
// when the field should be re-prompted (an invalid integer with input still
// available); otherwise it sets the value (when valid) and returns false.
func applyAnswer(out io.Writer, cfg *config.Config, fd fieldDef, answer string, eof bool) bool {
	if fd.isInt {
		if _, perr := strconv.Atoi(answer); perr != nil {
			fmt.Fprintf(out, "invalid number %q, please enter an integer\n", answer)
			// Re-prompt only when there is more input to retry with.
			return !eof
		}
	}
	fd.setValue(cfg, answer)
	return false
}

// Run loads configPath (or config.Default() if the file is absent), runs the
// interactive editor against os.Stdin/os.Stdout, validates the result, and
// saves it atomically via config.Save. A confirmation line is printed on
// success.
func Run(configPath string) error {
	var cfg *config.Config
	if _, err := os.Stat(configPath); err == nil {
		loaded, lerr := config.Load(configPath)
		if lerr != nil {
			return lerr
		}
		cfg = loaded
	} else {
		cfg = config.Default()
	}

	cfg, err := edit(os.Stdin, os.Stdout, cfg)
	if err != nil {
		return err
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	if err := config.Save(cfg, configPath); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "saved to %s\n", configPath)
	return nil
}
