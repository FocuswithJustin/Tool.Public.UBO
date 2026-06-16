package checker

import (
	"fmt"
	"os/exec"
	"strings"
)

type toolDef struct {
	name string
	pkg  string
}

var runTools = []toolDef{
	{"wg", "wireguard-tools"},
	{"ssh-keygen", "openssh-client"},
	{"ssh", "openssh-client"},
}

// findMissingTools returns the names of tools not found on PATH and the set of
// packages that provide them.
func findMissingTools(tools []toolDef) ([]string, map[string]bool) {
	var missing []string
	pkgSet := make(map[string]bool)
	for _, t := range tools {
		if _, err := exec.LookPath(t.name); err != nil {
			missing = append(missing, t.name)
			pkgSet[t.pkg] = true
		}
	}
	return missing, pkgSet
}

// CheckTools verifies that all tools required for the given subcommand are present.
// Returns a descriptive error with install instructions if any are missing.
func CheckTools(subcommand string) error {
	var tools []toolDef
	switch subcommand {
	case "run":
		tools = runTools
	default:
		return nil
	}

	missing, pkgSet := findMissingTools(tools)
	if len(missing) == 0 {
		return nil
	}

	var pkgs []string
	for p := range pkgSet {
		pkgs = append(pkgs, p)
	}

	return fmt.Errorf(
		"missing required tools: %s\n"+
			"Install with: sudo apt install %s\n"+
			"  (or equivalent for your system)",
		strings.Join(missing, ", "),
		strings.Join(pkgs, " "),
	)
}
