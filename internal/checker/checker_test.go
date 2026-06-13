package checker

import (
	"strings"
	"testing"
)

func TestCheckTools_unknownSubcommand(t *testing.T) {
	// Unknown subcommand should not error — nothing to check
	if err := CheckTools("configure"); err != nil {
		t.Errorf("unexpected error for configure subcommand: %v", err)
	}
	if err := CheckTools("init"); err != nil {
		t.Errorf("unexpected error for init subcommand: %v", err)
	}
	if err := CheckTools(""); err != nil {
		t.Errorf("unexpected error for empty subcommand: %v", err)
	}
}

func TestCheckTools_run_toolsPresent(t *testing.T) {
	// In the nix-shell dev environment wg and ssh-keygen are always available.
	// If they're not, skip rather than fail — this is an environment issue.
	err := CheckTools("run")
	if err != nil {
		if strings.Contains(err.Error(), "missing required tools") {
			t.Skipf("tools not in PATH; skipping: %v", err)
		}
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCheckTools_run_errorMessage(t *testing.T) {
	// Temporarily replace runTools with a fake missing tool to test error formatting.
	orig := runTools
	defer func() { runTools = orig }()
	runTools = []toolDef{{"this-tool-does-not-exist-xyz", "some-package"}}

	err := CheckTools("run")
	if err == nil {
		t.Fatal("expected error for missing tool")
	}
	msg := err.Error()
	if !strings.Contains(msg, "this-tool-does-not-exist-xyz") {
		t.Errorf("error message missing tool name: %q", msg)
	}
	if !strings.Contains(msg, "some-package") {
		t.Errorf("error message missing package name: %q", msg)
	}
	if !strings.Contains(msg, "sudo apt install") {
		t.Errorf("error message missing install instructions: %q", msg)
	}
}

func TestCheckTools_deduplicatesPackages(t *testing.T) {
	orig := runTools
	defer func() { runTools = orig }()
	runTools = []toolDef{
		{"no-tool-a", "shared-pkg"},
		{"no-tool-b", "shared-pkg"},
	}

	err := CheckTools("run")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	// Package name should appear only once
	count := strings.Count(msg, "shared-pkg")
	if count != 1 {
		t.Errorf("package name appeared %d times in error message; want 1: %q", count, msg)
	}
}

func TestCheckTools_multiplePackages(t *testing.T) {
	orig := runTools
	defer func() { runTools = orig }()
	runTools = []toolDef{
		{"no-tool-a", "pkg-alpha"},
		{"no-tool-b", "pkg-beta"},
	}

	err := CheckTools("run")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "no-tool-a") {
		t.Errorf("error missing tool name no-tool-a: %q", msg)
	}
	if !strings.Contains(msg, "no-tool-b") {
		t.Errorf("error missing tool name no-tool-b: %q", msg)
	}
	if !strings.Contains(msg, "pkg-alpha") {
		t.Errorf("error missing package pkg-alpha: %q", msg)
	}
	if !strings.Contains(msg, "pkg-beta") {
		t.Errorf("error missing package pkg-beta: %q", msg)
	}
}

func TestCheckTools_unlock_toolsPresent(t *testing.T) {
	// In the nix-shell dev environment wg-quick, ssh and ping are available.
	// If they're not, skip rather than fail — this is an environment issue.
	err := CheckTools("unlock")
	if err != nil {
		if strings.Contains(err.Error(), "missing required tools") {
			t.Skipf("tools not in PATH; skipping: %v", err)
		}
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCheckTools_unlockChange_toolsPresent(t *testing.T) {
	// "unlock-change" maps to the same unlockTools set as "unlock".
	err := CheckTools("unlock-change")
	if err != nil {
		if strings.Contains(err.Error(), "missing required tools") {
			t.Skipf("tools not in PATH; skipping: %v", err)
		}
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCheckTools_unlock_errorMessage(t *testing.T) {
	// Replace unlockTools with fake missing tools to exercise the unlock
	// branch's error formatting (tools + packages + install instructions).
	orig := unlockTools
	defer func() { unlockTools = orig }()
	unlockTools = []toolDef{
		{"no-wg-quick-xyz", "wireguard-tools"},
		{"no-ssh-xyz", "openssh-client"},
		{"no-ping-xyz", "iputils-ping"},
	}

	err := CheckTools("unlock")
	if err == nil {
		t.Fatal("expected error for missing unlock tools")
	}
	msg := err.Error()
	for _, want := range []string{
		"no-wg-quick-xyz", "no-ssh-xyz", "no-ping-xyz",
		"wireguard-tools", "openssh-client", "iputils-ping",
		"sudo apt install",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q: %q", want, msg)
		}
	}
}

func TestCheckTools_unlockChange_errorMessage(t *testing.T) {
	// "unlock-change" uses the same unlockTools slice; verify the missing-tool
	// path is reached via that subcommand alias too.
	orig := unlockTools
	defer func() { unlockTools = orig }()
	unlockTools = []toolDef{{"no-unlock-change-tool-xyz", "uc-pkg"}}

	err := CheckTools("unlock-change")
	if err == nil {
		t.Fatal("expected error for missing unlock-change tool")
	}
	msg := err.Error()
	if !strings.Contains(msg, "no-unlock-change-tool-xyz") {
		t.Errorf("error missing tool name: %q", msg)
	}
	if !strings.Contains(msg, "uc-pkg") {
		t.Errorf("error missing package name: %q", msg)
	}
}

func TestCheckTools_unlock_partialMissing(t *testing.T) {
	// One present tool, one missing: only the missing tool/package should be
	// reported, exercising the false branch of the LookPath condition for the
	// unlock path while still producing an error.
	orig := unlockTools
	defer func() { unlockTools = orig }()
	unlockTools = []toolDef{
		{"sh", "should-not-appear-pkg"}, // present in PATH
		{"definitely-no-such-tool-xyz", "needed-pkg"},
	}

	err := CheckTools("unlock")
	if err == nil {
		t.Fatal("expected error when one unlock tool is missing")
	}
	msg := err.Error()
	if !strings.Contains(msg, "definitely-no-such-tool-xyz") {
		t.Errorf("error missing the absent tool name: %q", msg)
	}
	if strings.Contains(msg, "sh,") || strings.Contains(msg, ", sh") {
		t.Errorf("present tool 'sh' should not be listed as missing: %q", msg)
	}
	if strings.Contains(msg, "should-not-appear-pkg") {
		t.Errorf("package for present tool should not appear: %q", msg)
	}
}
