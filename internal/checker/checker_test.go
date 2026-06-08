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
