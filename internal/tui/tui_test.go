package tui

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ubo/internal/config"

	tea "github.com/charmbracelet/bubbletea"
)

// key builds a tea.KeyMsg for a single special key type.
func key(t tea.KeyType) tea.KeyMsg {
	return tea.KeyMsg(tea.Key{Type: t})
}

// runeKey builds a tea.KeyMsg for typed runes.
func runeKey(rs ...rune) tea.KeyMsg {
	return tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: rs})
}

// isQuit reports whether cmd, when invoked, yields a tea.QuitMsg.
func isQuit(cmd tea.Cmd) bool {
	if cmd == nil {
		return false
	}
	msg := cmd()
	_, ok := msg.(tea.QuitMsg)
	return ok
}

// validTOML is a complete, valid config that round-trips through config.Load.
const validTOML = `host = "192.168.1.100"
[ssh]
user = "root"
port = 22
key = ""
[wireguard]
port = 51820
server_ip = "10.42.0.1/24"
client_ip = "10.42.0.2/32"
[dropbear]
port = 22
[output]
dir = ""
[network]
interface = ""
ip = ""
[luks]
device = ""
`

func writeFile(t *testing.T, dir, name, contents string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func TestNewModel_NonexistentUsesDefault(t *testing.T) {
	p := filepath.Join(t.TempDir(), "does-not-exist.toml")
	m, err := newModel(p)
	if err != nil {
		t.Fatalf("newModel: %v", err)
	}
	if m.cfg.Host != config.Default().Host {
		t.Errorf("expected default host, got %q", m.cfg.Host)
	}
	if len(m.inputs) != len(fields) {
		t.Errorf("expected %d inputs, got %d", len(fields), len(m.inputs))
	}
	// First input must be focused.
	if !m.inputs[0].Focused() {
		t.Error("expected first input focused")
	}
	// SSH port default 22 should be pre-populated as a string.
	if got := m.inputs[2].Value(); got != "22" {
		t.Errorf("expected ssh port input '22', got %q", got)
	}
}

func TestNewModel_ExistingValidPrepopulates(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "ubo.toml", validTOML)
	m, err := newModel(p)
	if err != nil {
		t.Fatalf("newModel: %v", err)
	}
	if m.cfg.Host != "192.168.1.100" {
		t.Errorf("expected loaded host, got %q", m.cfg.Host)
	}
	if m.inputs[0].Value() != "192.168.1.100" {
		t.Errorf("expected host input pre-populated, got %q", m.inputs[0].Value())
	}
}

func TestNewModel_InvalidTOMLReturnsError(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "bad.toml", "this is = = not valid toml [[[")
	m, err := newModel(p)
	if err == nil {
		t.Fatal("expected error for malformed TOML")
	}
	if m != nil {
		t.Error("expected nil model on error")
	}
	if !strings.Contains(err.Error(), "load config") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestInit(t *testing.T) {
	m, _ := newModel(filepath.Join(t.TempDir(), "x.toml"))
	if cmd := m.Init(); cmd == nil {
		t.Error("expected non-nil Init cmd (Blink)")
	}
}

func TestUpdate_TabAdvancesAndWraps(t *testing.T) {
	m, _ := newModel(filepath.Join(t.TempDir(), "x.toml"))
	var cur tea.Model = m
	// Advance with "tab" through every field and wrap around to 0.
	for i := 1; i <= len(fields); i++ {
		nm, cmd := cur.Update(key(tea.KeyTab))
		cur = nm
		if cmd == nil {
			t.Error("expected Blink cmd on tab")
		}
		want := i % len(fields)
		if got := nm.(model).focusIdx; got != want {
			t.Fatalf("after %d tabs focusIdx=%d want %d", i, got, want)
		}
	}
	// "down" also advances.
	nm, _ := cur.Update(key(tea.KeyDown))
	if nm.(model).focusIdx != 1 {
		t.Errorf("down: focusIdx=%d want 1", nm.(model).focusIdx)
	}
}

func TestUpdate_ShiftTabRetreatsAndWraps(t *testing.T) {
	m, _ := newModel(filepath.Join(t.TempDir(), "x.toml"))
	var cur tea.Model = m
	// shift+tab from 0 wraps to last index.
	nm, cmd := cur.Update(key(tea.KeyShiftTab))
	if cmd == nil {
		t.Error("expected Blink cmd on shift+tab")
	}
	if got := nm.(model).focusIdx; got != len(fields)-1 {
		t.Fatalf("shift+tab wrap: focusIdx=%d want %d", got, len(fields)-1)
	}
	// "up" retreats one more.
	nm2, _ := nm.Update(key(tea.KeyUp))
	if got := nm2.(model).focusIdx; got != len(fields)-2 {
		t.Errorf("up: focusIdx=%d want %d", got, len(fields)-2)
	}
}

func TestUpdate_TypingRuneSetsDirty(t *testing.T) {
	m, _ := newModel(filepath.Join(t.TempDir(), "x.toml"))
	m.saved = true // ensure it gets cleared
	nm, _ := m.Update(runeKey('x'))
	res := nm.(model)
	if !res.dirty {
		t.Error("expected dirty after typing")
	}
	if res.saved {
		t.Error("expected saved cleared after typing")
	}
	if res.err != "" {
		t.Error("expected err cleared after typing")
	}
	if !strings.Contains(res.inputs[0].Value(), "x") {
		t.Errorf("expected typed rune in input, got %q", res.inputs[0].Value())
	}
}

func TestUpdate_NonMutatingKeyDoesNotSetDirty(t *testing.T) {
	m, _ := newModel(filepath.Join(t.TempDir(), "x.toml"))
	// Left arrow moves cursor but doesn't change value -> not dirty.
	nm, _ := m.Update(key(tea.KeyLeft))
	if nm.(model).dirty {
		t.Error("expected not dirty after non-mutating key")
	}
}

func TestUpdate_CtrlSSaveSuccess(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "out.toml")
	m, _ := newModel(p)
	m.inputs[0].SetValue("192.168.1.100") // host required for valid save
	m.dirty = true
	nm, cmd := m.Update(key(tea.KeyCtrlS))
	res := nm.(model)
	if res.err != "" {
		t.Fatalf("unexpected err: %s", res.err)
	}
	if !res.saved {
		t.Error("expected saved=true")
	}
	if res.dirty {
		t.Error("expected dirty=false after save")
	}
	if isQuit(cmd) {
		t.Error("ctrl+s should not quit")
	}
	if _, err := config.Load(p); err != nil {
		t.Errorf("saved file should load: %v", err)
	}
}

func TestUpdate_CtrlSSaveValidationError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "out.toml")
	m, _ := newModel(p)
	m.inputs[0].SetValue("") // clear Host -> validation fails
	nm, _ := m.Update(key(tea.KeyCtrlS))
	res := nm.(model)
	if res.err == "" {
		t.Error("expected validation error set")
	}
	if res.saved {
		t.Error("expected saved=false on validation failure")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("file should not be written on validation failure")
	}
}

func TestUpdate_EscQuitsWhenClean(t *testing.T) {
	m, _ := newModel(filepath.Join(t.TempDir(), "x.toml"))
	nm, cmd := m.Update(key(tea.KeyEsc))
	if nm.(model).confirmQuit {
		t.Error("clean esc should not set confirmQuit")
	}
	if !isQuit(cmd) {
		t.Error("clean esc should quit")
	}
}

func TestUpdate_EscConfirmsWhenDirty(t *testing.T) {
	m, _ := newModel(filepath.Join(t.TempDir(), "x.toml"))
	m.dirty = true
	nm, cmd := m.Update(key(tea.KeyEsc))
	if !nm.(model).confirmQuit {
		t.Error("dirty esc should set confirmQuit")
	}
	if isQuit(cmd) {
		t.Error("dirty esc should not quit immediately")
	}
}

func TestUpdate_CtrlCQuitsWhenClean(t *testing.T) {
	m, _ := newModel(filepath.Join(t.TempDir(), "x.toml"))
	nm, cmd := m.Update(key(tea.KeyCtrlC))
	if nm.(model).confirmQuit {
		t.Error("clean ctrl+c should not set confirmQuit")
	}
	if !isQuit(cmd) {
		t.Error("clean ctrl+c should quit")
	}
}

func TestUpdate_CtrlCConfirmsWhenDirty(t *testing.T) {
	m, _ := newModel(filepath.Join(t.TempDir(), "x.toml"))
	m.dirty = true
	nm, cmd := m.Update(key(tea.KeyCtrlC))
	if !nm.(model).confirmQuit {
		t.Error("dirty ctrl+c should set confirmQuit")
	}
	if isQuit(cmd) {
		t.Error("dirty ctrl+c should not quit immediately")
	}
}

func TestUpdate_WindowSize(t *testing.T) {
	m, _ := newModel(filepath.Join(t.TempDir(), "x.toml"))
	nm, cmd := m.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
	if cmd != nil {
		t.Error("WindowSizeMsg should return nil cmd")
	}
	if nm == nil {
		t.Error("expected model back")
	}
}

// --- confirmQuit dialog branches ---

func dirtyModel(t *testing.T, p string) model {
	t.Helper()
	m, _ := newModel(p)
	m.inputs[0].SetValue("192.168.1.100") // host required so save() succeeds
	m.dirty = true
	m.confirmQuit = true
	return *m
}

func TestConfirmQuit_YSavesAndQuits(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out.toml")
	m := dirtyModel(t, p)
	nm, cmd := m.Update(runeKey('y'))
	if !isQuit(cmd) {
		t.Error("'y' should quit")
	}
	if _, err := os.Stat(p); err != nil {
		t.Errorf("'y' should save file: %v", err)
	}
	_ = nm
}

func TestConfirmQuit_CapitalYSavesAndQuits(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out.toml")
	m := dirtyModel(t, p)
	_, cmd := m.Update(runeKey('Y'))
	if !isQuit(cmd) {
		t.Error("'Y' should quit")
	}
	if _, err := os.Stat(p); err != nil {
		t.Errorf("'Y' should save file: %v", err)
	}
}

func TestConfirmQuit_YSaveErrorCancels(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out.toml")
	m := dirtyModel(t, p)
	m.inputs[0].SetValue("") // invalid -> save fails
	nm, cmd := m.Update(runeKey('y'))
	res := nm.(model)
	if isQuit(cmd) {
		t.Error("'y' with save error should not quit")
	}
	if res.confirmQuit {
		t.Error("'y' save error should clear confirmQuit")
	}
	if res.err == "" {
		t.Error("'y' save error should set err")
	}
}

func TestConfirmQuit_EnterSavesAndQuits(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out.toml")
	m := dirtyModel(t, p)
	_, cmd := m.Update(key(tea.KeyEnter))
	if !isQuit(cmd) {
		t.Error("enter should save+quit")
	}
	if _, err := os.Stat(p); err != nil {
		t.Errorf("enter should save file: %v", err)
	}
}

func TestConfirmQuit_EnterSaveErrorCancels(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out.toml")
	m := dirtyModel(t, p)
	m.inputs[0].SetValue("")
	nm, cmd := m.Update(key(tea.KeyEnter))
	res := nm.(model)
	if isQuit(cmd) {
		t.Error("enter with save error should not quit")
	}
	if res.confirmQuit {
		t.Error("enter save error should clear confirmQuit")
	}
	if res.err == "" {
		t.Error("enter save error should set err")
	}
}

func TestConfirmQuit_NCancels(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out.toml")
	m := dirtyModel(t, p)
	nm, cmd := m.Update(runeKey('n'))
	if nm.(model).confirmQuit {
		t.Error("'n' should cancel confirmQuit")
	}
	if isQuit(cmd) {
		t.Error("'n' should not quit")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("'n' should not write file")
	}
}

func TestConfirmQuit_CapitalNCancels(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out.toml")
	m := dirtyModel(t, p)
	nm, cmd := m.Update(runeKey('N'))
	if nm.(model).confirmQuit {
		t.Error("'N' should cancel confirmQuit")
	}
	if isQuit(cmd) {
		t.Error("'N' should not quit")
	}
}

func TestConfirmQuit_EscCancels(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out.toml")
	m := dirtyModel(t, p)
	nm, cmd := m.Update(key(tea.KeyEsc))
	if nm.(model).confirmQuit {
		t.Error("esc should cancel confirmQuit")
	}
	if isQuit(cmd) {
		t.Error("esc should not quit")
	}
}

func TestConfirmQuit_CtrlCForceQuits(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out.toml")
	m := dirtyModel(t, p)
	_, cmd := m.Update(key(tea.KeyCtrlC))
	if !isQuit(cmd) {
		t.Error("ctrl+c should force quit")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("ctrl+c force quit should not write file")
	}
}

func TestConfirmQuit_OtherKeyIgnored(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out.toml")
	m := dirtyModel(t, p)
	nm, cmd := m.Update(runeKey('z'))
	if !nm.(model).confirmQuit {
		t.Error("unrelated key should keep confirmQuit active")
	}
	if cmd != nil {
		t.Error("unrelated key in confirmQuit should return nil cmd")
	}
}

// --- View states ---

func TestView_Normal(t *testing.T) {
	m, _ := newModel(filepath.Join(t.TempDir(), "x.toml"))
	out := m.View()
	if out == "" {
		t.Fatal("empty view")
	}
	for _, want := range []string{"UBO Configuration Editor", "Host", "SSH", "WireGuard", "navigate"} {
		if !strings.Contains(out, want) {
			t.Errorf("normal view missing %q", want)
		}
	}
}

func TestView_ConfirmQuit(t *testing.T) {
	m, _ := newModel(filepath.Join(t.TempDir(), "x.toml"))
	m.confirmQuit = true
	out := m.View()
	if !strings.Contains(out, "Save before exit") {
		t.Errorf("confirmQuit view missing prompt: %q", out)
	}
}

func TestView_Error(t *testing.T) {
	m, _ := newModel(filepath.Join(t.TempDir(), "x.toml"))
	m.err = "boom"
	out := m.View()
	if !strings.Contains(out, "error: boom") {
		t.Errorf("error view missing message: %q", out)
	}
}

func TestView_Saved(t *testing.T) {
	p := filepath.Join(t.TempDir(), "saved.toml")
	m, _ := newModel(p)
	m.saved = true
	out := m.View()
	if !strings.Contains(out, "saved to "+p) {
		t.Errorf("saved view missing path: %q", out)
	}
}

func TestView_FocusHighlightBothBranches(t *testing.T) {
	// Exercise both the active-label and plain-label branches in View by
	// rendering with focus on field 0 and then on field 1. Color codes may be
	// stripped without a TTY, so we only assert the views render non-empty and
	// still contain the labels (the if i == m.focusIdx branch is hit either way).
	m, _ := newModel(filepath.Join(t.TempDir(), "x.toml"))
	first := m.View()
	m.focusIdx = 1
	second := m.View()
	if first == "" || second == "" {
		t.Fatal("expected non-empty views")
	}
	if !strings.Contains(first, "Host") || !strings.Contains(second, "SSH User") {
		t.Error("expected labels present in both focus states")
	}
}

// --- save() ---

func TestSave_SuccessRoundTrips(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rt.toml")
	m, _ := newModel(p)
	m.inputs[0].SetValue("10.0.0.5")
	if err := m.save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := config.Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Host != "10.0.0.5" {
		t.Errorf("round-trip host=%q want 10.0.0.5", loaded.Host)
	}
}

func TestSave_ValidationFailureNoWrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "novalid.toml")
	m, _ := newModel(p)
	m.inputs[0].SetValue("") // empty host
	err := m.save()
	if err == nil {
		t.Fatal("expected validation error")
	}
	if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
		t.Error("file should not be written on validation failure")
	}
}

func TestSave_SetValueAppliesPortFields(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ports.toml")
	m, _ := newModel(p)
	m.inputs[0].SetValue("1.2.3.4")
	m.inputs[2].SetValue("2222") // SSH Port
	if err := m.save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, _ := config.Load(p)
	if loaded.SSH.Port != 2222 {
		t.Errorf("ssh port=%d want 2222", loaded.SSH.Port)
	}
}

func TestSave_CreateTempErrorOnMissingDir(t *testing.T) {
	// configPath in a directory that does not exist -> CreateTemp fails.
	p := filepath.Join(t.TempDir(), "no-such-dir", "out.toml")
	m, _ := newModel(p)
	m.inputs[0].SetValue("1.2.3.4")
	err := m.save()
	if err == nil {
		t.Fatal("expected create temp error for missing dir")
	}
	if !strings.Contains(err.Error(), "create temp file") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSave_RenameErrorWhenTargetIsDir(t *testing.T) {
	// configPath points at an existing directory -> os.Rename fails.
	dir := t.TempDir()
	target := filepath.Join(dir, "adir")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	m, _ := newModel(filepath.Join(dir, "seed.toml")) // load defaults
	m.configPath = target
	m.inputs[0].SetValue("1.2.3.4")
	err := m.save()
	if err == nil {
		t.Fatal("expected rename error when target is a directory")
	}
	if !strings.Contains(err.Error(), "save config") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSave_BareFilenameUsesCwd(t *testing.T) {
	// A configPath with no directory component: filepath.Dir returns ".",
	// so the temp file is created in the current working directory. Run from a
	// temp dir so we don't pollute the repo.
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)

	m, _ := newModel("bare.toml")
	m.inputs[0].SetValue("1.2.3.4")
	if err := m.save(); err != nil {
		t.Fatalf("save with bare filename: %v", err)
	}
	if _, err := config.Load(filepath.Join(dir, "bare.toml")); err != nil {
		t.Errorf("expected bare.toml written to cwd: %v", err)
	}
}

// Sanity: confirm tea.Quit identity used by isQuit.
func TestIsQuitHelper(t *testing.T) {
	if !isQuit(tea.Quit) {
		t.Error("tea.Quit should be detected as quit")
	}
	if isQuit(nil) {
		t.Error("nil cmd should not be quit")
	}
	if isQuit(func() tea.Msg { return nil }) {
		t.Error("non-quit cmd should not be quit")
	}
	_ = reflect.TypeOf(model{})
}
