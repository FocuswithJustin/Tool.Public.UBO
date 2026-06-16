package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"ubo/contrib/rootless"
	"ubo/internal/checker"
	"ubo/internal/config"
	"ubo/internal/keygen"
	"ubo/internal/remote"
	"ubo/internal/setup"
	"ubo/internal/templates"
	"ubo/internal/tui"
)

// Seams: indirections over the few non-deterministic / external operations,
// so functions can be exercised end-to-end in unit tests without network
// access or external processes. Production code uses the real implementations
// assigned here; tests reassign them.
var (
	remoteConnect     = remote.Connect
	keygenGenerateAll = keygen.GenerateAll
	setupConfigure    = setup.Configure
	checkTools        = checker.CheckTools
	tuiRun            = tui.Run

	// sudoProbe runs a trivial remote command to test whether passwordless sudo
	// (-n) works. Seamed so tests can stub it without a real SSH connection.
	sudoProbe = func(ctx context.Context, c *remote.Client) error {
		_, err := remote.RunCommand(ctx, c, "true")
		return err
	}

	// readSudoPassword prompts the operator for a sudo password with echo
	// suppressed. Seamed so tests can inject a fixed password.
	readSudoPassword = readSudoPasswordTTY

	// userspaceUnlock is the unlock path: wireguard-go netstack + in-process SSH.
	// No kernel WireGuard module, no wg-quick, no root needed.
	// Seamed for unit tests.
	userspaceUnlock = func(ctx context.Context, cfg *config.Config, outDir string, changeKey bool) error {
		return rootless.Unlock(ctx, cfg, outDir, changeKey)
	}

	// bootstrapConfigFn is seamed so tests can avoid reading from stdin.
	bootstrapConfigFn = bootstrapConfig
)

const usage = `ubo — Unlock Before Operation

Configure a Debian 13.5 system for remote LUKS unlock via WireGuard + Dropbear.

Usage:
  ubo [subcommand] [--config FILE]

Subcommands:
  configure           Open interactive TUI to create or edit config (default: ./ubo.toml)
  init                Write a default config file non-interactively
  run                 Configure the remote host — generates keys, installs WireGuard+Dropbear
                      If no --config is given and no ubo.toml exists, prompts for connection details
  status              Report whether the output dir is configured and ready to unlock
  unlock [HOST]       Bring up WireGuard, SSH to Dropbear, unlock disk, tear down tunnel
                      HOST: use the config in ./ubo-<HOST>/; omit to pick from available systems
  unlock change [HOST] Change LUKS passphrase, then optionally unlock

Flags:
  --config FILE  Config file path (default: ./ubo.toml for most subcommands)
  --help         Show this help
`

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func dispatch(args []string) error {
	sub, args := parseSubcommand(args)

	if isHelpSubcommand(sub) {
		fmt.Print(usage)
		return nil
	}

	// Default is empty so each handler can distinguish "not given" from
	// "given as ubo.toml". Unlock resolution and run bootstrap depend on this.
	fs := flag.NewFlagSet(sub, flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path")
	fs.Usage = func() { fmt.Print(usage) }
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	run, ok := subcommands[sub]
	if !ok {
		return fmt.Errorf("unknown subcommand %q\nRun 'ubo help' for usage", sub)
	}
	return run(context.Background(), *cfgPath, fs.Args())
}

// subcommands maps each subcommand name to its handler. The third parameter
// carries any remaining positional arguments after flag parsing (e.g. the
// optional HOST argument for unlock).
var subcommands = map[string]func(context.Context, string, []string) error{
	"configure": func(_ context.Context, cfgPath string, _ []string) error {
		return tuiRun(orDefault(cfgPath, "ubo.toml"))
	},
	"init": func(_ context.Context, cfgPath string, _ []string) error {
		return cmdInit(orDefault(cfgPath, "ubo.toml"))
	},
	"run": func(ctx context.Context, cfgPath string, _ []string) error {
		return cmdRun(ctx, cfgPath)
	},
	"status": func(_ context.Context, cfgPath string, _ []string) error {
		return cmdStatus(orDefault(cfgPath, "ubo.toml"))
	},
	"unlock": func(ctx context.Context, cfgPath string, args []string) error {
		if cfgPath == "" {
			var err error
			cfgPath, err = resolveUnlockConfig(args)
			if err != nil {
				return err
			}
		}
		return cmdUnlock(ctx, cfgPath, false)
	},
	"unlock-change": func(ctx context.Context, cfgPath string, args []string) error {
		if cfgPath == "" {
			var err error
			cfgPath, err = resolveUnlockConfig(args)
			if err != nil {
				return err
			}
		}
		return cmdUnlock(ctx, cfgPath, true)
	},
}

// orDefault returns s if non-empty, otherwise def.
func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// parseSubcommand extracts the subcommand name (defaulting to "run") and returns
// the remaining args. It folds the two-word "unlock change" into "unlock-change".
func parseSubcommand(args []string) (string, []string) {
	sub := "run"
	if len(args) > 0 && !isFlag(args[0]) {
		sub = args[0]
		args = args[1:]
		if sub == "unlock" && len(args) > 0 && args[0] == "change" {
			sub = "unlock-change"
			args = args[1:]
		}
	}
	return sub, args
}

func isHelpSubcommand(sub string) bool {
	return sub == "help" || sub == "--help" || sub == "-h"
}

func isFlag(s string) bool {
	return len(s) > 0 && s[0] == '-'
}

// cmdInit writes a default config file.
func cmdInit(cfgPath string) error {
	if _, err := os.Stat(cfgPath); err == nil {
		return fmt.Errorf("%s already exists; delete it first or use 'ubo configure' to edit it", cfgPath)
	}
	if err := os.WriteFile(cfgPath, []byte(config.DefaultTemplate), 0644); err != nil {
		return fmt.Errorf("write %s: %w", cfgPath, err)
	}
	fmt.Printf("Created %s\nEdit with 'ubo configure' or open in your editor, then run 'ubo run'.\n", cfgPath)
	return nil
}

// loadConfig wraps config.Load with a more helpful error when the file is absent.
func loadConfig(cfgPath string) (*config.Config, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("config file %q not found\nRun 'ubo init' to create one, or 'ubo configure' to open the editor", cfgPath)
		}
		return nil, err
	}
	return cfg, nil
}

// cmdRun configures the remote host.
func cmdRun(ctx context.Context, cfgPath string) error {
	cfg, outDir, err := prepareRun(cfgPath)
	if err != nil {
		return err
	}

	keys, err := keygenGenerateAll(outDir)
	if err != nil {
		return err
	}

	client, err := connectForRun(ctx, cfg, outDir)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := setupConfigure(ctx, client, cfg, keys, outDir); err != nil {
		return err
	}

	// Always save a copy of the config to outDir so that
	// 'ubo unlock <host>' and 'ubo unlock' (picker) find it.
	outCfgPath := filepath.Join(outDir, "ubo.toml")
	if err := config.Save(cfg, outCfgPath); err != nil {
		fmt.Printf("[ubo] warning: could not save config to %s: %v\n", outCfgPath, err)
	}

	readmePath, err := writeRunArtifacts(cfg, keys, outDir, outCfgPath)
	if err != nil {
		return err
	}

	fmt.Printf("\n[ubo] configuration complete!\n")
	fmt.Printf("[ubo] output directory: %s\n", outDir)
	fmt.Printf("[ubo] to unlock on next boot: ubo unlock %s\n", cfg.Host)
	fmt.Printf("[ubo] see %s for manual instructions\n", readmePath)
	return nil
}

// prepareRun loads (or bootstraps) the config, validates it, checks tools,
// and creates the output directory.
func prepareRun(cfgPath string) (*config.Config, string, error) {
	cfg, err := loadOrBootstrap(cfgPath)
	if err != nil {
		return nil, "", err
	}
	if err := cfg.Validate(); err != nil {
		return nil, "", fmt.Errorf("config: %w", err)
	}
	if err := checkTools("run"); err != nil {
		return nil, "", err
	}
	outDir := cfg.OutputDir()
	if err := os.MkdirAll(outDir, 0700); err != nil {
		return nil, "", fmt.Errorf("create output dir %s: %w", outDir, err)
	}
	fmt.Printf("[ubo] output directory: %s\n", outDir)
	return cfg, outDir, nil
}

// loadOrBootstrap returns a Config. When cfgPath is non-empty it is loaded
// directly (error if absent or invalid). When cfgPath is empty it tries
// ./ubo.toml; if that is absent it falls back to an interactive prompt.
func loadOrBootstrap(cfgPath string) (*config.Config, error) {
	if cfgPath != "" {
		return loadConfig(cfgPath)
	}
	cfg, err := config.Load("ubo.toml")
	if err == nil {
		return cfg, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("load config ubo.toml: %w", err)
	}
	return bootstrapConfigFn()
}

// bootstrapConfig interactively prompts for the minimum required fields and
// returns a Config with all other fields set to defaults.
func bootstrapConfig() (*config.Config, error) {
	fmt.Fprintln(os.Stderr, "[ubo] no config file found — enter connection details to continue")
	fmt.Fprintln(os.Stderr)
	r := bufio.NewReader(os.Stdin)
	cfg := config.Default()

	host, err := promptRequired(r, "  Server host/IP: ")
	if err != nil {
		return nil, err
	}
	cfg.Host = host

	user, err := promptLine(r, "SSH user", cfg.SSH.User)
	if err != nil {
		return nil, err
	}
	cfg.SSH.User = user

	portStr, err := promptLine(r, "SSH port", fmt.Sprintf("%d", cfg.SSH.Port))
	if err != nil {
		return nil, err
	}
	if _, scanErr := fmt.Sscanf(portStr, "%d", &cfg.SSH.Port); scanErr != nil {
		return nil, fmt.Errorf("invalid SSH port %q", portStr)
	}

	key, err := promptLine(r, "SSH private key path (blank = agent/default keys)", "")
	if err != nil {
		return nil, err
	}
	cfg.SSH.Key = key

	fmt.Fprintln(os.Stderr)
	return cfg, nil
}

// promptRequired prints prompt to stderr and reads a non-empty line, looping
// until the user provides one.
func promptRequired(r *bufio.Reader, prompt string) (string, error) {
	for {
		fmt.Fprint(os.Stderr, prompt)
		line, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		if v := strings.TrimSpace(line); v != "" {
			return v, nil
		}
	}
}

// promptLine prints "  <label> [<def>]: " to stderr and returns def when the
// user enters nothing. def may be empty for optional fields.
func promptLine(r *bufio.Reader, label, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(os.Stderr, "  %s [%s]: ", label, def)
	} else {
		fmt.Fprintf(os.Stderr, "  %s: ", label)
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return def, err
	}
	if v := strings.TrimSpace(line); v != "" {
		return v, nil
	}
	return def, nil
}

// resolveUnlockConfig finds a config path when --config is not given.
// args[0], if present, is treated as a host/IP and ./ubo-<host>/ubo.toml is
// returned. Otherwise all ubo-*/ubo.toml directories in the current directory
// are found; a single match is auto-selected; multiple matches prompt a list.
func resolveUnlockConfig(args []string) (string, error) {
	if len(args) > 0 {
		return findConfigByHost(args[0])
	}
	return pickUnlockConfig()
}

// findConfigByHost returns the path ./ubo-<host>/ubo.toml if it exists.
func findConfigByHost(host string) (string, error) {
	p := filepath.Join("ubo-"+host, "ubo.toml")
	if _, err := os.Stat(p); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("no output directory found for %q (looked for ./%s)\nRun 'ubo run' to configure this host first",
		host, filepath.Dir(p))
}

// pickUnlockConfig scans for ubo-*/ubo.toml in the current directory.
// One match: auto-selected. Multiple: numbered prompt. None: error.
func pickUnlockConfig() (string, error) {
	matches, _ := filepath.Glob("ubo-*/ubo.toml")
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no ubo output directories found in the current directory\n" +
			"Run 'ubo run' to configure a system first, or use 'ubo unlock --config FILE'")
	case 1:
		fmt.Printf("[ubo] using %s\n", filepath.Dir(matches[0]))
		return matches[0], nil
	default:
		return promptSelectConfig(matches)
	}
}

// promptSelectConfig prints a numbered list of host dirs and returns the chosen
// config path. Pressing Enter selects the first entry.
func promptSelectConfig(configs []string) (string, error) {
	fmt.Println("Available systems:")
	for i, p := range configs {
		fmt.Printf("  %d) %s\n", i+1, strings.TrimPrefix(filepath.Dir(p), "ubo-"))
	}
	fmt.Fprintf(os.Stderr, "\nSelect [1-%d]: ", len(configs))
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read selection: %w", err)
	}
	s := strings.TrimSpace(line)
	if s == "" {
		s = "1"
	}
	var idx int
	if _, scanErr := fmt.Sscanf(s, "%d", &idx); scanErr != nil || idx < 1 || idx > len(configs) {
		return "", fmt.Errorf("invalid selection %q (choose 1-%d)", s, len(configs))
	}
	return configs[idx-1], nil
}

// connectForRun opens the TOFU SSH connection to the remote host for cmdRun
// and, when ssh.sudo is enabled, verifies sudo access (probing for passwordless
// NOPASSWD first, then prompting interactively if needed).
func connectForRun(ctx context.Context, cfg *config.Config, outDir string) (*remote.Client, error) {
	fmt.Printf("[ubo] connecting to %s:%d as %s...\n", cfg.Host, cfg.SSH.Port, cfg.SSH.User)
	client, err := remoteConnect(ctx, &remote.ConnectOptions{
		Host:           cfg.Host,
		Port:           cfg.SSH.Port,
		User:           cfg.SSH.User,
		KeyPath:        cfg.SSH.Key,
		KnownHostsPath: filepath.Join(outDir, "ssh_known_hosts"),
		Sudo:           cfg.SSH.Sudo,
		ProxyJump:      cfg.SSH.ProxyJump,
	})
	if err != nil {
		return nil, err
	}
	if err := ensureSudo(ctx, client, cfg); err != nil {
		client.Close()
		return nil, err
	}
	return client, nil
}

// ensureSudo verifies sudo access when ssh.sudo is true. It first probes
// passwordless sudo (`-n`); if that fails it prompts once for the password,
// stores it in the client for the session, and verifies it before continuing.
// When ssh.sudo is false the function is a no-op so existing root-login configs
// are completely unaffected.
func ensureSudo(ctx context.Context, client *remote.Client, cfg *config.Config) error {
	if !cfg.SSH.Sudo {
		return nil
	}
	if err := sudoProbe(ctx, client); err == nil {
		fmt.Println("[ubo] sudo: passwordless access confirmed")
		return nil
	}
	pw, err := readSudoPassword(fmt.Sprintf("[ubo] sudo password for %s@%s: ", cfg.SSH.User, cfg.Host))
	if err != nil {
		return fmt.Errorf("read sudo password: %w", err)
	}
	client.SetSudoPassword(pw)
	if err := sudoProbe(ctx, client); err != nil {
		return fmt.Errorf("sudo authentication failed: %w", err)
	}
	fmt.Println("[ubo] sudo: password accepted")
	return nil
}

// readSudoPasswordTTY is the real implementation of readSudoPassword: it
// disables terminal echo via stty, reads one line from stdin, and restores echo.
func readSudoPasswordTTY(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	off := exec.Command("stty", "-echo")
	off.Stdin = os.Stdin
	_ = off.Run()
	defer func() {
		on := exec.Command("stty", "echo")
		on.Stdin = os.Stdin
		_ = on.Run()
		fmt.Fprintln(os.Stderr)
	}()
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

// writeRunArtifacts writes the local client WireGuard config and README produced
// by 'ubo run' and returns the README path.
func writeRunArtifacts(cfg *config.Config, keys *keygen.Keys, outDir, cfgPath string) (string, error) {
	serverTunnelIP := cfg.WGServerTunnelIP()
	wgClient := templates.WireGuardClientConfig{
		PrivateKey:      keys.ClientWGPrivate,
		Address:         cfg.WireGuard.ClientIP,
		ServerPublicKey: keys.ServerWGPublic,
		ServerEndpoint:  wgEndpoint(cfg.Host, cfg.WireGuard.Port),
		AllowedIPs:      serverTunnelIP + "/32",
	}
	wgClientINI, err := wgClient.MarshalINI()
	if err != nil {
		return "", fmt.Errorf("render client WireGuard config: %w", err)
	}
	wgClientPath := filepath.Join(outDir, "client_wg.conf")
	if err := os.WriteFile(wgClientPath, []byte(wgClientINI), 0600); err != nil {
		return "", fmt.Errorf("write %s: %w", wgClientPath, err)
	}

	readme := templates.RenderReadme(templates.ReadmeTmplData{
		ServerTunnelIP: serverTunnelIP,
		DropbearPort:   cfg.Dropbear.Port,
		ConfigPath:     cfgPath,
	})
	readmePath := filepath.Join(outDir, "README.txt")
	if err := os.WriteFile(readmePath, []byte(readme), 0644); err != nil {
		return "", fmt.Errorf("write %s: %w", readmePath, err)
	}
	return readmePath, nil
}

// statusFile names a file expected in the output directory and whether its
// presence is required for unlock to be possible.
type statusFile struct {
	name              string
	requiredForUnlock bool
}

// unlockArtifacts are the files cmdUnlock needs; the rest are produced by run
// but not strictly required to unlock.
var statusArtifacts = []statusFile{
	{"server_wg_private.key", false},
	{"server_wg_public.key", false},
	{"client_wg_private.key", false},
	{"client_wg_public.key", false},
	{"client_auth_ed25519", true},
	{"client_auth_ed25519.pub", false},
	{"dropbear_host_key.pub", true},
	{"client_wg.conf", true},
	{"README.txt", false},
}

// statusReport inspects outDir and returns, for each expected artifact, whether
// it is present, plus an overall readiness flag (true only when every file
// required for unlock is present).
func statusReport(outDir string) (ready bool, present map[string]bool) {
	present = make(map[string]bool, len(statusArtifacts))
	ready = true
	for _, a := range statusArtifacts {
		_, err := os.Stat(filepath.Join(outDir, a.name))
		ok := err == nil
		present[a.name] = ok
		if a.requiredForUnlock && !ok {
			ready = false
		}
	}
	return ready, present
}

// cmdStatus reports whether the output directory contains the artifacts that
// 'ubo run' produces and whether 'ubo unlock' can proceed. It is local-only and
// makes no network connections.
func cmdStatus(cfgPath string) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	outDir := cfg.OutputDir()
	fmt.Printf("[ubo] host:           %s\n", cfg.Host)
	fmt.Printf("[ubo] output dir:     %s\n", outDir)

	if _, err := os.Stat(outDir); err != nil {
		fmt.Printf("[ubo] not configured: output dir does not exist\n")
		fmt.Printf("[ubo] run 'ubo run --config %s' to configure the target\n", cfgPath)
		return nil
	}

	ready, present := statusReport(outDir)
	printArtifactList(present)

	if ready {
		fmt.Printf("\n[ubo] ready to unlock: ubo unlock %s\n", cfg.Host)
	} else {
		fmt.Printf("\n[ubo] not ready to unlock — missing required artifacts\n")
		fmt.Printf("[ubo] run 'ubo run --config %s' to (re)configure the target\n", cfgPath)
	}
	return nil
}

// printArtifactList prints each expected artifact with a present/absent mark and
// a note when it is required for unlock.
func printArtifactList(present map[string]bool) {
	fmt.Println("[ubo] artifacts:")
	for _, a := range statusArtifacts {
		mark := "✗"
		if present[a.name] {
			mark = "✓"
		}
		req := ""
		if a.requiredForUnlock {
			req = "  (required for unlock)"
		}
		fmt.Printf("        %s %s%s\n", mark, a.name, req)
	}
}

// cmdUnlock loads config, checks artifacts, and unlocks using the userspace
// WireGuard path (wireguard-go netstack). No root required.
func cmdUnlock(ctx context.Context, cfgPath string, changeKey bool) error {
	cfg, err := loadUnlockConfig(cfgPath)
	if err != nil {
		return err
	}
	outDir := cfg.OutputDir()
	if err := requireUnlockFiles(
		filepath.Join(outDir, "client_wg.conf"),
		filepath.Join(outDir, "client_auth_ed25519"),
		filepath.Join(outDir, "dropbear_host_key.pub"),
	); err != nil {
		return err
	}
	fmt.Println("[ubo] using userspace WireGuard (wireguard-go netstack)...")
	return userspaceUnlock(ctx, cfg, outDir, changeKey)
}

// loadUnlockConfig loads and validates the config. Privilege and tool checks
// are done in cmdUnlock after the path (kernel vs userspace) is chosen.
func loadUnlockConfig(cfgPath string) (*config.Config, error) {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

// requireUnlockFiles ensures every artifact cmdUnlock depends on exists.
func requireUnlockFiles(paths ...string) error {
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("missing file %s\nRun 'ubo run' to configure the target first", p)
		}
	}
	return nil
}

// wgEndpoint formats a WireGuard endpoint as host:port, bracketing IPv6 addresses.
func wgEndpoint(host string, port int) string {
	if strings.Contains(host, ":") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}
