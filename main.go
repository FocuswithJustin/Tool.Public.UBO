package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"ubo/internal/checker"
	"ubo/internal/config"
	"ubo/internal/keygen"
	"ubo/internal/remote"
	"ubo/internal/setup"
	"ubo/internal/templates"
	"ubo/internal/tui"
)

// Seams: indirections over the few non-deterministic / external operations in
// the unlock flow, so cmdUnlock can be exercised end-to-end in unit tests
// without root, a real WireGuard tunnel, or a live Dropbear server. Production
// code uses the real implementations assigned here; tests reassign them.
var (
	osGetuid                     = os.Getuid
	remoteConnect                = remote.Connect
	interactiveSession           = remote.InteractiveSession
	waitForTunnelFn              = waitForTunnel
	keygenGenerateAll            = keygen.GenerateAll
	setupConfigure               = setup.Configure
	checkTools                   = checker.CheckTools
	tuiRun                       = tui.Run
	unlockStdin        io.Reader = os.Stdin

	// sudoProbe runs a trivial remote command to test whether passwordless sudo
	// (-n) works. Seamed so tests can stub it without a real SSH connection.
	sudoProbe = func(ctx context.Context, c *remote.Client) error {
		_, err := remote.RunCommand(ctx, c, "true")
		return err
	}

	// readSudoPassword prompts the operator for a sudo password with echo
	// suppressed. Seamed so tests can inject a fixed password.
	readSudoPassword = readSudoPasswordTTY

	wgQuickUp = func(ctx context.Context, cfgPath string) error {
		cmd := exec.CommandContext(ctx, "wg-quick", "up", cfgPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	wgQuickDown = func(cfgPath string) error {
		cmd := exec.Command("wg-quick", "down", cfgPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
)

const usage = `ubo — Unlock Before Operation

Configure a Debian 13.5 system for remote LUKS unlock via WireGuard + Dropbear.

Usage:
  ubo [subcommand] [--config FILE]

Subcommands:
  configure      Open interactive TUI to create or edit config (default: ./ubo.toml)
  init           Write a default config file non-interactively
  run            Configure the remote host — generates keys, installs WireGuard+Dropbear
  status         Report whether the output dir is configured and ready to unlock
  unlock         Bring up WireGuard, SSH to Dropbear, unlock disk, tear down tunnel
  unlock change  Change LUKS passphrase, then optionally unlock

Flags:
  --config FILE  Config file path (default: ./ubo.toml)
  --help         Show this help

Run 'ubo init' to generate a starting config, then 'ubo configure' to edit it.
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

	// All subcommands share --config
	fs := flag.NewFlagSet(sub, flag.ContinueOnError)
	cfgPath := fs.String("config", "ubo.toml", "config file path")
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
	return run(context.Background(), *cfgPath)
}

// subcommands maps each subcommand name to its handler. Handlers share a common
// signature so dispatch can invoke them from a table.
var subcommands = map[string]func(ctx context.Context, cfgPath string) error{
	"configure": func(_ context.Context, cfgPath string) error { return tuiRun(cfgPath) },
	"init":      func(_ context.Context, cfgPath string) error { return cmdInit(cfgPath) },
	"run":       cmdRun,
	"status":    func(_ context.Context, cfgPath string) error { return cmdStatus(cfgPath) },
	"unlock":    func(ctx context.Context, cfgPath string) error { return cmdUnlock(ctx, cfgPath, false) },
	"unlock-change": func(ctx context.Context, cfgPath string) error {
		return cmdUnlock(ctx, cfgPath, true)
	},
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

	// Generate all keys locally
	keys, err := keygenGenerateAll(outDir)
	if err != nil {
		return err
	}

	client, err := connectForRun(ctx, cfg, outDir)
	if err != nil {
		return err
	}
	defer client.Close()

	// Run all 11 setup steps on the remote
	if err := setupConfigure(ctx, client, cfg, keys, outDir); err != nil {
		return err
	}

	readmePath, err := writeRunArtifacts(cfg, keys, outDir, cfgPath)
	if err != nil {
		return err
	}

	fmt.Printf("\n[ubo] configuration complete!\n")
	fmt.Printf("[ubo] output directory: %s\n", outDir)
	fmt.Printf("[ubo] to unlock on next boot: sudo ubo unlock --config %s\n", cfgPath)
	fmt.Printf("[ubo] see %s for manual instructions\n", readmePath)
	return nil
}

// prepareRun loads and validates the config, checks required tools, and creates
// the output directory, returning the config and output dir for cmdRun.
func prepareRun(cfgPath string) (*config.Config, string, error) {
	cfg, err := loadConfig(cfgPath)
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
		ServerEndpoint:  fmt.Sprintf("%s:%d", cfg.Host, cfg.WireGuard.Port),
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

	readme, err := templates.RenderReadme(templates.ReadmeTmplData{
		ServerTunnelIP: serverTunnelIP,
		DropbearPort:   cfg.Dropbear.Port,
		ConfigPath:     cfgPath,
	})
	if err != nil {
		return "", fmt.Errorf("render README: %w", err)
	}
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
		fmt.Printf("\n[ubo] ready to unlock: sudo ubo unlock --config %s\n", cfgPath)
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

// cmdUnlock brings up the WireGuard tunnel, connects to Dropbear, and unlocks.
// If changeKey is true it runs cryptsetup luksChangeKey first.
func cmdUnlock(ctx context.Context, cfgPath string, changeKey bool) error {
	cfg, err := loadUnlockConfig(cfgPath)
	if err != nil {
		return err
	}

	outDir := cfg.OutputDir()
	wgConfigPath := filepath.Join(outDir, "client_wg.conf")
	sshKeyPath := filepath.Join(outDir, "client_auth_ed25519")
	pinnedKeyPath := filepath.Join(outDir, "dropbear_host_key.pub")

	if err := requireUnlockFiles(wgConfigPath, sshKeyPath, pinnedKeyPath); err != nil {
		return err
	}

	// Bring up WireGuard tunnel
	fmt.Println("[ubo] bringing up WireGuard tunnel...")
	if err := wgQuickUp(ctx, wgConfigPath); err != nil {
		return fmt.Errorf("wg-quick up: %w", err)
	}
	// Always tear down on exit (registered before the wait so teardown still
	// runs if the tunnel never becomes reachable).
	defer tearDownTunnel(wgConfigPath)

	serverTunnelIP := cfg.WGServerTunnelIP()
	fmt.Printf("[ubo] waiting for tunnel to %s...\n", serverTunnelIP)
	if err := waitForTunnelFn(serverTunnelIP, 10); err != nil {
		return err
	}

	client, err := connectDropbear(ctx, cfg, serverTunnelIP, sshKeyPath, pinnedKeyPath)
	if err != nil {
		return err
	}
	defer client.Close()

	return performUnlock(client, cfg, changeKey)
}

// performUnlock optionally changes the LUKS passphrase and then unlocks the disk
// over an established Dropbear connection.
func performUnlock(client *remote.Client, cfg *config.Config, changeKey bool) error {
	if changeKey {
		proceed, err := runChangeKey(client, cfg)
		if err != nil {
			return err
		}
		if !proceed {
			return nil
		}
	}

	fmt.Println("[ubo] unlocking disk (enter LUKS passphrase when prompted)...")
	// cryptroot-unlock already loops through all crypttab entries with
	// x-initrd.attach, so multi-LUKS hosts with sequential prompts are handled
	// automatically by this single interactive session.
	if err := interactiveSession(client, "cryptroot-unlock"); err != nil {
		return fmt.Errorf("cryptroot-unlock: %w", err)
	}

	fmt.Println("[ubo] unlock complete")
	return nil
}

// loadUnlockConfig loads and validates the config and enforces the tool and root
// preconditions shared by every unlock invocation.
func loadUnlockConfig(cfgPath string) (*config.Config, error) {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := checkTools("unlock"); err != nil {
		return nil, err
	}
	if osGetuid() != 0 {
		return nil, fmt.Errorf("unlock requires root privileges\nRun: sudo ubo unlock --config %s", cfgPath)
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

// connectDropbear opens the SSH connection to Dropbear over the tunnel using the
// pinned host key.
func connectDropbear(ctx context.Context, cfg *config.Config, serverTunnelIP, sshKeyPath, pinnedKeyPath string) (*remote.Client, error) {
	fmt.Printf("[ubo] connecting to Dropbear at %s:%d...\n", serverTunnelIP, cfg.Dropbear.Port)
	client, err := remoteConnect(ctx, &remote.ConnectOptions{
		Host:          serverTunnelIP,
		Port:          cfg.Dropbear.Port,
		User:          "root",
		KeyPath:       sshKeyPath,
		PinnedKeyPath: pinnedKeyPath,
	})
	if err != nil {
		return nil, fmt.Errorf("connect to Dropbear: %w", err)
	}
	return client, nil
}

// tearDownTunnel lowers the WireGuard tunnel, warning (but not failing) on error.
func tearDownTunnel(wgConfigPath string) {
	fmt.Println("[ubo] tearing down WireGuard tunnel...")
	if err := wgQuickDown(wgConfigPath); err != nil {
		fmt.Fprintf(os.Stderr, "[ubo] warning: wg-quick down failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "[ubo] you may need to run manually: sudo wg-quick down %s\n", wgConfigPath)
	}
}

// crypttabChangeKeyCmd resolves the first LUKS backing device from /etc/crypttab
// to a usable device path before running cryptsetup luksChangeKey. crypttab
// field 2 is commonly a tag form (UUID=, PARTUUID=, LABEL=, PARTLABEL=) that
// cryptsetup rejects directly, so each tag is mapped to its /dev/disk/by-* path.
const crypttabChangeKeyCmd = `SRC=$(awk 'NF && !/^#/{print $2; exit}' /etc/crypttab)
case "$SRC" in
  UUID=*) DEV="/dev/disk/by-uuid/${SRC#UUID=}" ;;
  PARTUUID=*) DEV="/dev/disk/by-partuuid/${SRC#PARTUUID=}" ;;
  LABEL=*) DEV="/dev/disk/by-label/${SRC#LABEL=}" ;;
  PARTLABEL=*) DEV="/dev/disk/by-partlabel/${SRC#PARTLABEL=}" ;;
  *) DEV="$SRC" ;;
esac
test -n "$DEV" || { echo "could not determine LUKS device from /etc/crypttab" >&2; exit 1; }
cryptsetup luksChangeKey "$DEV"`

// runChangeKey performs the interactive LUKS passphrase change and asks whether
// to continue to unlock. It returns whether the caller should proceed to unlock.
func runChangeKey(client *remote.Client, cfg *config.Config) (bool, error) {
	changeCmd := crypttabChangeKeyCmd
	if cfg.LUKS.Device != "" {
		changeCmd = fmt.Sprintf("cryptsetup luksChangeKey %q", cfg.LUKS.Device)
	}

	fmt.Println("[ubo] changing LUKS passphrase (enter current passphrase, then new passphrase twice)...")
	if err := interactiveSession(client, changeCmd); err != nil {
		return false, fmt.Errorf("luksChangeKey: %w", err)
	}

	fmt.Print("\nChange complete. Unlock and boot now? [Y/n]: ")
	reader := bufio.NewReader(unlockStdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer != "" && answer != "y" {
		fmt.Println("[ubo] not unlocking; the WireGuard tunnel will be torn down")
		return false, nil
	}
	return true, nil
}

// waitForTunnel pings ip once per second for up to maxSec seconds.
func waitForTunnel(ip string, maxSec int) error {
	for i := 0; i < maxSec; i++ {
		cmd := exec.Command("ping", "-c", "1", "-W", "1", ip)
		cmd.Stdout = nil
		cmd.Stderr = nil
		if cmd.Run() == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("tunnel to %s did not become reachable after %d seconds", ip, maxSec)
}
