package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
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

const usage = `ubo — Unlock Before Operation

Configure a Debian 13.5 system for remote LUKS unlock via WireGuard + Dropbear.

Usage:
  ubo [subcommand] [--config FILE]

Subcommands:
  configure      Open interactive TUI to create or edit config (default: ./ubo.toml)
  init           Write a default config file non-interactively
  run            Configure the remote host — generates keys, installs WireGuard+Dropbear
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
	sub := "run"
	if len(args) > 0 && !isFlag(args[0]) {
		sub = args[0]
		args = args[1:]
		// "unlock change" is a two-word subcommand
		if sub == "unlock" && len(args) > 0 && args[0] == "change" {
			sub = "unlock-change"
			args = args[1:]
		}
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

	ctx := context.Background()

	switch sub {
	case "configure":
		return tui.Run(*cfgPath)
	case "init":
		return cmdInit(*cfgPath)
	case "run":
		return cmdRun(ctx, *cfgPath)
	case "unlock":
		return cmdUnlock(ctx, *cfgPath, false)
	case "unlock-change":
		return cmdUnlock(ctx, *cfgPath, true)
	case "help", "--help", "-h":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("unknown subcommand %q\nRun 'ubo help' for usage", sub)
	}
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

// cmdRun configures the remote host.
func cmdRun(ctx context.Context, cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := checker.CheckTools("run"); err != nil {
		return err
	}

	outDir := cfg.OutputDir()
	if err := os.MkdirAll(outDir, 0700); err != nil {
		return fmt.Errorf("create output dir %s: %w", outDir, err)
	}
	fmt.Printf("[ubo] output directory: %s\n", outDir)

	// Generate all keys locally
	keys, err := keygen.GenerateAll(outDir)
	if err != nil {
		return err
	}

	// Connect to remote host (TOFU: save host key on first connect)
	fmt.Printf("[ubo] connecting to %s:%d as %s...\n", cfg.Host, cfg.SSH.Port, cfg.SSH.User)
	client, err := remote.Connect(ctx, &remote.ConnectOptions{
		Host:           cfg.Host,
		Port:           cfg.SSH.Port,
		User:           cfg.SSH.User,
		KeyPath:        cfg.SSH.Key,
		KnownHostsPath: filepath.Join(outDir, "ssh_known_hosts"),
	})
	if err != nil {
		return err
	}
	defer client.Close()

	// Run all 11 setup steps on the remote
	if err := setup.Configure(ctx, client, cfg, keys, outDir); err != nil {
		return err
	}

	// Write client WireGuard config locally
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
		return fmt.Errorf("render client WireGuard config: %w", err)
	}
	wgClientPath := filepath.Join(outDir, "client_wg.conf")
	if err := os.WriteFile(wgClientPath, []byte(wgClientINI), 0600); err != nil {
		return fmt.Errorf("write %s: %w", wgClientPath, err)
	}

	// Write README
	readme, err := templates.RenderReadme(templates.ReadmeTmplData{
		ServerTunnelIP: serverTunnelIP,
		DropbearPort:   cfg.Dropbear.Port,
		ConfigPath:     cfgPath,
	})
	if err != nil {
		return fmt.Errorf("render README: %w", err)
	}
	readmePath := filepath.Join(outDir, "README.txt")
	if err := os.WriteFile(readmePath, []byte(readme), 0644); err != nil {
		return fmt.Errorf("write %s: %w", readmePath, err)
	}

	fmt.Printf("\n[ubo] configuration complete!\n")
	fmt.Printf("[ubo] output directory: %s\n", outDir)
	fmt.Printf("[ubo] to unlock on next boot: sudo ubo unlock --config %s\n", cfgPath)
	fmt.Printf("[ubo] see %s for manual instructions\n", readmePath)
	return nil
}

// cmdUnlock brings up the WireGuard tunnel, connects to Dropbear, and unlocks.
// If changeKey is true it runs cryptsetup luksChangeKey first.
func cmdUnlock(ctx context.Context, cfgPath string, changeKey bool) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := checker.CheckTools("unlock"); err != nil {
		return err
	}
	if os.Getuid() != 0 {
		return fmt.Errorf("unlock requires root privileges\nRun: sudo ubo unlock --config %s", cfgPath)
	}

	outDir := cfg.OutputDir()
	wgConfigPath := filepath.Join(outDir, "client_wg.conf")
	sshKeyPath := filepath.Join(outDir, "client_auth_ed25519")
	pinnedKeyPath := filepath.Join(outDir, "dropbear_host_key.pub")

	for _, p := range []string{wgConfigPath, sshKeyPath, pinnedKeyPath} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("missing file %s\nRun 'ubo run' to configure the target first", p)
		}
	}

	// Bring up WireGuard tunnel
	fmt.Println("[ubo] bringing up WireGuard tunnel...")
	wgUp := exec.CommandContext(ctx, "wg-quick", "up", wgConfigPath)
	wgUp.Stdout = os.Stdout
	wgUp.Stderr = os.Stderr
	if err := wgUp.Run(); err != nil {
		return fmt.Errorf("wg-quick up: %w", err)
	}
	// Always tear down on exit
	defer func() {
		fmt.Println("[ubo] tearing down WireGuard tunnel...")
		cmd := exec.Command("wg-quick", "down", wgConfigPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run() //nolint:errcheck
	}()

	// Wait for tunnel
	serverTunnelIP := cfg.WGServerTunnelIP()
	fmt.Printf("[ubo] waiting for tunnel to %s...\n", serverTunnelIP)
	if err := waitForTunnel(serverTunnelIP, 10); err != nil {
		return err
	}

	// Connect to Dropbear with pinned host key
	fmt.Printf("[ubo] connecting to Dropbear at %s:%d...\n", serverTunnelIP, cfg.Dropbear.Port)
	client, err := remote.Connect(ctx, &remote.ConnectOptions{
		Host:          serverTunnelIP,
		Port:          cfg.Dropbear.Port,
		User:          "root",
		KeyPath:       sshKeyPath,
		PinnedKeyPath: pinnedKeyPath,
	})
	if err != nil {
		return fmt.Errorf("connect to Dropbear: %w", err)
	}
	defer client.Close()

	if changeKey {
		luksDevice := cfg.LUKS.Device
		var changeCmd string
		if luksDevice != "" {
			changeCmd = fmt.Sprintf("cryptsetup luksChangeKey %q", luksDevice)
		} else {
			changeCmd = `DEVICE=$(awk 'NF && !/^#/{print $2; exit}' /etc/crypttab) && cryptsetup luksChangeKey "$DEVICE"`
		}

		fmt.Println("[ubo] changing LUKS passphrase (enter current passphrase, then new passphrase twice)...")
		if err := remote.InteractiveSession(client, changeCmd); err != nil {
			return fmt.Errorf("luksChangeKey: %w", err)
		}

		fmt.Print("\nChange complete. Unlock and boot now? [Y/n]: ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "" && answer != "y" {
			fmt.Println("[ubo] not unlocking; the WireGuard tunnel will be torn down")
			return nil
		}
	}

	fmt.Println("[ubo] unlocking disk (enter LUKS passphrase when prompted)...")
	if err := remote.InteractiveSession(client, "cryptroot-unlock"); err != nil {
		return fmt.Errorf("cryptroot-unlock: %w", err)
	}

	fmt.Println("[ubo] unlock complete")
	return nil
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
