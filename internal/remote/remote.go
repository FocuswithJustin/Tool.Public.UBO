// Package remote performs remote operations by shelling out to the system
// OpenSSH client (the `ssh` binary) via os/exec. It deliberately does NOT
// implement the SSH protocol or any cryptography itself — it invokes the
// OpenSSH client that is already a required system tool. This keeps the module
// free of third-party Go dependencies (standard library only).
package remote

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ConnectOptions configures an SSH connection.
type ConnectOptions struct {
	Host    string
	Port    int
	User    string
	KeyPath string // explicit SSH private key; empty = let ssh use its defaults/agent

	// Exactly one of the following should be set:
	KnownHostsPath string // TOFU: accept-new and save host key here on first connection
	PinnedKeyPath  string // Strict: pin the host key from this authorized_keys-format file

	// Sudo runs remote commands under passwordless sudo. Used when User is a
	// non-root account that is in the sudo group (the unlock-time Dropbear
	// session always runs as root and never needs this).
	Sudo bool

	// ProxyJump, when non-empty, is passed as -o ProxyJump=<value> to ssh.
	// Allows reaching the target through a bastion / jump host.
	// Format: [user@]host[:port]  (same as ssh -J)
	ProxyJump string
}

// Client holds the connection parameters used to invoke the ssh binary. There
// is no persistent connection: each operation spawns a fresh `ssh` process.
type Client struct {
	host         string
	port         int
	user         string
	keyPath      string
	sudo         bool
	sudoPassword string // non-empty means feed via sudo -S instead of -n
	proxyJump    string // passed as -o ProxyJump=<value>; empty = direct

	// knownHostsFile is the file passed to ssh via UserKnownHostsFile.
	knownHostsFile string
	// strictMode is the value passed to ssh via StrictHostKeyChecking
	// ("accept-new" for TOFU, "yes" for pinned).
	strictMode string
	// tempKnownHosts, when non-empty, is a known_hosts file that Connect
	// materialized for pinned mode and that Close() must remove.
	tempKnownHosts string
}

// Connect validates the options and builds a *Client. With the CLI approach
// there is no live session established here: Connect only prepares (and, in
// pinned mode, materializes) the host-key verification settings. Connection
// errors surface on the first real RunCommand/WriteFile/etc.
func Connect(ctx context.Context, opts *ConnectOptions) (*Client, error) {
	if err := validateConnectOptions(opts); err != nil {
		return nil, err
	}

	c := &Client{
		host:      opts.Host,
		port:      opts.Port,
		user:      opts.User,
		keyPath:   opts.KeyPath,
		sudo:      opts.Sudo,
		proxyJump: opts.ProxyJump,
	}

	if err := applyHostKeyMode(c, opts); err != nil {
		return nil, err
	}

	return c, nil
}

// validateConnectOptions checks the required fields and mutually exclusive
// host-key mode selectors on opts.
func validateConnectOptions(opts *ConnectOptions) error {
	if opts == nil {
		return fmt.Errorf("nil connect options")
	}
	if opts.Host == "" {
		return fmt.Errorf("host is required")
	}
	if opts.User == "" {
		return fmt.Errorf("user is required")
	}
	if opts.Port <= 0 {
		return fmt.Errorf("invalid port %d", opts.Port)
	}
	return validateHostKeyModeExclusive(opts)
}

// validateHostKeyModeExclusive rejects setting both host-key mode selectors.
func validateHostKeyModeExclusive(opts *ConnectOptions) error {
	if opts.KnownHostsPath != "" && opts.PinnedKeyPath != "" {
		return fmt.Errorf("set only one of KnownHostsPath or PinnedKeyPath")
	}
	return nil
}

// applyHostKeyMode configures c's host-key verification settings from opts,
// materializing a pinned known_hosts file when in strict mode. Behavior is
// identical to the original inline switch in Connect.
func applyHostKeyMode(c *Client, opts *ConnectOptions) error {
	switch {
	case opts.PinnedKeyPath != "":
		// Strict mode: materialize a known_hosts file from the pinned key now,
		// so a bad pinned file is reported at Connect time.
		khFile, err := materializePinnedKnownHosts(opts.Host, opts.Port, opts.PinnedKeyPath)
		if err != nil {
			return err
		}
		c.knownHostsFile = khFile
		c.tempKnownHosts = khFile
		c.strictMode = "yes"
	case opts.KnownHostsPath != "":
		// TOFU mode: accept-new into the caller-provided known_hosts file.
		c.knownHostsFile = opts.KnownHostsPath
		c.strictMode = "accept-new"
	default:
		return fmt.Errorf("set one of KnownHostsPath (TOFU) or PinnedKeyPath (strict)")
	}
	return nil
}

// knownHostsHostname formats the host as it appears in a known_hosts line:
// bare "host" for the default SSH port 22, and "[host]:port" otherwise.
func knownHostsHostname(host string, port int) string {
	if port == 22 {
		return host
	}
	return fmt.Sprintf("[%s]:%d", host, port)
}

// materializePinnedKnownHosts reads an authorized_keys-format pinned host key
// file (a line like `ssh-ed25519 AAAA... comment`) and writes a known_hosts
// file containing a single line `<knownhosts-hostname> <keytype> <keydata>`.
// It returns the path to the written file.
func materializePinnedKnownHosts(host string, port int, pinnedPath string) (string, error) {
	data, err := os.ReadFile(pinnedPath)
	if err != nil {
		return "", fmt.Errorf("read pinned host key %s: %w", pinnedPath, err)
	}

	keyType, keyData, err := parseAuthorizedKey(data)
	if err != nil {
		return "", fmt.Errorf("parse pinned host key %s: %w", pinnedPath, err)
	}

	line := fmt.Sprintf("%s %s %s\n", knownHostsHostname(host, port), keyType, keyData)
	outPath := pinnedPath + ".known_hosts"
	if err := os.WriteFile(outPath, []byte(line), 0600); err != nil {
		return "", fmt.Errorf("write known_hosts %s: %w", outPath, err)
	}
	return outPath, nil
}

// parseAuthorizedKey extracts the key type and base64 key data from the first
// non-comment, non-empty line of an authorized_keys-format file. The optional
// comment field is ignored. It does not validate the base64 cryptographically;
// it only checks the structural shape so ssh receives a well-formed line.
func parseAuthorizedKey(data []byte) (keyType, keyData string, err error) {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return parseAuthorizedKeyLine(line)
	}
	// scanner.Err on an in-memory strings.Reader cannot fail, so the only way
	// out of the loop is an input with no usable key line.
	return "", "", fmt.Errorf("no key found in pinned file")
}

// parseAuthorizedKeyLine validates a single non-empty, non-comment
// authorized_keys line and returns its key type and base64 key data.
func parseAuthorizedKeyLine(line string) (keyType, keyData string, err error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", "", fmt.Errorf("malformed authorized_keys line: %q", line)
	}
	if !hasKnownKeyTypePrefix(fields[0]) {
		return "", "", fmt.Errorf("unrecognized key type %q", fields[0])
	}
	// strings.Fields never yields an empty field, so fields[1] is non-empty.
	return fields[0], fields[1], nil
}

// hasKnownKeyTypePrefix reports whether field looks like a recognized SSH key
// type token (ssh-*, ecdsa-*, or sk-*).
func hasKnownKeyTypePrefix(field string) bool {
	return strings.HasPrefix(field, "ssh-") ||
		strings.HasPrefix(field, "ecdsa-") ||
		strings.HasPrefix(field, "sk-")
}

// sshArgs builds the common ssh argument list (everything before the remote
// command) shared by all operations.
func (c *Client) sshArgs() []string {
	args := []string{"-p", fmt.Sprintf("%d", c.port)}
	if c.keyPath != "" {
		args = append(args, "-i", c.keyPath)
	}
	if c.proxyJump != "" {
		args = append(args, "-o", "ProxyJump="+c.proxyJump)
	}
	args = append(args,
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=30",
		"-o", "UserKnownHostsFile="+c.knownHostsFile,
		"-o", "StrictHostKeyChecking="+c.strictMode,
		fmt.Sprintf("%s@%s", c.user, c.host),
	)
	return args
}

// SetSudoPassword stores pw so that subsequent commands use `sudo -S` (read
// password from stdin) instead of `sudo -n` (fail if NOPASSWD not configured).
// Call this only after a passwordless probe fails; otherwise leave it unset.
func (c *Client) SetSudoPassword(pw string) { c.sudoPassword = pw }

// sudoCmd wraps cmd for privileged execution. With no password set it uses
// `sudo -n` (non-interactive, fails fast if NOPASSWD is not configured). With a
// password set it uses `sudo -S -p ”` (reads password from stdin silently).
// Single quotes inside cmd are escaped so the outer sh -c argument is valid.
func (c *Client) sudoCmd(cmd string) string {
	if !c.sudo {
		return cmd
	}
	escaped := strings.ReplaceAll(cmd, "'", `'\''`)
	flag := "-n"
	if c.sudoPassword != "" {
		flag = "-S -p ''"
	}
	return "sudo " + flag + " sh -c '" + escaped + "'"
}

// sudoStdin prepends the sudo password line to base when password-mode sudo is
// in use. base may be nil (no process stdin). Returns nil when sudo is inactive
// or NOPASSWD mode is used, leaving the caller's existing stdin handling intact.
func (c *Client) sudoStdin(base io.Reader) io.Reader {
	if !c.sudo || c.sudoPassword == "" {
		return base
	}
	pw := strings.NewReader(c.sudoPassword + "\n")
	if base == nil {
		return pw
	}
	return io.MultiReader(pw, base)
}

// Close removes any temporary known_hosts file materialized for pinned mode.
// It is safe to call multiple times.
func (c *Client) Close() error {
	if c.tempKnownHosts == "" {
		return nil
	}
	path := c.tempKnownHosts
	c.tempKnownHosts = ""
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove temp known_hosts %s: %w", path, err)
	}
	return nil
}

// RunCommand executes cmd on the remote via `ssh` and returns the remote
// command's stdout, trimmed of surrounding whitespace. Stderr is captured
// separately and only surfaced in the error message on failure, so local ssh
// client warnings (e.g. unsupported ssh_config options) never corrupt the
// returned value.
func RunCommand(ctx context.Context, c *Client, cmd string) (string, error) {
	args := append(c.sshArgs(), c.sudoCmd(cmd))
	command := exec.CommandContext(ctx, "ssh", args...)
	command.Stdin = c.sudoStdin(nil)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	out := strings.TrimSpace(stdout.String())
	if err != nil {
		return out, fmt.Errorf("remote command failed: %w\noutput: %s", err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// WriteFile writes content to remotePath on the remote host. It creates the
// parent directory, pipes content to the file via stdin, and applies mode.
// remotePath is single-quoted in the remote snippet; our paths are internal
// constants without single quotes.
func WriteFile(c *Client, remotePath, content string, mode os.FileMode) error {
	octal := fmt.Sprintf("%o", mode.Perm())
	dir := filepath.Dir(remotePath)
	remoteCmd := fmt.Sprintf("mkdir -p '%s' && cat > '%s' && chmod %s '%s'",
		dir, remotePath, octal, remotePath)

	args := append(c.sshArgs(), c.sudoCmd(remoteCmd))
	cmd := exec.Command("ssh", args...)
	cmd.Stdin = c.sudoStdin(strings.NewReader(content))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("write %s: %w\noutput: %s", remotePath, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// WriteFileExec writes content to remotePath and makes it executable (0755).
func WriteFileExec(c *Client, remotePath, content string) error {
	return WriteFile(c, remotePath, content, 0755)
}

// ReadFile returns the raw content of remotePath (no trimming, to match the
// previous SFTP-based behavior which returned bytes faithfully).
func ReadFile(c *Client, remotePath string) (string, error) {
	remoteCmd := fmt.Sprintf("cat '%s'", remotePath)
	args := append(c.sshArgs(), c.sudoCmd(remoteCmd))
	cmd := exec.Command("ssh", args...)
	cmd.Stdin = c.sudoStdin(nil)
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr = strings.TrimSpace(string(exitErr.Stderr))
		}
		return "", fmt.Errorf("open %s: %w\noutput: %s", remotePath, err, stderr)
	}
	return string(out), nil
}

// InteractiveSession runs cmd on the remote with a forced PTY (`ssh -t`),
// wiring the local stdin/stdout/stderr to the ssh process. Required for
// cryptroot-unlock and cryptsetup luksChangeKey, which both need a real TTY.
func InteractiveSession(c *Client, cmd string) error {
	args := []string{"-t", "-o", "LogLevel=ERROR"}
	args = append(args, c.sshArgs()...)
	args = append(args, cmd)

	command := exec.Command("ssh", args...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		// Exit status 1 from cryptroot-unlock / cryptsetup is a passphrase error,
		// not a connection failure — surface it cleanly.
		return fmt.Errorf("remote session: %w", err)
	}
	return nil
}
