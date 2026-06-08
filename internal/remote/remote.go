package remote

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ConnectOptions configures an SSH connection.
type ConnectOptions struct {
	Host    string
	Port    int
	User    string
	KeyPath string // explicit SSH private key; empty = try agent + default keys

	// Exactly one of the following should be set:
	KnownHostsPath string // TOFU: accept and save host key here on first connection
	PinnedKeyPath  string // Strict: verify host key matches this authorized_keys-format file
}

// Connect establishes an SSH connection using the provided options.
func Connect(ctx context.Context, opts *ConnectOptions) (*ssh.Client, error) {
	auths, err := buildAuthMethods(opts.KeyPath)
	if err != nil {
		return nil, err
	}
	if len(auths) == 0 {
		return nil, fmt.Errorf("no SSH auth methods available; set ssh.key in ubo.toml")
	}

	hostKeyCallback, err := buildHostKeyCallback(opts)
	if err != nil {
		return nil, err
	}

	addr := fmt.Sprintf("%s:%d", opts.Host, opts.Port)

	dialer := &net.Dialer{}
	netConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}

	sshCfg := &ssh.ClientConfig{
		User:            opts.User,
		Auth:            auths,
		HostKeyCallback: hostKeyCallback,
		Timeout:         30 * time.Second,
	}

	conn, chans, reqs, err := ssh.NewClientConn(netConn, addr, sshCfg)
	if err != nil {
		netConn.Close()
		return nil, fmt.Errorf("SSH handshake with %s: %w", addr, err)
	}

	return ssh.NewClient(conn, chans, reqs), nil
}

func buildAuthMethods(keyPath string) ([]ssh.AuthMethod, error) {
	var auths []ssh.AuthMethod

	if keyPath != "" {
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read SSH key %s: %w", keyPath, err)
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse SSH key %s: %w", keyPath, err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
		return auths, nil
	}

	// Try SSH agent
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
		}
	}

	// Try default key files
	homeDir, _ := os.UserHomeDir()
	for _, name := range []string{"id_ed25519", "id_rsa", "id_ecdsa"} {
		data, err := os.ReadFile(filepath.Join(homeDir, ".ssh", name))
		if err != nil {
			continue
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			continue
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}

	return auths, nil
}

func buildHostKeyCallback(opts *ConnectOptions) (ssh.HostKeyCallback, error) {
	// Strict: verify against pinned public key
	if opts.PinnedKeyPath != "" {
		data, err := os.ReadFile(opts.PinnedKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read pinned host key %s: %w", opts.PinnedKeyPath, err)
		}
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse pinned host key: %w", err)
		}
		return ssh.FixedHostKey(pubKey), nil
	}

	// TOFU: save on first connection, verify on subsequent connections
	if opts.KnownHostsPath != "" {
		return toFUCallback(opts.KnownHostsPath), nil
	}

	// Fallback: accept any host key (used only when neither option is set)
	return ssh.InsecureIgnoreHostKey(), nil //nolint:gosec
}

// toFUCallback returns a HostKeyCallback that saves the host key on first
// connection and verifies it on subsequent connections.
func toFUCallback(savePath string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if _, err := os.Stat(savePath); err == nil {
			// File exists — check the key
			cb, err := knownhosts.New(savePath)
			if err != nil {
				return fmt.Errorf("load known_hosts %s: %w", savePath, err)
			}
			return cb(hostname, remote, key)
		}

		// First connection — save and trust
		line := knownhosts.Line([]string{hostname}, key)
		if err := os.WriteFile(savePath, []byte(line+"\n"), 0600); err != nil {
			return fmt.Errorf("save host key: %w", err)
		}
		fmt.Printf("[ubo] trusted host key for %s: %s %s\n",
			hostname, key.Type(), ssh.FingerprintSHA256(key))
		return nil
	}
}

// RunCommand executes cmd on the remote and returns combined stdout+stderr.
func RunCommand(ctx context.Context, client *ssh.Client, cmd string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new SSH session: %w", err)
	}
	defer session.Close()

	// Propagate context cancellation via a goroutine
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			session.Close()
		case <-done:
		}
	}()
	defer close(done)

	out, err := session.CombinedOutput(cmd)
	if err != nil {
		return strings.TrimSpace(string(out)), fmt.Errorf("remote command failed: %w\noutput: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// WriteFile writes content to remotePath on the remote host via SFTP.
// mode is applied to the file after writing.
func WriteFile(client *ssh.Client, remotePath, content string, mode os.FileMode) error {
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("SFTP open: %w", err)
	}
	defer sftpClient.Close()

	// Ensure parent directory exists
	dir := filepath.Dir(remotePath)
	if err := sftpClient.MkdirAll(dir); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	f, err := sftpClient.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return fmt.Errorf("open %s: %w", remotePath, err)
	}
	defer f.Close()

	if _, err := io.WriteString(f, content); err != nil {
		return fmt.Errorf("write %s: %w", remotePath, err)
	}

	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("chmod %s: %w", remotePath, err)
	}

	return nil
}

// WriteFileExec writes content to remotePath and makes it executable (0755).
func WriteFileExec(client *ssh.Client, remotePath, content string) error {
	return WriteFile(client, remotePath, content, 0755)
}

// ReadFile downloads the content of remotePath via SFTP.
func ReadFile(client *ssh.Client, remotePath string) (string, error) {
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return "", fmt.Errorf("SFTP open: %w", err)
	}
	defer sftpClient.Close()

	f, err := sftpClient.Open(remotePath)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", remotePath, err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", remotePath, err)
	}
	return string(data), nil
}

// InteractiveSession opens an SSH session with a PTY and runs cmd interactively,
// wiring stdin/stdout/stderr to the local terminal. Required for cryptroot-unlock
// and cryptsetup luksChangeKey, which both need a real TTY.
func InteractiveSession(client *ssh.Client, cmd string) error {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("new SSH session: %w", err)
	}
	defer session.Close()

	if err := session.RequestPty("xterm-256color", 40, 140, ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		return fmt.Errorf("request PTY: %w", err)
	}

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	if err := session.Run(cmd); err != nil {
		// Exit status 1 from cryptroot-unlock / cryptsetup is a passphrase error,
		// not a connection failure — surface it cleanly.
		return fmt.Errorf("remote session: %w", err)
	}
	return nil
}
