package keygen

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

// Keys holds all generated key material for a UBO deployment.
type Keys struct {
	ServerWGPrivate  string
	ServerWGPublic   string
	ClientWGPrivate  string
	ClientWGPublic   string
	ClientSSHKeyPath string // path to the ed25519 private key file
	ClientSSHPubKey  string // authorized_keys-format public key
}

// GenerateAll returns key material for a ubo deployment.
// If all key files already exist in outputDir they are loaded and reused —
// this makes re-running "ubo run" idempotent without invalidating an already-
// deployed client_wg.conf.  Delete the output directory to force fresh keys.
func GenerateAll(outputDir string) (*Keys, error) {
	if keys, err := loadExisting(outputDir); err == nil {
		fmt.Printf("[ubo] reusing existing keys in %s\n", outputDir)
		return keys, nil
	}

	fmt.Println("[ubo] generating server WireGuard keypair...")
	serverPriv, serverPub, err := GenerateWireGuardKeypair("server_wg", outputDir)
	if err != nil {
		return nil, fmt.Errorf("server WireGuard keypair: %w", err)
	}

	fmt.Println("[ubo] generating client WireGuard keypair...")
	clientPriv, clientPub, err := GenerateWireGuardKeypair("client_wg", outputDir)
	if err != nil {
		return nil, fmt.Errorf("client WireGuard keypair: %w", err)
	}

	fmt.Println("[ubo] generating client SSH keypair...")
	keyPath, pubKey, err := GenerateSSHKeypair("client_auth_ed25519", outputDir)
	if err != nil {
		return nil, fmt.Errorf("client SSH keypair: %w", err)
	}

	return &Keys{
		ServerWGPrivate:  serverPriv,
		ServerWGPublic:   serverPub,
		ClientWGPrivate:  clientPriv,
		ClientWGPublic:   clientPub,
		ClientSSHKeyPath: keyPath,
		ClientSSHPubKey:  pubKey,
	}, nil
}

// loadExisting reads all key files from outputDir and returns the Keys, or an
// error if any file is missing or unreadable.
func loadExisting(outputDir string) (*Keys, error) {
	names := []string{
		"server_wg_private.key",
		"server_wg_public.key",
		"client_wg_private.key",
		"client_wg_public.key",
		"client_auth_ed25519.pub",
	}
	vals, err := readTrimmedFiles(outputDir, names)
	if err != nil {
		return nil, err
	}

	sshKeyPath := filepath.Join(outputDir, "client_auth_ed25519")
	if _, err := os.Stat(sshKeyPath); err != nil {
		return nil, err
	}

	return &Keys{
		ServerWGPrivate:  vals[0],
		ServerWGPublic:   vals[1],
		ClientWGPrivate:  vals[2],
		ClientWGPublic:   vals[3],
		ClientSSHKeyPath: sshKeyPath,
		ClientSSHPubKey:  vals[4],
	}, nil
}

// readTrimmedFiles reads each named file in outputDir and returns the
// whitespace-trimmed contents in the same order, or the first read error.
func readTrimmedFiles(outputDir string, names []string) ([]string, error) {
	vals := make([]string, len(names))
	for i, name := range names {
		b, err := os.ReadFile(filepath.Join(outputDir, name))
		if err != nil {
			return nil, err
		}
		vals[i] = strings.TrimSpace(string(b))
	}
	return vals, nil
}

// generateWGPrivateKey returns a fresh WireGuard private key as a base64
// string. The key is a random 32-byte Curve25519 scalar clamped per RFC 7748.
func generateWGPrivateKey() (string, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	// Clamp per RFC 7748 §5 (identical to WireGuard spec).
	key[0] &= 248
	key[31] = (key[31] & 127) | 64
	return base64.StdEncoding.EncodeToString(key[:]), nil
}

// deriveWGPublicKey computes the Curve25519 public key for a base64-encoded
// WireGuard private key.
func deriveWGPublicKey(privateB64 string) (string, error) {
	priv, err := base64.StdEncoding.DecodeString(privateB64)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// GenerateWireGuardKeypair generates a WireGuard keypair entirely in-process
// using crypto/rand and golang.org/x/crypto/curve25519. No external wg binary
// is required.
// Private key is written to <outputDir>/<name>_private.key (mode 0600).
// Public key is written to <outputDir>/<name>_public.key (mode 0644).
func GenerateWireGuardKeypair(name, outputDir string) (privateKey, publicKey string, err error) {
	privPath := filepath.Join(outputDir, name+"_private.key")
	pubPath := filepath.Join(outputDir, name+"_public.key")

	privateKey, err = generateWGPrivateKey()
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(privPath, []byte(privateKey+"\n"), 0600); err != nil {
		return "", "", fmt.Errorf("write %s: %w", privPath, err)
	}

	publicKey, err = deriveWGPublicKey(privateKey)
	if err != nil {
		os.Remove(privPath) //nolint:errcheck
		return "", "", err
	}
	if err := os.WriteFile(pubPath, []byte(publicKey+"\n"), 0644); err != nil {
		os.Remove(privPath) //nolint:errcheck
		return "", "", fmt.Errorf("write %s: %w", pubPath, err)
	}

	return privateKey, publicKey, nil
}

// GenerateSSHKeypair generates an ed25519 SSH keypair entirely in-process
// using crypto/ed25519 and golang.org/x/crypto/ssh. No external ssh-keygen
// binary is required.
// Private key is written to <outputDir>/<name> (mode 0600) in OpenSSH format.
// Returns the private key path and authorized_keys-format public key string.
func GenerateSSHKeypair(name, outputDir string) (keyPath, pubKey string, err error) {
	keyPath = filepath.Join(outputDir, name)
	pubPath := keyPath + ".pub"

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate ed25519 key: %w", err)
	}

	privBlock, err := ssh.MarshalPrivateKey(edPriv, "")
	if err != nil {
		return "", "", fmt.Errorf("marshal private key: %w", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(privBlock), 0600); err != nil {
		return "", "", fmt.Errorf("write %s: %w", keyPath, err)
	}

	sshPub, err := ssh.NewPublicKey(edPub)
	if err != nil {
		os.Remove(keyPath) //nolint:errcheck
		return "", "", fmt.Errorf("marshal public key: %w", err)
	}
	pubKey = strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(sshPub)), "\n") + " ubo-client"

	if err := os.WriteFile(pubPath, []byte(pubKey+"\n"), 0644); err != nil {
		os.Remove(keyPath) //nolint:errcheck
		return "", "", fmt.Errorf("write %s: %w", pubPath, err)
	}

	return keyPath, pubKey, nil
}
