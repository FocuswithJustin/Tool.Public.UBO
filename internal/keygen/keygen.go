package keygen

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// GenerateAll generates all keypairs into outputDir and returns the key material.
func GenerateAll(outputDir string) (*Keys, error) {
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
	keyPath, pubKey, err := GenerateSSHKeypair("client_auth", outputDir)
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

// GenerateWireGuardKeypair uses wg to generate a keypair.
// Private key is written to <outputDir>/<name>_private.key (mode 0600).
// Public key is written to <outputDir>/<name>_public.key (mode 0644).
func GenerateWireGuardKeypair(name, outputDir string) (privateKey, publicKey string, err error) {
	privPath := filepath.Join(outputDir, name+"_private.key")
	pubPath := filepath.Join(outputDir, name+"_public.key")

	// Generate private key
	privCmd := exec.Command("wg", "genkey")
	privOut, err := privCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("wg genkey: %w", err)
	}
	privateKey = strings.TrimSpace(string(privOut))

	if err := os.WriteFile(privPath, []byte(privateKey+"\n"), 0600); err != nil {
		return "", "", fmt.Errorf("write %s: %w", privPath, err)
	}

	// Derive public key from private key
	pubCmd := exec.Command("wg", "pubkey")
	pubCmd.Stdin = strings.NewReader(privateKey + "\n")
	pubOut, err := pubCmd.Output()
	if err != nil {
		os.Remove(privPath)
		return "", "", fmt.Errorf("wg pubkey: %w", err)
	}
	publicKey = strings.TrimSpace(string(pubOut))

	if err := os.WriteFile(pubPath, []byte(publicKey+"\n"), 0644); err != nil {
		os.Remove(privPath)
		return "", "", fmt.Errorf("write %s: %w", pubPath, err)
	}

	return privateKey, publicKey, nil
}

// GenerateSSHKeypair uses ssh-keygen to create an ed25519 keypair.
// Private key written to <outputDir>/<name> (mode 0600).
// Returns the private key path and authorized_keys-format public key string.
func GenerateSSHKeypair(name, outputDir string) (keyPath, pubKey string, err error) {
	keyPath = filepath.Join(outputDir, name)
	pubPath := keyPath + ".pub"

	// Remove any existing keys so ssh-keygen doesn't prompt to overwrite
	os.Remove(keyPath)
	os.Remove(pubPath)

	cmd := exec.Command("ssh-keygen",
		"-t", "ed25519",
		"-f", keyPath,
		"-N", "",
		"-C", "ubo-client",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("ssh-keygen: %w\n%s", err, strings.TrimSpace(string(out)))
	}

	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		os.Remove(keyPath)
		return "", "", fmt.Errorf("read %s: %w", pubPath, err)
	}
	pubKey = strings.TrimSpace(string(pubBytes))

	return keyPath, pubKey, nil
}
