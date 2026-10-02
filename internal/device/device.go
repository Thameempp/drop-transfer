// Package device models drop device identity and the local registry of known peers.
package device

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Device is the public view of a drop installation.
type Device struct {
	ID        string            `json:"id"` // hex SHA-256 of the public key, truncated to 16 bytes
	Name      string            `json:"name"`
	OS        string            `json:"os"`
	PublicKey ed25519.PublicKey `json:"public_key"`
}

// IDFromPublicKey derives a stable device ID from a public key.
func IDFromPublicKey(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// Fingerprint renders a public key as grouped hex for human comparison.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// Identity is a device's persistent keypair. The private key never leaves disk.
type Identity struct {
	Device
	private ed25519.PrivateKey
}

// Signer exposes the private key for TLS. The key stays in this process.
func (i *Identity) Signer() crypto.Signer { return i.private }

// Sign signs msg with the device's private key.
func (i *Identity) Sign(msg []byte) []byte { return ed25519.Sign(i.private, msg) }

type identityFile struct {
	PrivateKey []byte `json:"private_key"`
}

// LoadOrCreate returns the identity stored in dir, generating one on first use.
// The key file is written with 0600 permissions.
func LoadOrCreate(dir, name, osName string) (*Identity, error) {
	path := filepath.Join(dir, "identity.json")
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		var f identityFile
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if len(f.PrivateKey) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("parse %s: invalid private key length %d", path, len(f.PrivateKey))
		}
		priv := ed25519.PrivateKey(f.PrivateKey)
		return build(priv, name, osName), nil
	case errors.Is(err, fs.ErrNotExist):
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate identity: %w", err)
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}
		out, _ := json.Marshal(identityFile{PrivateKey: priv})
		if err := os.WriteFile(path, out, 0o600); err != nil {
			return nil, fmt.Errorf("write %s: %w", path, err)
		}
		return build(priv, name, osName), nil
	default:
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
}

func build(priv ed25519.PrivateKey, name, osName string) *Identity {
	pub := priv.Public().(ed25519.PublicKey)
	return &Identity{
		Device:  Device{ID: IDFromPublicKey(pub), Name: name, OS: osName, PublicKey: pub},
		private: priv,
	}
}
