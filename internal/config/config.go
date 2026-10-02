// Package config loads drop's configuration and resolves platform paths.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

const dirName = "drop"

// Config is the user-editable configuration. Every field has a working default,
// so no config file is required.
type Config struct {
	Device   DeviceConfig   `toml:"device"`
	Transfer TransferConfig `toml:"transfer"`
	Security SecurityConfig `toml:"security"`
}

type DeviceConfig struct {
	// Name overrides the hostname advertised to peers.
	Name string `toml:"name"`
}

type TransferConfig struct {
	Verify bool `toml:"verify"`
	// ReceiveDir is where accepted files are written. Empty means ~/Downloads.
	ReceiveDir string `toml:"receive_dir"`
}

// SecurityConfig tunes PIN authorization. Defaults are secure; see docs/security.md.
type SecurityConfig struct {
	// TextRequiresPIN makes plain-text transfers require the PIN too.
	TextRequiresPIN bool `toml:"text_requires_pin"`
	// PINLength is the length of generated PINs (6-12).
	PINLength int `toml:"pin_length"`
	// MaxAttempts failed PIN attempts trigger a lockout.
	MaxAttempts int `toml:"max_attempts"`
	// LockoutSeconds is the first lockout duration; it doubles per lockout.
	LockoutSeconds int `toml:"lockout_seconds"`
	// LockoutMaxSeconds caps the lockout duration.
	LockoutMaxSeconds int `toml:"lockout_max_seconds"`
	// TrustExpiryDays: a trusted device unused for this long must use the PIN
	// again (use refreshes it). 0 means trust never expires.
	TrustExpiryDays int `toml:"trust_expiry_days"`
}

// Default returns the built-in configuration.
func Default() Config {
	return Config{
		Transfer: TransferConfig{Verify: true},
		Security: SecurityConfig{PINLength: 6, MaxAttempts: 3, LockoutSeconds: 30, LockoutMaxSeconds: 3600, TrustExpiryDays: 90},
	}
}

// Dir returns the directory holding config and identity. DROP_HOME overrides
// the OS default, which keeps tests and multiple local instances isolated.
func Dir() (string, error) {
	if d := os.Getenv("DROP_HOME"); d != "" {
		return d, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate config directory: %w", err)
	}
	return filepath.Join(base, dirName), nil
}

// Load reads config.toml from dir. A missing file yields defaults.
func Load(dir string) (Config, error) {
	cfg := Default()
	path := filepath.Join(dir, "config.toml")
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return cfg, nil
		}
		return Default(), fmt.Errorf("read %s: %w", path, err)
	}
	return cfg, nil
}

// ResolveReceiveDir resolves the directory for incoming files.
func (c Config) ResolveReceiveDir() (string, error) {
	if c.Transfer.ReceiveDir != "" {
		return c.Transfer.ReceiveDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, "Downloads"), nil
}
