// Package config loads drop's configuration and resolves platform paths.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

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
	// ReceiveDir is where accepted files are written. Empty means the current directory.
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

// Save writes the config to config.toml in dir (0600).
func Save(dir string, c Config) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(c); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// ExpandDir turns a user-typed directory into an absolute path: it expands a
// leading ~ and resolves relative paths against the current directory.
func ExpandDir(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", errors.New("empty directory")
	}
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("locate home directory: %w", err)
		}
		p = filepath.Join(home, p[1:])
	}
	return filepath.Abs(p)
}

// ResolveReceiveDir resolves the directory for incoming files.
func (c Config) ResolveReceiveDir() (string, error) {
	if c.Transfer.ReceiveDir != "" {
		return c.Transfer.ReceiveDir, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("locate current directory: %w", err)
	}
	return wd, nil
}
