package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadMissingFileGivesDefaults(t *testing.T) {
	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Transfer.Verify {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
}

func TestLoadOverridesAndKeepsOtherDefaults(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[device]\nname = \"box\"\n"), 0o600)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Device.Name != "box" || !cfg.Transfer.Verify {
		t.Fatalf("unexpected: %+v", cfg)
	}
}

func TestLoadInvalidTOML(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[[["), 0o600)
	if _, err := Load(dir); err == nil {
		t.Fatal("expected error")
	}
}

func TestDirHonoursDropHome(t *testing.T) {
	t.Setenv("DROP_HOME", "/x/y")
	d, _ := Dir()
	if d != "/x/y" {
		t.Fatal(d)
	}
}

func TestSecurityDefaultsAreSecure(t *testing.T) {
	cfg, _ := Load(t.TempDir())
	s := cfg.Security
	if s.TextRequiresPIN || s.PINLength != 6 || s.MaxAttempts != 3 || s.LockoutSeconds != 30 || s.TrustExpiryDays != 90 {
		t.Fatalf("%+v", s)
	}
}

func TestSecurityOverride(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[security]\ntext_requires_pin = true\nmax_attempts = 5\n"), 0o600)
	cfg, _ := Load(dir)
	if !cfg.Security.TextRequiresPIN || cfg.Security.MaxAttempts != 5 || cfg.Security.PINLength != 6 {
		t.Fatalf("%+v", cfg.Security)
	}
}

func TestSaveLoadReceiveDirAndExpand(t *testing.T) {
	dir := t.TempDir()
	c := Default()
	c.Transfer.ReceiveDir = "/tmp/inbox"
	if err := Save(dir, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil || got.Transfer.ReceiveDir != "/tmp/inbox" || !got.Transfer.Verify {
		t.Fatalf("%+v %v", got, err)
	}
	if p, _ := ExpandDir("~/x"); !filepath.IsAbs(p) || strings.Contains(p, "~") {
		t.Fatalf("got %q", p)
	}
	if _, err := ExpandDir("  "); err == nil {
		t.Fatal("empty dir accepted")
	}
}
