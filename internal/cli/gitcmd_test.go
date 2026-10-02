package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/thameem/drop/internal/git"
)

func TestSafeFileName(t *testing.T) {
	for in, want := range map[string]string{
		"pdf-assistant-feature/mcq": "pdf-assistant-feature-mcq",
		"my project-main":           "my-project-main",
		"../../etc/passwd":          "etc-passwd",
		"détached at abc123":        "d-tached-at-abc123",
		"":                          "drop",
		"///":                       "drop",
		"a.b_c-d":                   "a.b_c-d",
	} {
		if got := safeFileName(in); got != want {
			t.Errorf("safeFileName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{"x.patch": "x.patch", "my project.patch": "'my project.patch'", "it's.patch": `'it'\''s.patch'`} {
		if got := shellQuote(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

func TestScreenChangesWithholdsSecretsButNotTemplates(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "src"), 0o755)
	os.WriteFile(filepath.Join(root, "src", "legacy.py"), []byte(`K = "AKIAIOSFODNN7ABCDEFG"`), 0o644)
	os.WriteFile(filepath.Join(root, "src", "ok.py"), []byte("x = 1"), 0o644)
	os.WriteFile(filepath.Join(root, ".env.example"), []byte("KEY="), 0o644)
	changes := []git.Change{
		{Path: ".env", Kind: git.Modified},
		{Path: ".env.example", Kind: git.Modified},
		{Path: "config/credentials.json", Kind: git.Added},
		{Path: ".ssh/config", Kind: git.Added},
		{Path: "keys/renamed.txt", OldPath: "keys/server.pem", Kind: git.Renamed},
		{Path: "src/legacy.py", Kind: git.Modified},
		{Path: "src/ok.py", Kind: git.Modified},
		{Path: "secrets.yaml", Kind: git.Deleted},
	}
	keep, held := screenChanges(root, changes, false)
	kept := map[string]bool{}
	for _, c := range keep {
		kept[c.Path] = true
	}
	if !kept[".env.example"] || !kept["src/ok.py"] || len(keep) != 2 {
		t.Fatalf("kept: %v", kept)
	}
	if len(held) != 6 {
		t.Fatalf("withheld %d: %v", len(held), held)
	}
	for _, h := range held {
		if h.Reason == "" || filepath.Base(h.Reason) == "AKIAIOSFODNN7ABCDEFG" {
			t.Fatalf("bad reason: %+v", h)
		}
	}
	// A deleted sensitive file is withheld by name (its old content would be in the patch).
	// The override sends everything.
	keep, held = screenChanges(root, changes, true)
	if len(keep) != len(changes) || len(held) != 0 {
		t.Fatal("--include-secrets did not disable screening")
	}
}
