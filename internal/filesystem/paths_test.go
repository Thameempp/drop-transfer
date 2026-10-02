package filesystem

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeNameRejectsTraversal(t *testing.T) {
	for _, n := range []string{
		"", ".", "..", "../x", "a/b", `a\b`, "/etc/passwd", `C:\Windows\x`,
		"C:evil", "..\\..\\x", "a\x00b", "\xff\xfe", strings.Repeat("a", 300), "...", " ",
	} {
		if got, err := SafeName(n); err == nil {
			t.Errorf("SafeName(%q) = %q, want error", n, got)
		}
	}
}

func TestSafeNameAccepts(t *testing.T) {
	for in, want := range map[string]string{
		"main.py":        "main.py",
		"my file (1).go": "my file (1).go",
		"données-日本.txt": "données-日本.txt",
		".env":           ".env",
		"ab:c.txt":       "ab_c.txt", // ':' is illegal on Windows
		"CON":            "_CON",
		"nul.txt":        "_nul.txt",
		"report.":        "report",
	} {
		got, err := SafeName(in)
		if err != nil || got != want {
			t.Errorf("SafeName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestReserveUnique(t *testing.T) {
	dir := t.TempDir()
	var got []string
	for i := 0; i < 3; i++ {
		p, err := ReserveUnique(dir, "a.txt")
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, filepath.Base(p))
	}
	want := []string{"a.txt", "a (1).txt", "a (2).txt"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestReserveUniqueDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(outside, []byte("keep"), 0o600)
	if err := os.Symlink(outside, filepath.Join(dir, "a.txt")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	p, err := ReserveUnique(dir, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(p) == "a.txt" {
		t.Fatal("reused symlink path")
	}
	if b, _ := os.ReadFile(outside); string(b) != "keep" {
		t.Fatal("symlink target modified")
	}
}
