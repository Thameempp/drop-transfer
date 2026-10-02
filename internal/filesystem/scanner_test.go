package filesystem

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func write(t *testing.T, root, rel, content string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func TestScanTree(t *testing.T) {
	root := filepath.Join(t.TempDir(), "proj")
	write(t, root, "src/main.py", "print(1)", 0o644)
	write(t, root, "src/utils/helpers.py", "x", 0o644)
	write(t, root, "my docs/résumé.txt", "", 0o644)
	write(t, root, "run.sh", "#!/bin/sh", 0o755)
	os.MkdirAll(filepath.Join(root, "empty"), 0o755)

	res, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "proj" || res.Files != 4 || res.Dirs != 4 || res.TotalSize != 8+1+0+9 {
		t.Fatalf("%+v", res)
	}
	seen := map[string]bool{"": true}
	for _, e := range res.Entries {
		parent := filepath.ToSlash(filepath.Dir(e.Path))
		if parent == "." {
			parent = ""
		}
		if !seen[parent] {
			t.Fatalf("%s listed before its parent", e.Path)
		}
		if e.Dir {
			seen[e.Path] = true
		}
		if filepath.IsAbs(e.Path) || e.Path == "" {
			t.Fatalf("bad path %q", e.Path)
		}
	}
	if runtime.GOOS != "windows" {
		for _, e := range res.Entries {
			if e.Path == "run.sh" && !e.Exec {
				t.Fatal("exec bit lost")
			}
		}
	}
}

func TestScanSkipsAndReportsSymlinksWithoutFollowing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "proj")
	write(t, root, "a.txt", "a", 0o644)
	outside := t.TempDir()
	write(t, outside, "secret.txt", "TOPSECRET", 0o644)
	if err := os.Symlink(outside, filepath.Join(root, "link-to-dir")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "link-to-file"))

	res, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 1 || res.Dirs != 0 || len(res.Skipped) != 2 {
		t.Fatalf("files=%d dirs=%d skipped=%v", res.Files, res.Dirs, res.Skipped)
	}
	for _, s := range res.Skipped {
		if s.Reason != "symbolic link" {
			t.Fatalf("%+v", s)
		}
	}
}

func TestScanErrors(t *testing.T) {
	if _, err := Scan(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing dir accepted")
	}
	f := filepath.Join(t.TempDir(), "file")
	os.WriteFile(f, nil, 0o600)
	if _, err := Scan(f); err == nil {
		t.Fatal("file accepted as directory")
	}
	if _, err := Scan(string(filepath.Separator)); err == nil {
		t.Fatal("filesystem root accepted")
	}
}

func TestScanUnreadableDirectoryIsAnErrorNotSilentlyDropped(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission semantics differ")
	}
	root := filepath.Join(t.TempDir(), "proj")
	write(t, root, "ok.txt", "x", 0o644)
	locked := filepath.Join(root, "locked")
	os.MkdirAll(locked, 0o755)
	write(t, root, "locked/hidden.txt", "x", 0o644)
	os.Chmod(locked, 0)
	defer os.Chmod(locked, 0o755)
	if _, err := Scan(root); err == nil {
		t.Fatal("unreadable folder was silently skipped")
	}
}

func TestScanCurrentDirectoryName(t *testing.T) {
	root := filepath.Join(t.TempDir(), "myproject")
	write(t, root, "a", "x", 0o644)
	old, _ := os.Getwd()
	os.Chdir(root)
	defer os.Chdir(old)
	res, err := Scan(".")
	if err != nil || res.Name != "myproject" {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestRenameUnique(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "proj"), 0o755)
	os.WriteFile(filepath.Join(dir, "proj", "keep"), []byte("old"), 0o644)
	src := filepath.Join(dir, ".staging")
	os.MkdirAll(src, 0o755)
	os.WriteFile(filepath.Join(src, "new"), []byte("new"), 0o644)
	p, err := RenameUnique(src, dir, "proj")
	if err != nil || filepath.Base(p) != "proj (1)" {
		t.Fatalf("%q %v", p, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "proj", "keep")); string(b) != "old" {
		t.Fatal("existing folder modified")
	}
	if _, err := os.Stat(filepath.Join(p, "new")); err != nil {
		t.Fatal(err)
	}
}

func TestNewScanFromPaths(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	write(t, root, "src/utils/a.py", "aa", 0o644)
	write(t, root, "src/b.py", "b", 0o644)
	write(t, root, "top.txt", "t", 0o755)
	write(t, root, "unrelated/skip.txt", "x", 0o644)
	res, err := NewScanFromPaths(root, "repo-changes", []string{"src/utils/a.py", "top.txt", "src/b.py"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 3 || res.Dirs != 2 || res.TotalSize != 4 || res.Name != "repo-changes" {
		t.Fatalf("%+v", res)
	}
	seen := map[string]bool{"": true}
	for _, e := range res.Entries {
		parent := filepath.ToSlash(filepath.Dir(e.Path))
		if parent == "." {
			parent = ""
		}
		if !seen[parent] {
			t.Fatalf("%s before its parent", e.Path)
		}
		if e.Dir {
			seen[e.Path] = true
		}
		if e.Path == "unrelated/skip.txt" || e.Path == "unrelated" {
			t.Fatal("unrequested path included")
		}
	}
}

func TestNewScanFromPathsRejectsEscapesAndReportsSymlinks(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	write(t, root, "a.txt", "a", 0o644)
	for _, bad := range []string{"../outside", "a/../../outside", "/etc/passwd", "..", "."} {
		if _, err := NewScanFromPaths(root, "x", []string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := NewScanFromPaths(root, "x", []string{"missing.txt"}); err == nil {
		t.Fatal("missing file accepted")
	}
	outside := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(outside, []byte("s"), 0o644)
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skip("symlinks unavailable")
	}
	res, err := NewScanFromPaths(root, "x", []string{"a.txt", "link"})
	if err != nil || res.Files != 1 || len(res.Skipped) != 1 || res.Skipped[0].Path != "link" {
		t.Fatalf("%+v %v", res, err)
	}
}
