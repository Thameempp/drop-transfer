package git

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

var ctx = context.Background()

func openRepo(t *testing.T, dir string) (*Repo, error) {
	t.Helper()
	repo, err := Open(ctx, dir)
	if repo != nil {
		t.Cleanup(repo.Close)
	}
	return repo, err
}

func need(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

func sh(t *testing.T, dir string, args ...string) string {
	t.Helper()
	c := exec.Command("git", append([]string{"-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"}, args...)...)
	c.Dir = dir
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func write(t *testing.T, root, rel, content string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	os.Chmod(p, mode)
}

func newRepo(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "my project")
	os.MkdirAll(root, 0o755)
	sh(t, root, "init", "-q", "-b", "main")
	return root
}

// treeHash fingerprints every file under dir (path, mode, content), optionally skipping .git.
func treeHash(t *testing.T, dir string, skipGit bool) string {
	t.Helper()
	var lines []string
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		if skipGit && (rel == ".git" || strings.HasPrefix(rel, ".git"+string(filepath.Separator))) {
			return filepath.SkipDir
		}
		if d.Type().IsRegular() {
			b, _ := os.ReadFile(p)
			info, _ := d.Info()
			h := sha256.Sum256(b)
			lines = append(lines, rel+" "+info.Mode().String()+" "+hex.EncodeToString(h[:]))
		} else if d.IsDir() {
			lines = append(lines, rel+"/")
		}
		return nil
	})
	sort.Strings(lines)
	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(h[:])
}

func TestOpenNotARepo(t *testing.T) {
	need(t)
	if _, err := openRepo(t, t.TempDir()); err != ErrNotRepo {
		t.Fatalf("got %v", err)
	}
}

func TestOpenBranchDetachedAndUnborn(t *testing.T) {
	need(t)
	root := newRepo(t)
	repo, err := openRepo(t, root)
	if err != nil || repo.HasCommits || repo.Branch != "main" || repo.Name != "my project" {
		t.Fatalf("unborn: %+v %v", repo, err)
	}
	write(t, root, "a.txt", "1", 0o644)
	sh(t, root, "add", "-A")
	sh(t, root, "commit", "-qm", "one")
	sh(t, root, "checkout", "-q", "-b", "feature/mcq")
	repo, _ = openRepo(t, root)
	if !repo.HasCommits || repo.Branch != "feature/mcq" || repo.Detached {
		t.Fatalf("%+v", repo)
	}
	sh(t, root, "checkout", "-q", "--detach")
	repo, _ = openRepo(t, root)
	if !repo.Detached || !strings.HasPrefix(repo.Branch, "detached at ") {
		t.Fatalf("%+v", repo)
	}
	// Opening from a subdirectory finds the root.
	os.MkdirAll(filepath.Join(root, "sub", "deeper"), 0o755)
	repo, err = openRepo(t, filepath.Join(root, "sub", "deeper"))
	if err != nil || !strings.HasSuffix(repo.Root, "my project") {
		t.Fatalf("%+v %v", repo, err)
	}
}

func byPath(cs []Change) map[string]Change {
	m := map[string]Change{}
	for _, c := range cs {
		m[c.Path] = c
	}
	return m
}

func TestChangesClassification(t *testing.T) {
	need(t)
	root := newRepo(t)
	write(t, root, "keep.txt", "same", 0o644)
	write(t, root, "mod.py", "v1\n", 0o644)
	write(t, root, "gone.txt", "bye", 0o644)
	write(t, root, "old name.txt", strings.Repeat("renamed content\n", 20), 0o644)
	write(t, root, "staged-mod.go", "v1", 0o644)
	sh(t, root, "add", "-A")
	sh(t, root, "commit", "-qm", "base")

	write(t, root, "mod.py", "v2\n", 0o644)          // unstaged modify
	os.Remove(filepath.Join(root, "gone.txt"))       // unstaged delete
	sh(t, root, "mv", "old name.txt", "ünï new.txt") // staged rename
	write(t, root, "staged-mod.go", "v2", 0o644)     // staged modify
	sh(t, root, "add", "staged-mod.go")
	write(t, root, "tests/test_rag.py", "new", 0o644) // staged add
	sh(t, root, "add", "tests/test_rag.py")
	write(t, root, "untracked file.txt", "u", 0o644) // untracked
	write(t, root, "ignored.log", "x", 0o644)
	write(t, root, ".gitignore", "*.log\n", 0o644)

	repo, _ := openRepo(t, root)
	cs, err := repo.Changes(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	m := byPath(cs)
	want := map[string]Kind{"mod.py": Modified, "gone.txt": Deleted, "ünï new.txt": Renamed, "staged-mod.go": Modified,
		"tests/test_rag.py": Added, "untracked file.txt": Added, ".gitignore": Added}
	for p, k := range want {
		if c, ok := m[p]; !ok || c.Kind != k {
			t.Errorf("%s: %+v present=%v, want %v", p, c, ok, k)
		}
	}
	if m["ünï new.txt"].OldPath != "old name.txt" {
		t.Errorf("rename old path: %q", m["ünï new.txt"].OldPath)
	}
	if _, ok := m["old name.txt"]; ok {
		t.Error("rename source listed separately as a deletion")
	}
	if _, ok := m["ignored.log"]; ok {
		t.Error("ignored file listed")
	}
	if !m["untracked file.txt"].Untracked || m["mod.py"].Staged || !m["staged-mod.go"].Staged {
		t.Errorf("staged/untracked flags wrong: %+v", m)
	}
	if _, ok := m["keep.txt"]; ok {
		t.Error("unchanged file listed")
	}

	staged, _ := repo.Changes(ctx, true)
	sm := byPath(staged)
	if _, ok := sm["mod.py"]; ok {
		t.Error("unstaged change in staged-only list")
	}
	if _, ok := sm["untracked file.txt"]; ok {
		t.Error("untracked file in staged-only list")
	}
	if sm["staged-mod.go"].Kind != Modified || sm["tests/test_rag.py"].Kind != Added || sm["ünï new.txt"].Kind != Renamed {
		t.Errorf("%+v", sm)
	}
}

func TestChangesBeforeFirstCommit(t *testing.T) {
	need(t)
	root := newRepo(t)
	write(t, root, "a.txt", "a", 0o644)
	write(t, root, "b.txt", "b", 0o644)
	sh(t, root, "add", "a.txt")
	repo, _ := openRepo(t, root)
	cs, err := repo.Changes(ctx, false)
	if err != nil || len(cs) != 2 {
		t.Fatalf("%v %v", cs, err)
	}
	var buf bytes.Buffer
	if err := repo.WritePatch(ctx, &buf, cs, false); err != nil || !strings.Contains(buf.String(), "a.txt") || !strings.Contains(buf.String(), "b.txt") {
		t.Fatalf("%v\n%s", err, buf.String())
	}
}

func TestChangesRefusesConflicts(t *testing.T) {
	need(t)
	root := newRepo(t)
	write(t, root, "f.txt", "base\n", 0o644)
	sh(t, root, "add", "-A")
	sh(t, root, "commit", "-qm", "base")
	sh(t, root, "checkout", "-q", "-b", "other")
	write(t, root, "f.txt", "other\n", 0o644)
	sh(t, root, "commit", "-qam", "other")
	sh(t, root, "checkout", "-q", "main")
	write(t, root, "f.txt", "main\n", 0o644)
	sh(t, root, "commit", "-qam", "main")
	exec.Command("git", "-C", root, "merge", "other").Run() // conflicts
	repo, _ := openRepo(t, root)
	if _, err := repo.Changes(ctx, false); err != ErrConflicts {
		t.Fatalf("got %v", err)
	}
}

// The property that matters: applying our patch to a clean checkout of the
// base commit reproduces the sender's working tree, for every kind of change.
func TestPatchReproducesWorkingTree(t *testing.T) {
	need(t)
	if runtime.GOOS == "windows" {
		t.Skip("file modes")
	}
	root := newRepo(t)
	bin := append([]byte{0, 1, 2, 3, 255, 254}, bytes.Repeat([]byte{7}, 500)...)
	os.WriteFile(filepath.Join(root, "image.bin"), bin, 0o644)
	write(t, root, "mod.py", "line1\nline2\nline3\n", 0o644)
	write(t, root, "script.sh", "#!/bin/sh\n", 0o644)
	write(t, root, "gone.txt", "bye\n", 0o644)
	write(t, root, "dir/old name.txt", strings.Repeat("some stable content\n", 30), 0o644)
	sh(t, root, "add", "-A")
	sh(t, root, "commit", "-qm", "base")
	clone := filepath.Join(t.TempDir(), "clone")
	sh(t, filepath.Dir(clone), "clone", "-q", root, clone)

	write(t, root, "mod.py", "line1\nLINE TWO\nline3\nline4\n", 0o644)
	os.WriteFile(filepath.Join(root, "image.bin"), append(bin, 9, 9, 9), 0o644)
	os.Chmod(filepath.Join(root, "script.sh"), 0o755)
	os.Remove(filepath.Join(root, "gone.txt"))
	sh(t, root, "mv", "dir/old name.txt", "dir/ünï ☃ new.txt")
	write(t, root, "added/staged.txt", "staged new\n", 0o644)
	sh(t, root, "add", "added/staged.txt")
	write(t, root, "untracked ünï.txt", "untracked\nwith lines\n", 0o644)
	os.WriteFile(filepath.Join(root, "new.bin"), []byte{0, 0, 1, 2, 3}, 0o644)
	write(t, root, "empty.txt", "", 0o644)

	repo, _ := openRepo(t, root)
	cs, err := repo.Changes(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	before := treeHash(t, filepath.Join(root, ".git"), false)
	var patch bytes.Buffer
	if err := repo.WritePatch(ctx, &patch, cs, false); err != nil {
		t.Fatal(err)
	}
	if after := treeHash(t, filepath.Join(root, ".git"), false); after != before {
		t.Fatal("building the patch modified the .git directory")
	}

	pf := filepath.Join(t.TempDir(), "x.patch")
	os.WriteFile(pf, patch.Bytes(), 0o600)
	sh(t, clone, "apply", "--check", pf)
	sh(t, clone, "apply", pf)
	if got, want := treeHash(t, clone, true), treeHash(t, root, true); got != want {
		t.Fatalf("patched clone differs from the source working tree\npatch:\n%s", patch.String())
	}
}

func TestStagedOnlyPatchContainsOnlyIndexChanges(t *testing.T) {
	need(t)
	root := newRepo(t)
	write(t, root, "a.txt", "a1\n", 0o644)
	write(t, root, "b.txt", "b1\n", 0o644)
	sh(t, root, "add", "-A")
	sh(t, root, "commit", "-qm", "base")
	write(t, root, "a.txt", "a2\n", 0o644)
	sh(t, root, "add", "a.txt")
	write(t, root, "b.txt", "b2\n", 0o644) // unstaged
	write(t, root, "c.txt", "c\n", 0o644)  // untracked
	repo, _ := openRepo(t, root)
	cs, _ := repo.Changes(ctx, true)
	var buf bytes.Buffer
	if err := repo.WritePatch(ctx, &buf, cs, true); err != nil {
		t.Fatal(err)
	}
	p := buf.String()
	if !strings.Contains(p, "+a2") || strings.Contains(p, "b2") || strings.Contains(p, "c.txt") {
		t.Fatalf("%s", p)
	}
}

func TestPatchHonoursPathSelectionAndNeverGlobs(t *testing.T) {
	need(t)
	root := newRepo(t)
	write(t, root, "a.txt", "a1\n", 0o644)
	write(t, root, "secret.env", "S=1\n", 0o644)
	write(t, root, "*.txt", "literal star name\n", 0o644)
	sh(t, root, "add", "-A")
	sh(t, root, "commit", "-qm", "base")
	write(t, root, "a.txt", "a2\n", 0o644)
	write(t, root, "secret.env", "S=2\n", 0o644)
	write(t, root, "*.txt", "changed\n", 0o644)
	repo, _ := openRepo(t, root)
	all, _ := repo.Changes(ctx, false)
	var keep []Change
	for _, c := range all {
		if c.Path != "secret.env" {
			keep = append(keep, c)
		}
	}
	var buf bytes.Buffer
	repo.WritePatch(ctx, &buf, keep, false)
	if strings.Contains(buf.String(), "secret.env") || strings.Contains(buf.String(), "S=2") {
		t.Fatal("excluded file leaked into the patch")
	}
	if !strings.Contains(buf.String(), "+a2") || !strings.Contains(buf.String(), "+changed") {
		t.Fatalf("selected files missing:\n%s", buf.String())
	}
	// A path named "*.txt" must select only itself, not every .txt file.
	buf.Reset()
	repo.WritePatch(ctx, &buf, []Change{{Path: "*.txt", Kind: Modified}}, false)
	if strings.Contains(buf.String(), "+a2") || !strings.Contains(buf.String(), "+changed") {
		t.Fatalf("pathspec was interpreted as a glob:\n%s", buf.String())
	}
}

func TestPatchWithManyPathsIsChunked(t *testing.T) {
	need(t)
	root := newRepo(t)
	for i := 0; i < 600; i++ {
		write(t, root, filepath.Join("d", strings.Repeat("x", 60)+string(rune('a'+i%26))+"_"+itoa(i)+".txt"), "v1\n", 0o644)
	}
	sh(t, root, "add", "-A")
	sh(t, root, "commit", "-qm", "base")
	filepath.WalkDir(filepath.Join(root, "d"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			os.WriteFile(p, []byte("v2\n"), 0o644)
		}
		return nil
	})
	repo, _ := openRepo(t, root)
	cs, _ := repo.Changes(ctx, false)
	if len(cs) != 600 {
		t.Fatalf("%d changes", len(cs))
	}
	if n := len(chunkUnits(unitsOf(cs))); n < 2 {
		t.Fatalf("expected the long path list to be split, got %d chunk(s)", n)
	}
	var buf bytes.Buffer
	if err := repo.WritePatch(ctx, &buf, cs, false); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(buf.String(), "\ndiff --git ") + 1; got != 600 {
		t.Fatalf("patch has %d files, want 600", got)
	}
}

func itoa(i int) string { return fmt.Sprintf("%03d", i) }

func unitsOf(cs []Change) [][]string {
	var u [][]string
	for _, c := range cs {
		u = append(u, []string{c.Path})
	}
	return u
}

func TestReadOnlyGuarantee(t *testing.T) {
	need(t)
	root := newRepo(t)
	write(t, root, "a.txt", "1\n", 0o644)
	write(t, root, "stable.txt", "never edited\n", 0o644)
	sh(t, root, "add", "-A")
	sh(t, root, "commit", "-qm", "base")
	write(t, root, "a.txt", "2\n", 0o644)
	write(t, root, "new.txt", "n\n", 0o644)
	sh(t, root, "add", "new.txt")
	write(t, root, "untracked.txt", "u\n", 0o644)
	// Make the index stale: same content, new mtime. Plain `git status` refreshes
	// (rewrites) the index in this situation; ours must not.
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(filepath.Join(root, "stable.txt"), future, future); err != nil {
		t.Fatal(err)
	}
	// Premise check: an ordinary `git diff` DOES rewrite the index here, even
	// with GIT_OPTIONAL_LOCKS=0, so this test is able to fail.
	probeRoot := filepath.Join(t.TempDir(), "probe")
	sh(t, filepath.Dir(probeRoot), "clone", "-q", root, probeRoot)
	os.Chtimes(filepath.Join(probeRoot, "stable.txt"), future.Add(time.Hour), future.Add(time.Hour))
	pIdx := filepath.Join(probeRoot, ".git", "index")
	pBefore, _ := os.ReadFile(pIdx)
	probe := exec.Command("git", "diff", "HEAD")
	probe.Dir = probeRoot
	probe.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0")
	probe.Run()
	if pAfter, _ := os.ReadFile(pIdx); bytes.Equal(pBefore, pAfter) {
		t.Fatal("test premise broken: plain `git diff` no longer rewrites a stale index")
	}

	before := treeHash(t, root, false) // the whole tree including .git

	repo, _ := openRepo(t, root)
	cs, _ := repo.Changes(ctx, false)
	repo.Changes(ctx, true)
	var buf bytes.Buffer
	repo.WritePatch(ctx, &buf, cs, false)
	repo.TrackedFiles(ctx)
	repo.CommitCount(ctx)
	bundle := filepath.Join(t.TempDir(), "r.bundle")
	if err := repo.Bundle(ctx, bundle, false); err != nil {
		t.Fatal(err)
	}
	if after := treeHash(t, root, false); after != before {
		t.Fatal("the repository (including .git) changed while reading it")
	}
}

func TestBundleClonesWithHistory(t *testing.T) {
	need(t)
	root := newRepo(t)
	sh(t, root, "checkout", "-q", "-b", "feature/mcq") // not the clone's default branch name: this is what exposed the bug
	write(t, root, "a.txt", "1\n", 0o644)
	sh(t, root, "add", "-A")
	sh(t, root, "commit", "-qm", "first")
	write(t, root, "a.txt", "2\n", 0o644)
	sh(t, root, "commit", "-qam", "second")
	sh(t, root, "branch", "side")
	write(t, root, "uncommitted.txt", "not in the bundle", 0o644)
	repo, _ := openRepo(t, root)
	if repo.CommitCount(ctx) != 2 {
		t.Fatal("commit count")
	}
	bundle := filepath.Join(t.TempDir(), "r.bundle")
	if err := repo.Bundle(ctx, bundle, false); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "cloned")
	sh(t, filepath.Dir(dest), "clone", "-q", bundle, dest)
	if log := sh(t, dest, "log", "--oneline"); strings.Count(log, "\n") != 2 {
		t.Fatalf("history missing:\n%s", log)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "a.txt")); err != nil || string(b) != "2\n" {
		t.Fatalf("clone has no checked-out working tree: %v %q", err, b)
	}
	if br := strings.TrimSpace(sh(t, dest, "branch", "--show-current")); br != "feature/mcq" {
		t.Fatalf("clone checked out %q", br)
	}
	if _, err := os.Stat(filepath.Join(dest, "uncommitted.txt")); err == nil {
		t.Fatal("uncommitted file ended up in the bundle")
	}
	if out := sh(t, dest, "branch", "-a"); strings.Contains(out, "side") {
		t.Fatalf("default bundle contains other branches:\n%s", out)
	}
	all := filepath.Join(t.TempDir(), "all.bundle")
	repo.Bundle(ctx, all, true)
	dest2 := filepath.Join(t.TempDir(), "cloned2")
	sh(t, filepath.Dir(dest2), "clone", "-q", all, dest2)
	if out := sh(t, dest2, "branch", "-a"); !strings.Contains(out, "side") {
		t.Fatalf("--all bundle lacks the other branch:\n%s", out)
	}
}

func TestBundleErrors(t *testing.T) {
	need(t)
	root := newRepo(t)
	repo, _ := openRepo(t, root)
	if err := repo.Bundle(ctx, filepath.Join(t.TempDir(), "x"), false); err == nil {
		t.Fatal("bundled a repository with no commits")
	}
	write(t, root, "a", "1", 0o644)
	sh(t, root, "add", "-A")
	sh(t, root, "commit", "-qm", "c")
	sh(t, root, "checkout", "-q", "--detach")
	repo, _ = openRepo(t, root)
	if err := repo.Bundle(ctx, filepath.Join(t.TempDir(), "x"), false); err == nil {
		t.Fatal("bundled a detached HEAD without --all")
	}
}

func TestNoGitBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := openRepo(t, t.TempDir()); err != ErrNoGit {
		t.Fatalf("got %v", err)
	}
}

func TestHistoryFilesIncludesFilesDeletedLater(t *testing.T) {
	need(t)
	root := newRepo(t)
	write(t, root, "keep.txt", "1\n", 0o644)
	write(t, root, ".env", "SECRET=1\n", 0o644)
	sh(t, root, "add", "-A")
	sh(t, root, "commit", "-qm", "oops")
	sh(t, root, "rm", "-q", ".env")
	sh(t, root, "commit", "-qm", "remove env")
	repo, _ := openRepo(t, root)
	tracked, _ := repo.TrackedFiles(ctx)
	for _, f := range tracked {
		if f == ".env" {
			t.Fatal("premise broken: .env still tracked")
		}
	}
	hist, err := repo.HistoryFiles(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, f := range hist {
		found[f] = true
	}
	if !found[".env"] || !found["keep.txt"] || len(hist) != 2 {
		t.Fatalf("history files: %v", hist)
	}
}

// Git decides whether cached file stats can be trusted by comparing each index
// entry to the index file's own mtime ("racily clean" detection). The private
// index copy must therefore keep the original's mtime, or an edit made in the
// same instant as the last `git add` (same size) can be reported as unchanged.
// This was found as an intermittent failure of a many-file test.
func TestPrivateIndexKeepsOriginalMtime(t *testing.T) {
	need(t)
	root := newRepo(t)
	write(t, root, "a.txt", "v1\n", 0o644)
	sh(t, root, "add", "-A")
	sh(t, root, "commit", "-qm", "base")
	old := time.Now().Add(-90 * time.Minute).Truncate(time.Second)
	realIdx := filepath.Join(root, ".git", "index")
	os.Chtimes(realIdx, old, old)

	repo, err := openRepo(t, root)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(repo.r.index)
	if err != nil {
		t.Fatal(err)
	}
	if !st.ModTime().Equal(old) {
		t.Fatalf("private index mtime %v, want the original's %v", st.ModTime(), old)
	}
}
