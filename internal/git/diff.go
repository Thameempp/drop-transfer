package git

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxArgBytes bounds one git command line. Windows allows about 32 KiB in
// total, so stay well under it; macOS and Linux limits are far higher.
const maxArgBytes = 16 * 1024

// WritePatch writes a patch that turns the base commit into the current state
// of the given changes, in a format `git apply` accepts (binary files included).
// Only the listed paths are included, so callers can leave files out. It does
// not modify the repository.
//
// With stagedOnly the patch contains what is in the index; otherwise it is the
// working tree (staged and unstaged together) plus untracked files.
func (r *Repo) WritePatch(ctx context.Context, w io.Writer, changes []Change, stagedOnly bool) error {
	var tracked [][]string // each entry: the paths of one logical change (rename keeps both)
	var untracked []string
	for _, c := range changes {
		if c.Untracked {
			untracked = append(untracked, c.Path)
			continue
		}
		unit := []string{c.Path}
		if c.OldPath != "" {
			unit = append(unit, c.OldPath)
		}
		tracked = append(tracked, unit)
	}

	base := []string{"diff", "--binary", "--no-ext-diff", "--no-textconv", "--no-color", "-M"}
	if stagedOnly {
		base = append(base, "--cached")
	}
	base = append(base, r.base, "--")
	for _, chunk := range chunkUnits(tracked) {
		if err := r.r.stream(ctx, w, nil, append(append([]string{}, base...), chunk...)...); err != nil {
			return fmt.Errorf("build patch: %w", err)
		}
	}
	for _, p := range untracked {
		if err := r.untrackedPatch(ctx, w, p); err != nil {
			return err
		}
	}
	return nil
}

// untrackedPatch renders a new file as an addition without staging it
// (`git add -N` would modify the index).
func (r *Repo) untrackedPatch(ctx context.Context, w io.Writer, rel string) error {
	st, err := os.Lstat(filepath.Join(r.Root, filepath.FromSlash(rel)))
	if err != nil {
		return fmt.Errorf("inspect %s: %w", rel, err)
	}
	if st.IsDir() { // e.g. a nested repository: not a file we can express as a patch
		return nil
	}
	// Exit status 1 only means "there are differences".
	err = r.r.stream(ctx, w, []int{1}, "diff", "--no-index", "--binary", "--no-ext-diff", "--no-textconv", "--no-color", "--", os.DevNull, filepath.FromSlash(rel))
	if err != nil {
		return fmt.Errorf("build patch for %s: %w", rel, err)
	}
	return nil
}

func chunkUnits(units [][]string) [][]string {
	var chunks [][]string
	var cur []string
	size := 0
	for _, u := range units {
		n := 0
		for _, p := range u {
			n += len(p) + 1
		}
		if size+n > maxArgBytes && len(cur) > 0 {
			chunks, cur, size = append(chunks, cur), nil, 0
		}
		cur = append(cur, u...)
		size += n
	}
	if len(cur) > 0 {
		chunks = append(chunks, cur)
	}
	return chunks
}

// PatchStat counts what a patch contains, for display.
func PatchStat(patch []byte) (files int) {
	return bytes.Count(patch, []byte("\ndiff --git ")) + b2i(bytes.HasPrefix(patch, []byte("diff --git ")))
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Bundle writes a git bundle of the repository to dest. By default it contains
// the current branch (with its full history); all=true bundles every branch and tag.
// The receiver can `git clone <file>`. The working tree is not included.
func (r *Repo) Bundle(ctx context.Context, dest string, all bool) error {
	if !r.HasCommits {
		return fmt.Errorf("the repository has no commits yet; there is nothing to bundle")
	}
	args := []string{"bundle", "create", dest}
	switch {
	case all:
		args = append(args, "--all")
	case r.Detached:
		return fmt.Errorf("HEAD is detached; check out a branch or use --all")
	default:
		// HEAD must be included, otherwise `git clone` of the bundle cannot tell
		// which branch to check out and produces an empty working tree.
		args = append(args, "HEAD", "refs/heads/"+strings.TrimPrefix(r.Branch, "refs/heads/"))
	}
	if _, err := r.r.output(ctx, args...); err != nil {
		return fmt.Errorf("create bundle: %w", err)
	}
	return nil
}

// TrackedFiles lists every file in the base commit's tree.
func (r *Repo) TrackedFiles(ctx context.Context) ([]string, error) {
	if !r.HasCommits {
		return nil, nil
	}
	out, err := r.r.output(ctx, "ls-tree", "-r", "-z", "--name-only", "HEAD")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	return files, nil
}

// HistoryFiles lists every path that was ever added or modified in the history
// that a bundle would contain (the current branch, or everything with all=true).
// A file deleted in a later commit is still in the bundle, so it is included.
func (r *Repo) HistoryFiles(ctx context.Context, all bool) ([]string, error) {
	if !r.HasCommits {
		return nil, nil
	}
	rev := "HEAD"
	if all {
		rev = "--all"
	}
	out, err := r.r.output(ctx, "log", "--name-only", "--pretty=format:", "-z", "--diff-filter=AMCR", "--no-renames", rev)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		f = strings.TrimLeft(f, "\n")
		if f != "" && !seen[f] {
			seen[f] = true
			files = append(files, f)
		}
	}
	return files, nil
}

// CommitCount returns the number of commits reachable from HEAD.
func (r *Repo) CommitCount(ctx context.Context) int {
	out, err := r.r.output(ctx, "rev-list", "--count", "HEAD")
	if err != nil {
		return 0
	}
	n := 0
	fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &n)
	return n
}
