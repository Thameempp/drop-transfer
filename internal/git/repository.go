package git

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Kind is the net change of a path relative to the base commit.
type Kind int

const (
	Modified Kind = iota
	Added
	Deleted
	Renamed
)

func (k Kind) String() string {
	return [...]string{"Modified", "Added", "Deleted", "Renamed"}[k]
}

// Change is one changed path. Path uses forward slashes, relative to the repo root.
type Change struct {
	Path      string
	OldPath   string // renames only
	Kind      Kind
	Staged    bool // has a change in the index
	Unstaged  bool // has a change in the working tree
	Untracked bool
}

// Repo is a git working tree.
type Repo struct {
	Root       string // absolute path of the working tree root
	Name       string // base name of Root
	Branch     string // branch name, or short commit id when detached
	Detached   bool
	HasCommits bool
	base       string // object to diff against: HEAD, or the empty tree before the first commit
	r          runner
	tmpDir     string // holds the private index copy; removed by Close
}

// ErrConflicts is returned when the working tree has unmerged paths.
var ErrConflicts = errors.New("the repository has unresolved merge conflicts; resolve them first")

// Open finds the repository containing dir.
func Open(ctx context.Context, dir string) (*Repo, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	r := runner{dir: abs}
	out, err := r.output(ctx, "rev-parse", "--show-toplevel")
	if err != nil {
		if errors.Is(err, ErrNoGit) {
			return nil, err
		}
		if strings.Contains(err.Error(), "not a git repository") {
			return nil, ErrNotRepo
		}
		return nil, err
	}
	root := filepath.FromSlash(strings.TrimSpace(string(out)))
	repo := &Repo{Root: root, Name: filepath.Base(root), r: runner{dir: root}}
	if err := repo.isolateIndex(ctx); err != nil {
		return nil, err
	}

	if _, err := repo.r.output(ctx, "rev-parse", "--verify", "-q", "HEAD"); err == nil {
		repo.HasCommits, repo.base = true, "HEAD"
	} else {
		repo.base = emptyTree(ctx, repo.r) // no commits yet: everything is "added"
	}
	if b, err := repo.r.output(ctx, "symbolic-ref", "--short", "-q", "HEAD"); err == nil {
		repo.Branch = strings.TrimSpace(string(b))
	} else {
		repo.Detached = true
		repo.Branch = "(no branch)"
		if repo.HasCommits {
			if s, err := repo.r.output(ctx, "rev-parse", "--short", "HEAD"); err == nil {
				repo.Branch = "detached at " + strings.TrimSpace(string(s))
			}
		}
	}
	return repo, nil
}

// isolateIndex copies the index so no command can modify the real one. A
// repository without an index yet (no `git add` so far) gets an empty private
// index, which git treats the same way.
func (r *Repo) isolateIndex(ctx context.Context) error {
	out, err := r.r.output(ctx, "rev-parse", "--git-path", "index")
	if err != nil {
		return err
	}
	src := filepath.FromSlash(strings.TrimSpace(string(out)))
	if !filepath.IsAbs(src) {
		src = filepath.Join(r.Root, src)
	}
	tmp, err := os.MkdirTemp("", "drop-git-")
	if err != nil {
		return fmt.Errorf("create private index: %w", err)
	}
	dst := filepath.Join(tmp, "index")
	if data, err := os.ReadFile(src); err == nil {
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			os.RemoveAll(tmp)
			return fmt.Errorf("copy index: %w", err)
		}
		// Keep the original modification time. Git decides whether cached file
		// stats can be trusted ("racily clean" entries) by comparing each entry
		// to the index file's own mtime; a fresh mtime on the copy would make an
		// edit made in the same instant as the last `git add` look unchanged.
		if st, err := os.Stat(src); err == nil {
			_ = os.Chtimes(dst, st.ModTime(), st.ModTime())
		}
	}
	r.tmpDir, r.r.index = tmp, dst
	return nil
}

// Close removes the private index copy. Always call it.
func (r *Repo) Close() {
	if r.tmpDir != "" {
		os.RemoveAll(r.tmpDir)
		r.tmpDir = ""
	}
}

// emptyTree returns the empty tree object id for this repository's hash algorithm.
func emptyTree(ctx context.Context, r runner) string {
	if out, err := r.output(ctx, "rev-parse", "--show-object-format"); err == nil && strings.TrimSpace(string(out)) == "sha256" {
		return "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321"
	}
	return "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
}

// Changes lists changed paths. With stagedOnly, only changes recorded in the
// index are reported and untracked files are ignored.
func (r *Repo) Changes(ctx context.Context, stagedOnly bool) ([]Change, error) {
	out, err := r.r.output(ctx, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames")
	if err != nil {
		return nil, err
	}
	// --no-renames keeps every entry a single path; renames then show as a
	// delete plus an add, which is exactly what is needed to list files.
	// Rename detection for display is done below from the diff itself.
	var changes []Change
	for _, rec := range strings.Split(string(out), "\x00") {
		if len(rec) < 4 {
			continue
		}
		x, y, path := rec[0], rec[1], filepath.ToSlash(rec[3:])
		switch {
		case x == 'U' || y == 'U' || (x == 'A' && y == 'A') || (x == 'D' && y == 'D'):
			return nil, ErrConflicts
		case x == '?' && y == '?':
			if !stagedOnly {
				changes = append(changes, Change{Path: path, Kind: Added, Untracked: true})
			}
			continue
		case x == '!':
			continue
		}
		c := Change{Path: path, Staged: x != ' ', Unstaged: y != ' '}
		if stagedOnly && !c.Staged {
			continue
		}
		final := y
		if stagedOnly || y == ' ' {
			final = x
		}
		switch final {
		case 'D':
			c.Kind = Deleted
		case 'A', 'C':
			c.Kind = Added
		case 'R':
			c.Kind = Renamed
		default:
			c.Kind = Modified
		}
		// A file added to the index and deleted again has no net change.
		if x == 'A' && y == 'D' {
			continue
		}
		changes = append(changes, c)
	}
	return r.foldRenames(ctx, changes, stagedOnly), nil
}

// foldRenames merges matching delete+add pairs into one Renamed entry
// ("a → b") using git's own similarity detection, and drops the delete.
func (r *Repo) foldRenames(ctx context.Context, changes []Change, stagedOnly bool) []Change {
	args := []string{"diff", "--name-status", "-z", "-M", "--no-ext-diff", "--no-textconv"}
	if stagedOnly {
		args = append(args, "--cached")
	}
	args = append(args, r.base)
	out, err := r.r.output(ctx, args...)
	if err != nil {
		return changes
	}
	renamedTo := map[string]string{} // new path -> old path
	oldPaths := map[string]bool{}
	f := strings.Split(string(out), "\x00")
	for i := 0; i < len(f); {
		if strings.HasPrefix(f[i], "R") && i+2 < len(f) {
			old, nw := filepath.ToSlash(f[i+1]), filepath.ToSlash(f[i+2])
			renamedTo[nw], oldPaths[old] = old, true
			i += 3
		} else {
			i += 2
		}
	}
	if len(renamedTo) == 0 {
		return changes
	}
	var out2 []Change
	for _, c := range changes {
		if old, ok := renamedTo[c.Path]; ok {
			c.Kind, c.OldPath = Renamed, old
		} else if c.Kind == Deleted && oldPaths[c.Path] {
			continue // folded into its rename
		}
		out2 = append(out2, c)
	}
	return out2
}

// Describe returns a short human summary such as "feature/mcq".
func (r *Repo) String() string { return fmt.Sprintf("%s (%s)", r.Name, r.Branch) }
