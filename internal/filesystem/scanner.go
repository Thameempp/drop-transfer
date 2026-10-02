package filesystem

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// MaxEntries bounds the number of files and directories in one transfer.
const MaxEntries = 500_000

// Entry is one file or directory below the scan root. Path is relative and
// always uses forward slashes, whatever the OS.
type Entry struct {
	Path string
	Dir  bool
	Size int64
	Exec bool
}

// Skipped is something deliberately not transferred. Nothing is skipped
// silently: callers must show these to the user.
type Skipped struct {
	Path   string
	Reason string
}

// Category says why something was left out of a transfer.
type Category string

const (
	CatVCS       Category = "version control"
	CatGitignore Category = "gitignore"
	CatGenerated Category = "generated"
	CatSensitive Category = "sensitive"
)

// Exclusion is a Rules verdict to leave an entry (and, for a directory,
// everything under it) out of the transfer.
type Exclusion struct {
	Category Category
	Detail   string // human-readable reason, e.g. "AWS access key pattern"
}

// Excluded is an entry that was deliberately not transferred, with how much
// data that represents. Nothing is excluded invisibly.
type Excluded struct {
	Path  string // relative, forward slashes
	Dir   bool
	Size  int64 // bytes (for a directory, the total of what it contains; best effort)
	Files int   // files inside (directories) or 1
	Exclusion
}

// Rules decides what to leave out. Decide is called for every entry below the
// root, parents before children; returning non-nil excludes the entry (and
// prunes a directory). abs is the absolute path, rel the root-relative path.
type Rules interface {
	Decide(abs, rel string, d fs.DirEntry) *Exclusion
}

// ScanOptions customises a scan.
type ScanOptions struct {
	Rules Rules // nil: include everything (symlinks and special files are still skipped)
}

// ScanResult is a directory tree ready to be turned into a manifest.
type ScanResult struct {
	Root      string  // absolute path
	Name      string  // base name, used as the folder name on the receiver
	Entries   []Entry // parents always precede children; lexical order
	Files     int
	Dirs      int
	TotalSize int64
	Skipped   []Skipped
	Excluded  []Excluded // left out by Rules, largest first
}

// Scan walks root without following symlinks. Symlinks and special files
// (sockets, devices, pipes) are not transferred and are reported in Skipped.
// Any entry that cannot be read is an error rather than being dropped.
func Scan(root string) (*ScanResult, error) { return ScanWith(root, ScanOptions{}) }

// ScanWith is Scan with exclusion rules.
func ScanWith(root string, opts ScanOptions) (*ScanResult, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", root, err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", root, err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}
	name := filepath.Base(abs)
	if name == string(filepath.Separator) || name == "." || name == ".." {
		return nil, fmt.Errorf("cannot send %s: it has no folder name; cd into it or pass a named folder", root)
	}
	res := &ScanResult{Root: abs, Name: name}
	err = filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("read %s: %w", p, err)
		}
		if p == abs {
			return nil
		}
		rel, rerr := filepath.Rel(abs, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if opts.Rules != nil {
			if ex := opts.Rules.Decide(p, rel, d); ex != nil {
				e := Excluded{Path: rel, Dir: d.IsDir(), Exclusion: *ex}
				if !d.IsDir() {
					e.Files = 1
					if info, ierr := d.Info(); ierr == nil && d.Type().IsRegular() {
						e.Size = info.Size()
					}
				}
				res.Excluded = append(res.Excluded, e)
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
		}
		switch {
		case d.IsDir():
			res.Entries = append(res.Entries, Entry{Path: rel, Dir: true})
			res.Dirs++
		case d.Type().IsRegular():
			info, err := d.Info()
			if err != nil {
				return fmt.Errorf("inspect %s: %w", p, err)
			}
			res.Entries = append(res.Entries, Entry{Path: rel, Size: info.Size(), Exec: info.Mode()&0o111 != 0})
			res.Files++
			res.TotalSize += info.Size()
		case d.Type()&fs.ModeSymlink != 0:
			res.Skipped = append(res.Skipped, Skipped{rel, "symbolic link"})
		default:
			res.Skipped = append(res.Skipped, Skipped{rel, "special file"})
		}
		if len(res.Entries) > MaxEntries {
			return fmt.Errorf("more than %d files and folders; send a smaller tree", MaxEntries)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	res.measureExcluded(abs)
	return res, nil
}

// measureExcluded fills in sizes for excluded directories, in parallel. It is
// best effort (unreadable entries count as zero) because it only feeds the
// summary shown to the user.
func (r *ScanResult) measureExcluded(root string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i := range r.Excluded {
		if !r.Excluded[i].Dir {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(e *Excluded) {
			defer wg.Done()
			defer func() { <-sem }()
			filepath.WalkDir(filepath.Join(root, filepath.FromSlash(e.Path)), func(_ string, d fs.DirEntry, err error) error {
				if err == nil && d.Type().IsRegular() {
					if info, ierr := d.Info(); ierr == nil {
						e.Size += info.Size()
						e.Files++
					}
				}
				return nil
			})
		}(&r.Excluded[i])
	}
	wg.Wait()
	sort.SliceStable(r.Excluded, func(i, j int) bool { return r.Excluded[i].Size > r.Excluded[j].Size })
}

// ExcludedTotal returns the number of bytes and files left out.
func (r *ScanResult) ExcludedTotal() (size int64, files int) {
	for _, e := range r.Excluded {
		size += e.Size
		files += e.Files
	}
	return
}

// NewScanFromPaths builds a transfer plan from an explicit list of files
// (relative to root, forward slashes) instead of walking the tree: used to send
// only the changed files of a repository. Parent folders are added so the
// structure is preserved. Paths that escape root, are not regular files
// (symlinks, directories) or cannot be read are reported, never silently
// dropped.
func NewScanFromPaths(root, name string, paths []string) (*ScanResult, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", root, err)
	}
	res := &ScanResult{Root: abs, Name: name}
	dirs := map[string]bool{}
	var files []Entry
	for _, p := range paths {
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(p)))
		if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." || filepath.IsAbs(filepath.FromSlash(clean)) {
			return nil, fmt.Errorf("refusing path %q outside the repository", p)
		}
		st, err := os.Lstat(filepath.Join(abs, filepath.FromSlash(clean)))
		if err != nil {
			return nil, fmt.Errorf("inspect %s: %w", clean, err)
		}
		switch {
		case st.Mode().IsRegular():
			files = append(files, Entry{Path: clean, Size: st.Size(), Exec: st.Mode()&0o111 != 0})
			for d := path.Dir(clean); d != "."; d = path.Dir(d) {
				dirs[d] = true
			}
		case st.Mode()&fs.ModeSymlink != 0:
			res.Skipped = append(res.Skipped, Skipped{clean, "symbolic link"})
		default:
			res.Skipped = append(res.Skipped, Skipped{clean, "not a regular file"})
		}
	}
	for d := range dirs {
		res.Entries = append(res.Entries, Entry{Path: d, Dir: true})
		res.Dirs++
	}
	for _, f := range files {
		res.Entries = append(res.Entries, f)
		res.Files++
		res.TotalSize += f.Size
	}
	// Lexical order puts every parent before its children.
	sort.Slice(res.Entries, func(i, j int) bool { return res.Entries[i].Path < res.Entries[j].Path })
	if len(res.Entries) > MaxEntries {
		return nil, fmt.Errorf("more than %d files; send fewer", MaxEntries)
	}
	return res, nil
}
