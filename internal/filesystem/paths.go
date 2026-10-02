// Package filesystem holds path-safety helpers shared by sender and receiver.
package filesystem

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// ErrUnsafeName is returned for names that must never reach the filesystem.
var ErrUnsafeName = errors.New("unsafe file name")

// maxNameBytes is the common per-component limit across ext4, NTFS and APFS.
const maxNameBytes = 255

var windowsReserved = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// SafeName validates a single file name received from a peer and returns a
// form that is safe to create on any supported OS. Names that try to escape
// the destination (separators, "..", absolute paths, drive letters) are
// rejected rather than silently rewritten; merely OS-incompatible characters
// are replaced with '_'.
func SafeName(name string) (string, error) {
	if name == "" || name == "." || name == ".." {
		return "", fmt.Errorf("%w: %q", ErrUnsafeName, name)
	}
	if !utf8.ValidString(name) {
		return "", fmt.Errorf("%w: not valid UTF-8", ErrUnsafeName)
	}
	if strings.ContainsAny(name, "/\\") {
		return "", fmt.Errorf("%w: %q contains a path separator", ErrUnsafeName, name)
	}
	if len(name) >= 2 && name[1] == ':' { // C:foo — a Windows drive-relative path
		return "", fmt.Errorf("%w: %q looks like a drive path", ErrUnsafeName, name)
	}
	out := []rune(name)
	for i, r := range out {
		if r == 0 {
			return "", fmt.Errorf("%w: contains NUL", ErrUnsafeName)
		}
		if r < 0x20 || r == 0x7f || strings.ContainsRune(`<>:"|?*`, r) {
			out[i] = '_'
		}
	}
	s := strings.TrimRight(string(out), ". ") // Windows strips trailing dots/spaces
	if s == "" {
		return "", fmt.Errorf("%w: %q", ErrUnsafeName, name)
	}
	stem := s
	if i := strings.IndexByte(s, '.'); i >= 0 {
		stem = s[:i]
	}
	if windowsReserved[strings.ToUpper(stem)] {
		s = "_" + s
	}
	if len(s) > maxNameBytes {
		return "", fmt.Errorf("%w: name longer than %d bytes", ErrUnsafeName, maxNameBytes)
	}
	return s, nil
}

// ReserveUnique atomically creates an empty file named name inside dir, or
// "name (1).ext", "name (2).ext", ... if taken, and returns its path. It never
// follows or overwrites an existing entry (O_EXCL), so it is safe against races
// and pre-planted symlinks.
func ReserveUnique(dir, name string) (string, error) {
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 0; i < 10000; i++ {
		candidate := name
		if i > 0 {
			candidate = fmt.Sprintf("%s (%d)%s", stem, i, ext)
		}
		p := filepath.Join(dir, candidate)
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			f.Close()
			return p, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("create %s: %w", p, err)
		}
	}
	return "", fmt.Errorf("no free name for %q in %s", name, dir)
}

// RenameUnique moves src to dir/name, or "name (1)", "name (2)", ... if that
// name is taken, and returns the final path. It never replaces an existing
// entry: it only renames onto a name that does not exist.
func RenameUnique(src, dir, name string) (string, error) {
	for i := 0; i < 10000; i++ {
		candidate := name
		if i > 0 {
			candidate = fmt.Sprintf("%s (%d)", name, i)
		}
		p := filepath.Join(dir, candidate)
		if _, err := os.Lstat(p); err == nil {
			continue
		}
		if err := os.Rename(src, p); err != nil {
			if _, serr := os.Lstat(p); serr == nil {
				continue // lost a race for this name; try the next
			}
			return "", fmt.Errorf("move %s to %s: %w", src, p, err)
		}
		return p, nil
	}
	return "", fmt.Errorf("no free name for %q in %s", name, dir)
}
