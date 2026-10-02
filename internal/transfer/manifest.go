package transfer

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/thameem/drop/internal/filesystem"
)

// Manifest limits. A manifest comes from an untrusted peer, so all of these are
// enforced before a single directory or file is created.
const (
	MaxManifestBytes = 64 << 20
	MaxPathDepth     = 64
	MaxPathBytes     = 1024
)

// ManifestEntry is one directory or file. Hashes are not here: they are sent
// as a trailer after each file's bytes so the sender reads every file once.
type ManifestEntry struct {
	Path string `json:"p"` // relative, forward slashes
	Dir  bool   `json:"d,omitempty"`
	Size int64  `json:"s,omitempty"`
	Exec bool   `json:"x,omitempty"`
}

// Manifest describes a folder transfer.
type Manifest struct {
	Entries []ManifestEntry `json:"entries"`
}

// Planned is a validated entry with the on-disk relative path the receiver will
// use (components made safe for every OS).
type Planned struct {
	ManifestEntry
	Local []string
}

// Plan is a fully validated manifest.
type Plan struct {
	Entries []Planned
	Files   int
	Dirs    int
	Total   int64
}

// NewManifest converts a scan into a manifest.
func NewManifest(scan *filesystem.ScanResult) *Manifest {
	m := &Manifest{Entries: make([]ManifestEntry, len(scan.Entries))}
	for i, e := range scan.Entries {
		m.Entries[i] = ManifestEntry{Path: e.Path, Dir: e.Dir, Size: e.Size, Exec: e.Exec}
	}
	return m
}

// Marshal encodes the manifest deterministically.
func (m *Manifest) Marshal() ([]byte, error) { return json.Marshal(m) }

// ParseManifest decodes and strictly validates an untrusted manifest.
func ParseManifest(data []byte) (*Manifest, *Plan, error) {
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, nil, fmt.Errorf("invalid manifest: %w", err)
	}
	plan, err := m.Validate()
	if err != nil {
		return nil, nil, err
	}
	return &m, plan, nil
}

// Validate checks every path and structural rule. It never trusts the sender:
//   - each component is made safe by filesystem.SafeName (traversal, absolute
//     paths, separators, drive prefixes, NUL, Windows reserved names rejected);
//   - two entries may not map to the same name on a case-insensitive file
//     system (so nothing can silently overwrite anything else);
//   - every entry's parent directory must be declared earlier;
//   - a path cannot be both a file and a directory;
//   - sizes must be non-negative and entry counts and depth are bounded.
func (m *Manifest) Validate() (*Plan, error) {
	if len(m.Entries) > filesystem.MaxEntries {
		return nil, fmt.Errorf("invalid manifest: %d entries exceeds the limit of %d", len(m.Entries), filesystem.MaxEntries)
	}
	plan := &Plan{Entries: make([]Planned, 0, len(m.Entries))}
	dirs := map[string]bool{"": true} // local, case-folded path -> is directory
	seen := map[string]bool{}
	for i, e := range m.Entries {
		local, err := safeComponents(e.Path)
		if err != nil {
			return nil, fmt.Errorf("invalid manifest entry %d (%q): %w", i+1, trunc(e.Path), err)
		}
		if e.Size < 0 || (e.Dir && e.Size != 0) {
			return nil, fmt.Errorf("invalid manifest entry %d (%q): bad size", i+1, trunc(e.Path))
		}
		key := strings.ToLower(strings.Join(local, "/"))
		parent := strings.ToLower(strings.Join(local[:len(local)-1], "/"))
		if !dirs[parent] {
			return nil, fmt.Errorf("invalid manifest entry %d (%q): parent folder was not declared", i+1, trunc(e.Path))
		}
		if seen[key] {
			return nil, fmt.Errorf("invalid manifest entry %d (%q): duplicate path, or names that differ only by case or unsafe characters", i+1, trunc(e.Path))
		}
		seen[key] = true
		if e.Dir {
			dirs[key] = true
			plan.Dirs++
		} else {
			plan.Files++
			plan.Total += e.Size
			if plan.Total < 0 {
				return nil, errors.New("invalid manifest: total size overflows")
			}
		}
		plan.Entries = append(plan.Entries, Planned{ManifestEntry: e, Local: local})
	}
	return plan, nil
}

func safeComponents(p string) ([]string, error) {
	if p == "" {
		return nil, errors.New("empty path")
	}
	if len(p) > MaxPathBytes {
		return nil, errors.New("path too long")
	}
	parts := strings.Split(p, "/")
	if len(parts) > MaxPathDepth {
		return nil, errors.New("path too deep")
	}
	out := make([]string, len(parts))
	for i, c := range parts {
		s, err := filesystem.SafeName(c) // rejects "", ".", "..", separators, drive prefixes, NUL
		if err != nil {
			return nil, err
		}
		out[i] = s
	}
	return out, nil
}

func trunc(s string) string {
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}
