package project

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/thameem/drop/internal/filesystem"
)

// Options select which protections apply.
type Options struct {
	// Project enables the project-only rules: version-control folders, .gitignore
	// and generated directories. Without it only secret protection applies.
	Project bool
	// IncludeSecrets disables secret protection (explicit user override).
	IncludeSecrets bool
}

// generated directories: name -> (reason, eligibility check on the parent dir).
type genRule struct {
	reason string
	// ok decides whether the directory abs is really generated output.
	ok func(abs string) bool
}

func always(string) bool { return true }

func hasSibling(names ...string) func(string) bool {
	return func(abs string) bool {
		parent := filepath.Dir(abs)
		for _, n := range names {
			if _, err := os.Lstat(filepath.Join(parent, n)); err == nil {
				return true
			}
		}
		return false
	}
}

var generated = map[string]genRule{
	"node_modules":  {"dependencies", always},
	"__pycache__":   {"Python bytecode cache", always},
	".pytest_cache": {"test cache", always},
	".mypy_cache":   {"type-checker cache", always},
	".ruff_cache":   {"linter cache", always},
	".tox":          {"test environments", always},
	".gradle":       {"build cache", always},
	".next":         {"build output", hasSibling("package.json")},
	".nuxt":         {"build output", hasSibling("package.json")},
	".cache":        {"cache", always},
	"coverage":      {"coverage reports", always},
	"dist":          {"build output", always},
	"build":         {"build output", always},
	// "target" is only generated for Rust/Maven; elsewhere it may be real source.
	"target": {"build output", hasSibling("Cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts")},
	// "venv"/".venv"/"env" are named freely; a pyvenv.cfg inside is what makes it a virtualenv.
	".venv": {"virtual environment", always},
	"venv":  {"virtual environment", isVenv},
	"env":   {"virtual environment", isVenv},
}

func isVenv(abs string) bool {
	_, err := os.Lstat(filepath.Join(abs, "pyvenv.cfg"))
	return err == nil
}

// junkFiles are OS litter with no value in a transfer.
var junkFiles = map[string]bool{".DS_Store": true, "Thumbs.db": true, "desktop.ini": true}

// NewRules returns the exclusion rules for a transfer rooted at root. It
// implements filesystem.Rules.
func NewRules(root string, o Options) filesystem.Rules {
	r := &rules{root: root, opts: o, matchers: map[string]*Matcher{}}
	if o.Project {
		if data, err := os.ReadFile(filepath.Join(root, ".git", "info", "exclude")); err == nil {
			r.exclude = ParseIgnore("", data)
		}
		r.load("") // root .gitignore
	}
	return r
}

type rules struct {
	root     string
	opts     Options
	exclude  *Matcher            // .git/info/exclude, lowest precedence
	matchers map[string]*Matcher // by directory (relative, "" for root)
}

func (r *rules) load(dirRel string) {
	if _, done := r.matchers[dirRel]; done {
		return
	}
	var m *Matcher
	if data, err := os.ReadFile(filepath.Join(r.root, filepath.FromSlash(dirRel), ".gitignore")); err == nil {
		m = ParseIgnore(dirRel, data)
	}
	r.matchers[dirRel] = m
}

// Decide implements filesystem.Rules.
func (r *rules) Decide(abs, rel string, d fs.DirEntry) *filesystem.Exclusion {
	name := d.Name()
	isDir := d.IsDir()

	if r.opts.Project && isDir && name == ".git" {
		return &filesystem.Exclusion{Category: filesystem.CatVCS, Detail: "Git history"}
	}
	if r.opts.Project && !isDir && junkFiles[name] {
		return &filesystem.Exclusion{Category: filesystem.CatGenerated, Detail: "OS metadata"}
	}

	if !r.opts.IncludeSecrets {
		if isDir {
			if why, ok := sensitiveDirs[name]; ok {
				return &filesystem.Exclusion{Category: filesystem.CatSensitive, Detail: why}
			}
		} else if d.Type().IsRegular() {
			if why, ok := SensitiveName(name); ok {
				return &filesystem.Exclusion{Category: filesystem.CatSensitive, Detail: why}
			}
			if info, err := d.Info(); err == nil {
				if kind, ok := ScanContent(abs, info.Size()); ok {
					return &filesystem.Exclusion{Category: filesystem.CatSensitive, Detail: "matches a known credential format: " + kind}
				}
			}
		}
	}

	if !r.opts.Project {
		return nil
	}
	if ignored, why := r.gitignored(rel, isDir); ignored {
		return &filesystem.Exclusion{Category: filesystem.CatGitignore, Detail: why}
	}
	if isDir {
		if g, ok := generated[name]; ok && g.ok(abs) {
			return &filesystem.Exclusion{Category: filesystem.CatGenerated, Detail: g.reason}
		}
		r.load(rel) // read this directory's own .gitignore before its children are visited
	}
	return nil
}

// gitignored applies every applicable ignore file, shallowest first, so a
// deeper file or a later line overrides an earlier one.
func (r *rules) gitignored(rel string, isDir bool) (bool, string) {
	ignored, source := false, ""
	apply := func(m *Matcher, label string) {
		if m == nil {
			return
		}
		if g, decided := m.match(rel, isDir); decided {
			ignored, source = g, label
		}
	}
	apply(r.exclude, ".git/info/exclude")
	apply(r.matchers[""], ".gitignore")
	parts := strings.Split(path.Dir(rel), "/")
	if path.Dir(rel) == "." {
		parts = nil
	}
	dir := ""
	for _, p := range parts {
		dir = path.Join(dir, p)
		apply(r.matchers[dir], path.Join(dir, ".gitignore"))
	}
	if ignored {
		return true, "listed in " + source
	}
	return false, ""
}
