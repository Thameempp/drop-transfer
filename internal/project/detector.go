package project

import (
	"os"
	"path/filepath"
	"sort"
)

// Info describes a detected project root.
type Info struct {
	Name    string
	Root    string
	Kinds   []string // e.g. "Go", "Node.js"
	Markers []string // files/directories that identified it
}

type marker struct {
	file string
	kind string // "" for generic markers (git, make)
}

// strong markers identify a project on their own.
var strong = []marker{
	{".git", "Git"},
	{"go.mod", "Go"},
	{"package.json", "Node.js"},
	{"pyproject.toml", "Python"},
	{"requirements.txt", "Python"},
	{"setup.py", "Python"},
	{"Cargo.toml", "Rust"},
	{"pom.xml", "Java"},
	{"build.gradle", "Java/Kotlin"},
	{"build.gradle.kts", "Java/Kotlin"},
	{"Gemfile", "Ruby"},
	{"composer.json", "PHP"},
	{"CMakeLists.txt", "C/C++"},
	{"Makefile", ""},
}

// weak markers only count together with a strong one: a lone README.md does
// not make a directory a project.
var weak = []string{"README.md", "README"}

// Detect inspects dir (only dir itself, never its parents) and reports whether
// it is a project. Not every directory is: a folder of photos with a README is
// just a folder.
func Detect(dir string) (*Info, bool) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, false
	}
	info := &Info{Name: filepath.Base(abs), Root: abs}
	kinds := map[string]bool{}
	for _, m := range strong {
		if _, err := os.Lstat(filepath.Join(abs, m.file)); err == nil {
			info.Markers = append(info.Markers, m.file)
			if m.kind != "" && !kinds[m.kind] {
				kinds[m.kind] = true
				info.Kinds = append(info.Kinds, m.kind)
			}
		}
	}
	if len(info.Markers) == 0 {
		return nil, false
	}
	for _, w := range weak {
		if _, err := os.Lstat(filepath.Join(abs, w)); err == nil {
			info.Markers = append(info.Markers, w)
		}
	}
	sort.Strings(info.Kinds)
	return info, true
}
