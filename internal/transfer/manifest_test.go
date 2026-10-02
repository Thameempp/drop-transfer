package transfer

import (
	"fmt"
	"strings"
	"testing"
)

func f(p string, size int64) ManifestEntry { return ManifestEntry{Path: p, Size: size} }
func d(p string) ManifestEntry             { return ManifestEntry{Path: p, Dir: true} }

func TestManifestAcceptsNormalTree(t *testing.T) {
	m := &Manifest{Entries: []ManifestEntry{
		d("src"), d("src/utils"), f("src/main.py", 10), f("src/utils/helpers.py", 5),
		d("my docs"), f("my docs/résumé 日本.txt", 0), f("README.md", 3), d("empty"),
	}}
	plan, err := m.Validate()
	if err != nil {
		t.Fatal(err)
	}
	if plan.Files != 4 || plan.Dirs != 4 || plan.Total != 18 {
		t.Fatalf("%+v", plan)
	}
}

func TestManifestRejectsHostileEntries(t *testing.T) {
	deep := strings.Repeat("a/", MaxPathDepth) + "x"
	deepDirs := []ManifestEntry{}
	for i := 1; i <= MaxPathDepth+1; i++ {
		deepDirs = append(deepDirs, d(strings.TrimSuffix(strings.Repeat("a/", i), "/")))
	}
	cases := map[string][]ManifestEntry{
		"parent traversal":      {f("../evil", 1)},
		"nested traversal":      {d("a"), f("a/../../evil", 1)},
		"absolute":              {f("/etc/passwd", 1)},
		"windows absolute":      {f(`C:\Windows\x`, 1)},
		"drive relative":        {f("C:evil", 1)},
		"backslash traversal":   {d("a"), f(`a\..\..\evil`, 1)},
		"dot":                   {f(".", 1)},
		"dotdot":                {f("..", 1)},
		"empty":                 {f("", 1)},
		"empty component":       {d("a"), f("a//b", 1)},
		"trailing slash":        {f("a/", 1)},
		"NUL":                   {f("a\x00b", 1)},
		"missing parent":        {f("a/b", 1)},
		"parent declared later": {f("a/b", 1), d("a")},
		"duplicate":             {f("a", 1), f("a", 1)},
		"case duplicate":        {f("Readme", 1), f("README", 1)},
		"dir/file collision":    {d("a"), f("a", 1)},
		"child of a file":       {f("a", 1), f("a/b", 1)},
		"unsafe-char collision": {f("ab:c", 1), f("ab_c", 1)},
		"negative size":         {f("a", -1)},
		"directory with size":   {{Path: "a", Dir: true, Size: 5}},
		"too deep":              {f(deep, 1)},
		"too deep via dirs":     deepDirs,
		"path too long":         {f(strings.Repeat("x", MaxPathBytes+1), 1)},
		"invalid utf8":          {f("a\xff", 1)},
		"size overflow":         {f("a", 1<<62), f("b", 1<<62), f("c", 1<<62)},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := (&Manifest{Entries: entries}).Validate(); err == nil {
				t.Fatalf("accepted: %v", entries)
			}
		})
	}
}

func TestManifestMakesWindowsReservedNamesSafe(t *testing.T) {
	plan, err := (&Manifest{Entries: []ManifestEntry{f("CON", 1), f("nul.txt", 1)}}).Validate()
	if err != nil {
		t.Fatal(err)
	}
	if plan.Entries[0].Local[0] != "_CON" || plan.Entries[1].Local[0] != "_nul.txt" {
		t.Fatalf("%v %v", plan.Entries[0].Local, plan.Entries[1].Local)
	}
}

func TestManifestLocalPathsNeverEscape(t *testing.T) {
	// Fuzz-ish: whatever validates must produce only single, separator-free components.
	for i := 0; i < 2000; i++ {
		p := fmt.Sprintf("%c%c/%c%c", rune(i%128), rune((i*7)%128), rune((i*13)%128), rune((i*31)%128))
		m := &Manifest{Entries: []ManifestEntry{d(strings.SplitN(p, "/", 2)[0]), f(p, 1)}}
		plan, err := m.Validate()
		if err != nil {
			continue
		}
		for _, e := range plan.Entries {
			for _, c := range e.Local {
				if c == "" || c == "." || c == ".." || strings.ContainsAny(c, `/\`) {
					t.Fatalf("unsafe component %q from %q", c, p)
				}
			}
		}
	}
}

func TestParseManifestRejectsMalformedAndUnknownFields(t *testing.T) {
	for _, in := range []string{``, `{`, `[]`, `{"entries":[{"p":"a","evil":1}]}`, `{"entries":"x"}`, `{"entries":[{"p":"a"}]} trailing`} {
		if _, _, err := ParseManifest([]byte(in)); err == nil && in != `{"entries":[{"p":"a"}]} trailing` {
			t.Errorf("accepted %q", in)
		}
	}
	if _, _, err := ParseManifest([]byte(`{"entries":[{"p":"a","s":1}]}`)); err != nil {
		t.Fatal(err)
	}
}
