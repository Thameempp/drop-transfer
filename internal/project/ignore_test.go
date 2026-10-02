package project

import "testing"

func ign(t *testing.T, patterns, path string, dir bool) bool {
	t.Helper()
	got, _ := ParseIgnore("", []byte(patterns)).match(path, dir)
	return got
}

func TestIgnorePatterns(t *testing.T) {
	cases := []struct {
		pats, path string
		dir, want  bool
	}{
		{"*.log", "a.log", false, true},
		{"*.log", "sub/dir/a.log", false, true},
		{"*.log", "a.logx", false, false},
		{"build/", "build", true, true},
		{"build/", "build", false, false}, // a file called build is not matched by "build/"
		{"build/", "src/build", true, true},
		{"/build", "build", true, true},
		{"/build", "src/build", true, false}, // anchored to the root
		{"doc/frotz", "doc/frotz", false, true},
		{"doc/frotz", "a/doc/frotz", false, false}, // slash in the middle anchors
		{"a/**/b", "a/b", false, true},
		{"a/**/b", "a/x/y/b", false, true},
		{"a/**/b", "ab", false, false},
		{"**/foo", "foo", false, true},
		{"**/foo", "x/y/foo", false, true},
		{"abc/**", "abc/x", false, true},
		{"abc/**", "abc", true, false}, // "/**" matches inside, not the directory
		{"foo/*", "foo/x", false, true},
		{"foo/*", "foo/x/y", false, false}, // '*' does not cross '/'
		{"f?o", "foo", false, true},
		{"f?o", "f/o", false, false},
		{"[abc].txt", "b.txt", false, true},
		{"[!abc].txt", "d.txt", false, true},
		{"[!abc].txt", "a.txt", false, false},
		{`\#notcomment`, "#notcomment", false, true},
		{"# comment\n*.tmp", "x.tmp", false, true},
		{`\!important`, "!important", false, true},
		{"*.txt\n!keep.txt", "keep.txt", false, false}, // negation re-includes
		{"*.txt\n!keep.txt", "other.txt", false, true},
		{"!keep.txt\n*.txt", "keep.txt", false, true}, // last match wins
		{"trailing   ", "trailing", false, true},      // trailing spaces trimmed
		{"", "a", false, false},
		{"\n\n   \n", "a", false, false},
		{"*.py[cod]", "x.pyc", false, true},
		{"CRLF.txt\r\n*.o\r\n", "a.o", false, true},
	}
	for _, c := range cases {
		if got := ign(t, c.pats, c.path, c.dir); got != c.want {
			t.Errorf("patterns %q path %q dir=%v: got %v want %v", c.pats, c.path, c.dir, got, c.want)
		}
	}
}

func TestNestedIgnoreBase(t *testing.T) {
	m := ParseIgnore("pkg/sub", []byte("*.gen\n/only-here\n"))
	if g, d := m.match("pkg/sub/x.gen", false); !g || !d {
		t.Fatal("pattern inside base should match")
	}
	if g, _ := m.match("x.gen", false); g {
		t.Fatal("pattern outside its directory must not apply")
	}
	if g, _ := m.match("pkg/sub/only-here", false); !g {
		t.Fatal("anchored to its own directory")
	}
	if g, _ := m.match("pkg/only-here", false); g {
		t.Fatal("anchored pattern leaked to parent")
	}
}

func TestMalformedPatternsDoNotPanic(t *testing.T) {
	for _, p := range []string{`\`, `[`, `[]`, `[a`, `a[`, `**`, `***`, `!`, `/`, `//`, "a\\", `[!`, `*[`} {
		ParseIgnore("", []byte(p)).match("a/b", false)
	}
}
