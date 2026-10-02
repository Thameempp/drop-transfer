// Package project makes directory transfers developer-aware: it recognises
// projects, honours .gitignore, leaves out generated directories, and keeps
// likely secrets from leaving the machine by accident.
package project

import (
	"regexp"
	"strings"
)

// pattern is one compiled .gitignore line.
type pattern struct {
	re      *regexp.Regexp
	negate  bool
	dirOnly bool
}

// Matcher holds the patterns of one ignore file, whose directory (relative to
// the transfer root, forward slashes, "" for the root) is base.
type Matcher struct {
	base string
	pats []pattern
}

// ParseIgnore compiles .gitignore content located in directory base. It
// implements the documented git semantics: comments, blank lines, trailing-space
// trimming, "!" negation, "\" escapes, trailing "/" (directories only), anchoring
// of patterns containing a slash, "*", "?", "[...]", and "**".
func ParseIgnore(base string, data []byte) *Matcher {
	m := &Matcher{base: base}
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if p, ok := compileLine(line); ok {
			m.pats = append(m.pats, p)
		}
	}
	return m
}

func compileLine(line string) (pattern, bool) {
	// Trailing spaces are ignored unless escaped with a backslash.
	for strings.HasSuffix(line, " ") && !strings.HasSuffix(line, `\ `) {
		line = line[:len(line)-1]
	}
	if line == "" || strings.HasPrefix(line, "#") {
		return pattern{}, false
	}
	var p pattern
	if strings.HasPrefix(line, "!") {
		p.negate = true
		line = line[1:]
	}
	if strings.HasSuffix(line, "/") {
		p.dirOnly = true
		line = strings.TrimRight(line, "/")
	}
	if line == "" {
		return pattern{}, false
	}
	// A slash at the start or in the middle anchors the pattern to base.
	anchored := strings.Contains(strings.TrimPrefix(line, "/"), "/") || strings.HasPrefix(line, "/")
	line = strings.TrimPrefix(line, "/")

	body, ok := globToRegex(line)
	if !ok {
		return pattern{}, false
	}
	var expr string
	if anchored {
		expr = "^" + body + "$"
	} else {
		expr = "(?:^|.*/)" + body + "$"
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return pattern{}, false
	}
	p.re = re
	return p, true
}

// globToRegex translates a gitignore glob (without leading/trailing slash) to
// a regular expression body.
func globToRegex(g string) (string, bool) {
	var b strings.Builder
	rs := []rune(g)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch c {
		case '\\':
			i++
			if i >= len(rs) {
				return "", false // dangling escape: git ignores such a pattern
			}
			b.WriteString(regexp.QuoteMeta(string(rs[i])))
		case '*':
			if i+1 < len(rs) && rs[i+1] == '*' {
				atStart := i == 0 || rs[i-1] == '/'
				j := i + 2
				atEnd := j == len(rs)
				followedBySlash := j < len(rs) && rs[j] == '/'
				switch {
				case atStart && followedBySlash: // "**/" : zero or more directories
					b.WriteString("(?:.*/)?")
					i = j // consume the slash
				case atStart && atEnd, i > 0 && rs[i-1] == '/' && atEnd: // "/**" or "**": everything inside
					b.WriteString(".*")
					i = j - 1
				default: // "a**b" behaves like "*"
					b.WriteString("[^/]*")
					i++
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '[':
			end := i + 1
			if end < len(rs) && (rs[end] == '!' || rs[end] == '^') {
				end++
			}
			if end < len(rs) && rs[end] == ']' {
				end++
			}
			for end < len(rs) && rs[end] != ']' {
				end++
			}
			if end >= len(rs) { // unterminated class: literal '['
				b.WriteString(`\[`)
				continue
			}
			class := string(rs[i+1 : end])
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			b.WriteString("[" + strings.ReplaceAll(class, `\`, `\\`) + "]")
			i = end
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String(), true
}

// match reports the verdict of this file's patterns for rel (relative to the
// transfer root). decided is false if no pattern applied. The last matching
// pattern wins, as in git.
func (m *Matcher) match(rel string, isDir bool) (ignored, decided bool) {
	sub := rel
	if m.base != "" {
		if !strings.HasPrefix(rel, m.base+"/") {
			return false, false
		}
		sub = rel[len(m.base)+1:]
	}
	for _, p := range m.pats {
		if p.dirOnly && !isDir {
			continue
		}
		if p.re.MatchString(sub) {
			ignored, decided = !p.negate, true
		}
	}
	return
}
