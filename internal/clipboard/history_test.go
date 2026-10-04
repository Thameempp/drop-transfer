package clipboard

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestHistoryNewestFirstDedupeAndCap(t *testing.T) {
	h := OpenHistory(t.TempDir())
	for _, s := range []string{"a", "b", "c", "a"} {
		if err := h.Add(s); err != nil {
			t.Fatal(err)
		}
	}
	es := h.List()
	if len(es) != 3 || es[0].Text != "a" || es[1].Text != "c" || es[2].Text != "b" {
		t.Fatalf("%+v", es)
	}
	for i := 0; i < MaxEntries+10; i++ {
		h.Add(strings.Repeat("x", i+1))
	}
	if n := len(h.List()); n != MaxEntries {
		t.Fatalf("kept %d entries", n)
	}
}

func TestHistoryIgnoresUnrecordableAndClears(t *testing.T) {
	dir := t.TempDir()
	h := OpenHistory(dir)
	h.Add("   \n")
	h.Add(strings.Repeat("y", MaxEntrySize+1))
	h.Add("bad\xff")
	if len(h.List()) != 0 {
		t.Fatal("unrecordable text stored")
	}
	h.Add("secret")
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(filepath.Join(dir, "clipboard_history.json")); st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", st.Mode().Perm())
		}
	}
	if err := h.Clear(); err != nil || len(h.List()) != 0 {
		t.Fatal("clear failed")
	}
	if err := h.Clear(); err != nil {
		t.Fatal("clearing twice must be fine")
	}
}
