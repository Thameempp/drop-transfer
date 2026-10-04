package clipboard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	// MaxEntries is how many entries the history keeps; older ones are dropped.
	MaxEntries = 50
	// MaxEntrySize is the largest single entry recorded. Bigger copies (a whole
	// document, a log) are skipped: this is meant for snippets, not storage.
	MaxEntrySize = 64 << 10
)

// Entry is one remembered copy.
type Entry struct {
	Text string    `json:"text"`
	At   time.Time `json:"at"`
}

// History is a small local list of copied text (clipboard_history.json, 0600),
// newest first. It never leaves this machine unless the user sends an entry.
type History struct {
	path string
	mu   sync.Mutex
}

func OpenHistory(dir string) *History {
	return &History{path: filepath.Join(dir, "clipboard_history.json")}
}

func (h *History) load() []Entry {
	var es []Entry
	if data, err := os.ReadFile(h.path); err == nil {
		_ = json.Unmarshal(data, &es)
	}
	return es
}

func (h *History) save(es []Entry) error {
	data, err := json.Marshal(es)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(h.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(h.path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), h.path)
}

// Recordable reports whether text is worth remembering.
func Recordable(text string) bool {
	return strings.TrimSpace(text) != "" && len(text) <= MaxEntrySize && utf8.ValidString(text)
}

// Add records text as the newest entry. A repeat moves to the top instead of
// duplicating. Text that is not Recordable is ignored.
func (h *History) Add(text string) error {
	if !Recordable(text) {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	es := h.load()
	out := make([]Entry, 0, len(es)+1)
	out = append(out, Entry{Text: text, At: time.Now().UTC()})
	for _, e := range es {
		if e.Text != text && len(out) < MaxEntries {
			out = append(out, e)
		}
	}
	return h.save(out)
}

// List returns the entries, newest first.
func (h *History) List() []Entry {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.load()
}

// Clear forgets everything.
func (h *History) Clear() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := os.Remove(h.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("clear clipboard history: %w", err)
	}
	return nil
}

// ID is a short stable identifier of an entry's text, for tests and display.
func ID(text string) string {
	s := sha256.Sum256([]byte(text))
	return hex.EncodeToString(s[:4])
}
