package cli

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/thameem/drop/internal/active"
	"github.com/thameem/drop/internal/clipboard"
	"github.com/thameem/drop/internal/security"
	"github.com/thameem/drop/internal/transfer"
)

func key(s string) tea.KeyMsg {
	switch s {
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "space":
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	case "ctrl+u":
		return tea.KeyMsg{Type: tea.KeyCtrlU}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func press(m clipPicker, keys ...string) clipPicker {
	for _, k := range keys {
		next, _ := m.Update(key(k))
		m = next.(clipPicker)
	}
	return m
}

func newPicker(n int) clipPicker {
	items := make([]clipItem, n)
	for i := range items {
		items[i] = newClipItem(strings.Repeat("x", i+1), time.Now())
	}
	return clipPicker{items: items, selected: map[int]bool{}, width: 80, height: 24, history: true}
}

func TestPickerSendsHighlightedWhenNothingSelected(t *testing.T) {
	m := press(newPicker(4), "down", "down", "enter")
	if got := m.result(); len(got) != 1 || got[0] != 2 || !m.done {
		t.Fatalf("%v done=%v", got, m.done)
	}
}

func TestPickerSpaceSelectsManyInListOrder(t *testing.T) {
	m := press(newPicker(5), "down", "space", "down", "down", "space", "up", "up", "up", "space", "enter")
	if got := m.result(); len(got) != 3 || got[0] != 0 || got[1] != 1 || got[2] != 3 {
		t.Fatalf("%v", got)
	}
	m = press(m, "space") // unselect the highlighted one again
	if len(m.selected) != 2 {
		t.Fatalf("%v", m.selected)
	}
}

func TestPickerSelectAllToggleAndBounds(t *testing.T) {
	m := press(newPicker(3), "a")
	if got := m.result(); len(got) != 3 {
		t.Fatalf("select all: %v", got)
	}
	m = press(m, "a")
	if len(m.selected) != 0 {
		t.Fatal("second 'a' must clear the selection")
	}
	m = press(m, "up", "up", "up")
	if m.cursor != 0 {
		t.Fatalf("cursor above the list: %d", m.cursor)
	}
	m = press(m, "down", "down", "down", "down", "down")
	if m.cursor != 2 {
		t.Fatalf("cursor below the list: %d", m.cursor)
	}
	if m = press(m, "esc"); !m.cancel {
		t.Fatal("esc must cancel")
	}
}

func TestPickerViewFitsAndScrolls(t *testing.T) {
	m := newPicker(50)
	m.height, m.width = 12, 60
	m = press(m, "down", "down", "down", "down", "down", "down", "down", "down", "down", "down", "down", "down")
	v := m.View()
	for _, line := range strings.Split(v, "\n") {
		if n := len([]rune(line)); n > 60 {
			t.Errorf("line wider than the terminal (%d): %q", n, line)
		}
	}
	if strings.Count(v, "\n") > 12 {
		t.Errorf("view taller than the terminal: %d lines", strings.Count(v, "\n"))
	}
	if !strings.Contains(v, "❯") {
		t.Error("cursor row scrolled out of view")
	}
}

func TestClipItemFlagsSecretsAndFlattensLines(t *testing.T) {
	it := newClipItem("key AKIAABCDEFGHIJKLMNOP\nsecond line\x1b[31m", time.Now())
	if it.secret == "" {
		t.Error("an AWS key was not flagged")
	}
	if strings.ContainsAny(it.oneRow, "\n\x1b") || !strings.Contains(it.oneRow, "(+1 lines)") {
		t.Errorf("preview %q", it.oneRow)
	}
	if newClipItem("just a note", time.Now()).secret != "" {
		t.Error("plain text flagged")
	}
}

func TestCollectPutsCurrentFirstWithoutDuplicates(t *testing.T) {
	hist := []clipboard.Entry{{Text: "b"}, {Text: "cur"}, {Text: "a"}}
	got := collectClipEntries("cur", hist)
	if len(got) != 3 || got[0].Text != "cur" || got[1].Text != "b" || got[2].Text != "a" {
		t.Fatalf("%+v", got)
	}
	if got := collectClipEntries("  ", hist[:1]); len(got) != 1 || got[0].Text != "b" {
		t.Fatalf("blank current clipboard must not be listed: %+v", got)
	}
}

type fakeClip struct {
	mu sync.Mutex
	s  string
}

func (f *fakeClip) Read() (string, error) { f.mu.Lock(); defer f.mu.Unlock(); return f.s, nil }
func (f *fakeClip) Write(s string) error  { f.mu.Lock(); f.s = s; f.mu.Unlock(); return nil }

func TestWatcherRecordsChangesOnlyWhileEnabled(t *testing.T) {
	be := &fakeClip{s: "start"}
	hist := clipboard.OpenHistory(t.TempDir())
	var on sync.Mutex
	enabled := true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		watchClipboard(ctx, be, hist, func() bool { on.Lock(); defer on.Unlock(); return enabled }, 10*time.Millisecond)
		close(done)
	}()
	wait := func(n int) {
		for i := 0; i < 200 && len(hist.List()) < n; i++ {
			time.Sleep(10 * time.Millisecond)
		}
	}
	wait(1)
	be.Write("one")
	wait(2)
	on.Lock()
	enabled = false
	on.Unlock()
	time.Sleep(50 * time.Millisecond)
	be.Write("while off")
	time.Sleep(80 * time.Millisecond)
	cancel()
	<-done
	es := hist.List()
	if len(es) != 2 || es[0].Text != "one" || es[1].Text != "start" {
		t.Fatalf("%+v", es)
	}
}

func TestHazardousControlsDetection(t *testing.T) {
	for _, ok := range []string{"plain", "tabs\tand\nlines\r\n", "ünï ✓"} {
		if hasHazardousControls(ok) {
			t.Errorf("%q flagged", ok)
		}
	}
	for _, bad := range []string{"\x1b[31mred", "bell\x07", "nul\x00", "del\x7f"} {
		if !hasHazardousControls(bad) {
			t.Errorf("%q not flagged", bad)
		}
	}
}

func TestAutoAcceptRulesForClipboardAndText(t *testing.T) {
	dir := t.TempDir()
	a := &app{active: active.OpenStore(dir)}
	set := func(clip bool) {
		a.active.Update(func(st *active.Settings) error {
			st.Enabled, st.Clipboard, st.Dir = true, clip, dir
			st.Devices = []string{"dev1"}
			st.Networks = []active.Network{{Name: "Elsewhere", GatewayMAC: "aa:bb:cc:dd:ee:ff"}} // never this machine's router
			return nil
		})
	}
	accepted := func(ty security.TransferType, trusted bool) bool {
		auth := ""
		if trusted {
			auth = "trusted"
		}
		d, _ := a.activeAccept(context.Background(), transfer.Incoming{Type: ty, AuthMethod: auth, KeyID: "dev1", Addr: "192.168.1.5:1234"})
		return d.Accept
	}
	set(false)
	if accepted(security.TransferClipboard, true) {
		t.Error("clipboard auto-accepted while live clipboard is off")
	}
	set(true)
	if accepted(security.TransferClipboard, true) {
		t.Error("clipboard auto-accepted although this is not a saved network")
	}
	if accepted(security.TransferClipboard, false) {
		t.Error("clipboard auto-accepted from a device that is not trusted")
	}
	for _, on := range []bool{false, true} {
		set(on)
		if accepted(security.TransferText, true) {
			t.Error("text must never be auto-accepted by active sharing")
		}
	}
}
