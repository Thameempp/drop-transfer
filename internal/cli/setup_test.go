package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/thameem/drop/internal/active"
	"github.com/thameem/drop/internal/clipboard"
)

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

func setupApp(t *testing.T) *app {
	t.Helper()
	t.Setenv("DROP_HOME", t.TempDir())
	t.Setenv("DROP_NO_SERVICE", "1")
	t.Setenv("NO_COLOR", "1")
	a, err := loadApp(false)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func newTestSetup(t *testing.T) (*setupModel, *app) {
	a := setupApp(t)
	m := newSetupModel(a)
	m.routerFn = func() routerMsg { return routerMsg{mac: "aa:bb:cc:dd:ee:01", ssid: "HomeNet"} }
	m.Update(m.Init()()) // network detection result
	return m, a
}

func pressSetup(m *setupModel, keys ...string) {
	for _, k := range keys {
		m.Update(key(k))
	}
}

func typeText(m *setupModel, s string) {
	for _, r := range s {
		m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
}

// goTo moves the cursor onto the row with the given id.
func goTo(t *testing.T, m *setupModel, id string) {
	t.Helper()
	for i := 0; i < 40; i++ {
		m.Update(key("up")) // start from the top
	}
	for i := 0; i < 40; i++ {
		rs := m.rows()
		if c := m.clamp(rs); c >= 0 && rs[c].id == id {
			return
		}
		m.Update(key("down"))
	}
	t.Fatalf("row %q not reachable on screen %v", id, m.sc)
}

func trustDevice(t *testing.T, a *app, name string) string {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	d, err := a.trust.Add(pub, name, "linux")
	if err != nil {
		t.Fatal(err)
	}
	return d.ID
}

func plain(m *setupModel) string { return ansiRe.ReplaceAllString(m.View(), "") }

func TestSetupFreshUserIsGuidedStepByStep(t *testing.T) {
	m, a := newTestSetup(t)
	if !strings.Contains(m.nextStep(m.settings()), "Trusted devices") {
		t.Fatalf("first hint: %q", m.nextStep(m.settings()))
	}
	// Turning Active sharing on with nothing set up takes you to the first missing piece, and stays off.
	goTo(t, m, "active")
	pressSetup(m, "enter")
	if m.sc != scAllowed || m.settings().Enabled || !m.bad {
		t.Fatalf("screen=%v enabled=%v msg=%q", m.sc, m.settings().Enabled, m.msg)
	}
	id := trustDevice(t, a, "Work PC")
	if !strings.Contains(plain(m), "Work PC") {
		t.Fatalf("trusted device not listed:\n%s", plain(m))
	}
	pressSetup(m, "down", "space")
	if !m.settings().HasDevice(id) {
		t.Fatalf("device not allowed; rows=%+v", m.rows())
	}
	pressSetup(m, "space")
	if m.settings().HasDevice(id) {
		t.Fatal("space must toggle the device back off")
	}
	pressSetup(m, "space", "esc")
	if m.sc != scMain {
		t.Fatal("esc must go back")
	}
	goTo(t, m, "active")
	pressSetup(m, "enter")
	if m.sc != scNetworks {
		t.Fatalf("next missing piece is a network, got screen %v", m.sc)
	}
}

func TestSetupSavesNetworksAndTurnsFeaturesOnAndOff(t *testing.T) {
	m, a := newTestSetup(t)
	id := trustDevice(t, a, "Work PC")
	m.change(func(s *active.Settings) { s.Allow(id) })

	goTo(t, m, "networks")
	pressSetup(m, "enter") // into the networks screen
	goTo(t, m, "addnet")
	pressSetup(m, "enter")
	if m.in == nil || string(m.in.buf) != "HomeNet" {
		t.Fatalf("name prompt should offer the Wi-Fi name, got %+v", m.in)
	}
	pressSetup(m, "ctrl+u")
	typeText(m, "Home")
	pressSetup(m, "enter")
	st := m.settings()
	if len(st.Networks) != 1 || st.Networks[0].Name != "Home" || st.Networks[0].GatewayMAC != "aa:bb:cc:dd:ee:01" || st.Networks[0].SSID != "HomeNet" {
		t.Fatalf("%+v", st.Networks)
	}
	if !strings.Contains(plain(m), "connected now") {
		t.Fatalf("saved network should be marked as connected:\n%s", plain(m))
	}
	pressSetup(m, "esc")

	// folder is still missing: Active sharing points at it and stays off.
	goTo(t, m, "active")
	pressSetup(m, "enter")
	if m.settings().Enabled || !m.bad || !strings.Contains(m.msg, "folder") {
		t.Fatalf("msg=%q enabled=%v", m.msg, m.settings().Enabled)
	}
	goTo(t, m, "activedir")
	pressSetup(m, "enter")
	dir := filepath.Join(t.TempDir(), "Shared")
	typeText(m, dir)
	pressSetup(m, "enter")
	if m.settings().Dir != dir {
		t.Fatalf("dir %q", m.settings().Dir)
	}
	goTo(t, m, "active")
	pressSetup(m, "enter")
	if !m.settings().Enabled {
		t.Fatalf("should be on now: %q", m.msg)
	}
	pressSetup(m, "enter")
	if m.settings().Enabled {
		t.Fatal("second Enter must turn it off")
	}
	if !strings.Contains(m.nextStep(m.settings()), "Ready") {
		t.Fatalf("hint %q", m.nextStep(m.settings()))
	}

	// active clipboard (needs a clipboard tool on this system)
	if _, err := clipboard.System(); err == nil {
		goTo(t, m, "clip")
		pressSetup(m, "enter")
		if !m.settings().Clipboard {
			t.Fatalf("clipboard not on: %q", m.msg)
		}
		pressSetup(m, "enter")
		if m.settings().Clipboard {
			t.Fatal("clipboard not off")
		}
	}
	// forget the network, with confirmation
	goTo(t, m, "networks")
	pressSetup(m, "enter", "down", "enter")
	if m.confirm == nil {
		t.Fatal("removing a network must ask first")
	}
	pressSetup(m, "esc")
	if len(m.settings().Networks) != 1 {
		t.Fatal("cancelled removal changed something")
	}
	pressSetup(m, "enter", "y")
	if len(m.settings().Networks) != 0 {
		t.Fatalf("%+v", m.settings().Networks)
	}
}

func TestSetupRemoveTrustedDeviceAlsoRevokesAllowance(t *testing.T) {
	m, a := newTestSetup(t)
	id := trustDevice(t, a, "Work PC")
	m.change(func(s *active.Settings) { s.Allow(id) })
	goTo(t, m, "trusted")
	pressSetup(m, "enter", "down", "enter")
	if m.confirm == nil {
		t.Fatal("must confirm")
	}
	pressSetup(m, "enter")
	if len(a.trust.List()) != 0 || m.settings().HasDevice(id) {
		t.Fatalf("trusted=%d allowed=%v", len(a.trust.List()), m.settings().HasDevice(id))
	}
}

func TestSetupPINScreen(t *testing.T) {
	m, a := newTestSetup(t)
	goTo(t, m, "pin")
	pressSetup(m, "enter") // PIN screen
	pressSetup(m, "enter") // show: none yet -> created
	pin := m.pin
	if len(pin) != 6 {
		t.Fatalf("pin %q msg %q", pin, m.msg)
	}
	if got, _ := a.pins.Reveal(); got != pin {
		t.Fatal("shown PIN is not the stored one")
	}
	goTo(t, m, "newpin")
	pressSetup(m, "enter")
	if m.confirm == nil || m.pin != pin {
		t.Fatal("a new PIN must be confirmed first and must not change before")
	}
	pressSetup(m, "y")
	if m.pin == pin || len(m.pin) != 6 {
		t.Fatalf("new pin %q", m.pin)
	}
}

func TestSetupQuitAndViewFitsNarrowTerminals(t *testing.T) {
	m, a := newTestSetup(t)
	trustDevice(t, a, "A very long device name that keeps going and going")
	for _, w := range []int{30, 40, 60, 100} {
		m.width = w
		for _, sc := range []screen{scMain, scTrusted, scAllowed, scNetworks, scPIN} {
			m.sc = sc
			for _, line := range strings.Split(plain(m), "\n") {
				if n := len([]rune(line)); n > w-1 {
					t.Errorf("width %d screen %v: %d columns: %q", w, sc, n, line)
				}
			}
		}
	}
	m.sc = scMain
	pressSetup(m, "esc")
	if !m.done {
		t.Fatal("esc on the main screen must leave")
	}
	_ = context.Background
}
