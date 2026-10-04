package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/thameem/drop/internal/active"
	"github.com/thameem/drop/internal/clipboard"
	"github.com/thameem/drop/internal/config"
	"github.com/thameem/drop/internal/discovery"
	"github.com/thameem/drop/internal/security"
)

func newSetupCmd(verbose *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "setup",
		Short: "Set up everything in one simple menu (active sharing, clipboard, trusted devices, networks)",
		Long: `An arrow-key menu to set drop up from scratch and change it later:

  • turn Active sharing and Active clipboard on or off
  • add or remove trusted devices
  • choose which trusted devices are allowed to send automatically
  • save or forget Wi-Fi/Ethernet networks they work on
  • choose the folders, and show or renew your Drop PIN

Everything saves the moment you change it. The same things are available as
commands (drop active ..., drop clipboard live ..., drop security ...).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !hasTTY() || !isTTY(os.Stderr) {
				return usageErr("`drop setup` is an interactive menu and needs a terminal; see `drop --help` for the equivalent commands")
			}
			a, err := loadApp(*verbose)
			if err != nil {
				return err
			}
			return a.runSetup()
		},
	}
}

type screen int

const (
	scMain screen = iota
	scTrusted
	scAllowed
	scNetworks
	scPIN
)

type srow struct {
	id    string
	label string
	value string
	desc  string
	sep   bool
	state string // "", "on", "off", "yes", "no"
}

type routerMsg struct{ mac, ssid string }
type trustDoneMsg struct{ err error }

type confirmState struct {
	prompt string
	yes    func() string
}

type inputState struct {
	label string
	buf   []rune
	ok    func(string) string
}

type setupModel struct {
	a       *app
	sc      screen
	cursor  map[screen]int
	width   int
	msg     string
	bad     bool
	pin     string // shown on the PIN screen
	confirm *confirmState
	in      *inputState

	here, wifi string // current router address and Wi-Fi name ("" until known)
	probed     bool

	routerFn func() routerMsg // detecting the network; replaceable in tests
	done     bool
}

func newSetupModel(a *app) *setupModel {
	return &setupModel{a: a, cursor: map[screen]int{}, width: 80, routerFn: detectRouter}
}

func detectRouter() routerMsg {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mac, _ := discovery.CurrentRouterMAC(ctx)
	return routerMsg{mac: mac, ssid: discovery.WiFiName(ctx)}
}

func (a *app) runSetup() error {
	m := newSetupModel(a)
	if _, err := tea.NewProgram(m, tea.WithOutput(os.Stderr), tea.WithInputTTY()).Run(); err != nil {
		return fmt.Errorf("menu: %w", err)
	}
	st, _ := a.active.Load()
	fmt.Fprintf(os.Stderr, "\nSetup saved. Active sharing: %s, active clipboard: %s. Run `drop setup` again any time, or `drop active status`.\n", onOff(st.Enabled), onOff(st.Clipboard))
	return nil
}

func (m *setupModel) Init() tea.Cmd {
	fn := m.routerFn
	return func() tea.Msg { return fn() }
}

// ---- data helpers

func (m *setupModel) settings() active.Settings { st, _ := m.a.active.Load(); return st }

func (m *setupModel) change(fn func(*active.Settings)) {
	if err := m.a.active.Update(func(st *active.Settings) error { fn(st); return nil }); err != nil {
		m.fail("could not save: " + err.Error())
		return
	}
	if note := m.a.syncServiceMsg(); note != "" {
		m.msg += "  " + note
	}
}

func (m *setupModel) ok(s string)   { m.msg, m.bad = s, false }
func (m *setupModel) fail(s string) { m.msg, m.bad = s, true }

func (m *setupModel) trustedName(d security.TrustedDevice) string {
	return m.a.label(d.ID, d.Name)
}

func (m *setupModel) onSavedNetwork(st active.Settings) bool {
	return m.here != "" && st.HasNetwork(m.here)
}

// nextStep tells a new user what to do next.
func (m *setupModel) nextStep(st active.Settings) string {
	switch {
	case len(m.a.trust.List()) == 0:
		return "Next: Trusted devices → add one (a device must send you something with your PIN first)."
	case len(st.Devices) == 0:
		return "Next: Allowed devices → pick who may send automatically."
	case len(st.Networks) == 0:
		return "Next: Saved networks → add the network you are on."
	case st.Dir == "" && !st.Clipboard:
		return "Next: set the Active sharing folder, then turn Active sharing on."
	case !st.Enabled && !st.Clipboard:
		return "Ready: turn on Active sharing and/or Active clipboard."
	}
	return "All set."
}

// ---- rows per screen

func (m *setupModel) rows() []srow {
	st := m.settings()
	switch m.sc {
	case scTrusted:
		rs := []srow{{id: "addtrust", label: "+ Add a trusted device", desc: "Waits for another device to send you something with your PIN, then asks to trust it."}}
		for _, d := range m.a.trust.List() {
			v := "last used " + d.LastUsed.Local().Format("2006-01-02")
			if m.a.trust.Expired(d) {
				v = "expired (needs the PIN)"
			}
			rs = append(rs, srow{id: "t:" + d.ID, label: m.trustedName(d), value: v, desc: "Enter removes it from your trusted devices; it will need the PIN again."})
		}
		return rs
	case scAllowed:
		rs := []srow{}
		devs := m.a.trust.List()
		if len(devs) == 0 {
			rs = append(rs, srow{id: "addtrust", label: "+ Add a trusted device first", desc: "Only trusted devices can be allowed."})
		}
		for _, d := range devs {
			state := "no"
			if st.HasDevice(d.ID) {
				state = "yes"
			}
			rs = append(rs, srow{id: "a:" + d.ID, label: m.trustedName(d), state: state,
				desc: "Enter or Space: allow / stop allowing this device to send files and clipboard automatically."})
		}
		return rs
	case scNetworks:
		rs := []srow{{id: "addnet", label: "+ Save the network I am on now", value: m.hereLabel(), desc: "Active features only work on saved networks (recognised by the router, not the Wi-Fi name)."}}
		for _, n := range st.SortedNetworks() {
			v := n.SSID
			state := ""
			if m.here != "" && strings.EqualFold(m.here, n.GatewayMAC) {
				state = "here"
				v = strings.TrimSpace(v + "  connected now")
			}
			rs = append(rs, srow{id: "n:" + n.Name, label: n.Name, value: v, state: state, desc: "Enter forgets this network: active features stop working there."})
		}
		return rs
	case scPIN:
		return []srow{
			{id: "showpin", label: "Show my Drop PIN", desc: "Senders need this PIN the first time (until you trust them)."},
			{id: "newpin", label: "Generate a new PIN", desc: "The old PIN stops working at once. Trusted devices stay trusted."},
		}
	}
	// main
	trusted := m.a.trust.List()
	netVal := fmt.Sprintf("%d", len(st.Networks))
	if m.onSavedNetwork(st) {
		netVal += "  (connected to one now)"
	} else if len(st.Networks) > 0 && m.probed {
		netVal += "  (not on one now)"
	}
	dir := st.Dir
	if dir == "" {
		dir = "not set"
	}
	recv := m.a.cfg.Transfer.ReceiveDir
	if recv == "" {
		recv = "where you run drop receive"
	}
	pinVal := "not created yet"
	if _, err := m.a.pins.Load(); err == nil {
		pinVal = "set"
	}
	stateOf := func(b bool) string {
		if b {
			return "on"
		}
		return "off"
	}
	return []srow{
		{id: "active", label: "Active sharing", state: stateOf(st.Enabled), desc: "Files and folders from allowed devices arrive with no prompt, into one folder. Enter turns it on or off."},
		{id: "clip", label: "Active clipboard", state: stateOf(st.Clipboard), desc: "A copy sent by an allowed device lands on your clipboard: just paste. Enter turns it on or off."},
		{sep: true},
		{id: "trusted", label: "Trusted devices", value: fmt.Sprintf("%d", len(trusted)), desc: "Devices that may send without the PIN. Add or remove them here."},
		{id: "allowed", label: "Allowed devices", value: fmt.Sprintf("%d", len(st.Devices)), desc: "Which trusted devices active sharing and clipboard accept from automatically."},
		{id: "networks", label: "Saved networks", value: netVal, desc: "The networks where active features work. Add the one you are on, or forget one."},
		{sep: true},
		{id: "activedir", label: "Active sharing folder", value: dir, desc: "Where automatically accepted files are saved."},
		{id: "recvdir", label: "Default receive folder", value: recv, desc: "Where files go when you run drop receive and accept them."},
		{id: "pin", label: "Drop PIN", value: pinVal, desc: "Show it or generate a new one."},
		{sep: true},
		{id: "done", label: "Done", desc: "Leave setup. Everything is already saved."},
	}
}

func (m *setupModel) hereLabel() string {
	switch {
	case !m.probed:
		return "detecting…"
	case m.here == "":
		return "not connected to a router"
	case m.wifi != "":
		return "Wi-Fi " + m.wifi
	}
	return "router found"
}

// selectable returns the indexes of rows the cursor may rest on.
func selectable(rs []srow) []int {
	var out []int
	for i, r := range rs {
		if !r.sep {
			out = append(out, i)
		}
	}
	return out
}

func (m *setupModel) clamp(rs []srow) int {
	sel := selectable(rs)
	if len(sel) == 0 {
		return -1
	}
	c := m.cursor[m.sc]
	for _, i := range sel {
		if i == c {
			return c
		}
	}
	m.cursor[m.sc] = sel[0]
	return sel[0]
}

func (m *setupModel) move(delta int) {
	rs := m.rows()
	cur := m.clamp(rs)
	sel := selectable(rs)
	for k, i := range sel {
		if i == cur {
			k += delta
			if k < 0 {
				k = 0
			}
			if k >= len(sel) {
				k = len(sel) - 1
			}
			m.cursor[m.sc] = sel[k]
			return
		}
	}
}

// ---- update

func (m *setupModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch k := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = k.Width
	case routerMsg:
		m.here, m.wifi, m.probed = k.mac, k.ssid, true
	case trustDoneMsg:
		if k.err != nil {
			m.fail("Adding a trusted device stopped: " + k.err.Error())
		} else {
			m.ok(fmt.Sprintf("Back in setup. You now have %d trusted device(s).", len(m.a.trust.List())))
		}
	case tea.KeyMsg:
		return m.key(k)
	}
	return m, nil
}

func (m *setupModel) key(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	s := k.String()
	if s == "ctrl+c" {
		m.done = true
		return m, tea.Quit
	}
	switch {
	case m.in != nil:
		return m.inputKey(k)
	case m.confirm != nil:
		switch s {
		case "enter", "y":
			c := m.confirm
			m.confirm = nil
			m.ok(c.yes())
		case "esc", "n", "q":
			m.confirm = nil
			m.ok("Nothing changed.")
		}
		return m, nil
	}
	switch s {
	case "up", "k":
		m.move(-1)
	case "down", "j":
		m.move(1)
	case "esc", "q", "left", "h":
		if m.sc != scMain {
			m.sc, m.pin = scMain, ""
			m.ok("")
			return m, nil
		}
		m.done = true
		return m, tea.Quit
	case "enter", " ", "right", "l":
		return m.activate(s == " ")
	}
	return m, nil
}

func (m *setupModel) inputKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	in := m.in
	switch k.Type {
	case tea.KeyEsc:
		m.in = nil
		m.ok("Cancelled.")
	case tea.KeyEnter:
		m.in = nil
		m.ok(in.ok(strings.TrimSpace(string(in.buf))))
	case tea.KeyBackspace:
		if len(in.buf) > 0 {
			in.buf = in.buf[:len(in.buf)-1]
		}
	case tea.KeyCtrlU:
		in.buf = nil
	case tea.KeyRunes, tea.KeySpace:
		in.buf = append(in.buf, k.Runes...)
	}
	return m, nil
}

func (m *setupModel) activate(space bool) (tea.Model, tea.Cmd) {
	rs := m.rows()
	cur := m.clamp(rs)
	if cur < 0 {
		return m, nil
	}
	r := rs[cur]
	if space && !(strings.HasPrefix(r.id, "a:") || r.id == "active" || r.id == "clip") {
		return m, nil // Space only toggles; Enter does everything
	}
	m.msg = ""
	st := m.settings()
	switch {
	case r.id == "done":
		m.done = true
		return m, tea.Quit
	case r.id == "active":
		return m, m.toggleActive(st)
	case r.id == "clip":
		m.toggleClipboard(st)
	case r.id == "trusted":
		m.sc = scTrusted
	case r.id == "allowed":
		m.sc = scAllowed
	case r.id == "networks":
		m.sc = scNetworks
	case r.id == "pin":
		m.sc = scPIN
	case r.id == "activedir":
		m.ask("Folder for active sharing", st.Dir, func(v string) string {
			p, err := prepareDir(v)
			if err != nil {
				m.bad = true
				return "Could not use that folder: " + err.Error()
			}
			m.change(func(s *active.Settings) { s.Dir = p })
			return "Active sharing folder: " + p
		})
	case r.id == "recvdir":
		m.ask("Default receive folder (empty = where you run drop receive)", m.a.cfg.Transfer.ReceiveDir, func(v string) string {
			p := ""
			if v != "" {
				var err error
				if p, err = prepareDir(v); err != nil {
					m.bad = true
					return "Could not use that folder: " + err.Error()
				}
			}
			m.a.cfg.Transfer.ReceiveDir = p
			if err := config.Save(m.a.cfgDir, m.a.cfg); err != nil {
				m.bad = true
				return "Could not save: " + err.Error()
			}
			if p == "" {
				return "Received files go where you run drop receive."
			}
			return "Default receive folder: " + p
		})
	case r.id == "addtrust":
		return m, m.addTrusted()
	case strings.HasPrefix(r.id, "t:"):
		id := strings.TrimPrefix(r.id, "t:")
		name := r.label
		m.confirm = &confirmState{prompt: fmt.Sprintf("Remove %s from trusted devices? It will need the PIN again.", name), yes: func() string {
			if _, err := m.a.trust.Remove(id); err != nil {
				m.bad = true
				return "Could not remove: " + err.Error()
			}
			m.change(func(s *active.Settings) { s.Deny(id) })
			return name + " is no longer trusted."
		}}
	case strings.HasPrefix(r.id, "a:"):
		id := strings.TrimPrefix(r.id, "a:")
		if st.HasDevice(id) {
			m.change(func(s *active.Settings) { s.Deny(id) })
			m.ok(r.label + " is no longer allowed to send automatically.")
		} else {
			m.change(func(s *active.Settings) { s.Allow(id) })
			m.ok(r.label + " may now send automatically.")
		}
	case r.id == "addnet":
		m.addNetwork(st)
	case strings.HasPrefix(r.id, "n:"):
		name := strings.TrimPrefix(r.id, "n:")
		m.confirm = &confirmState{prompt: fmt.Sprintf("Forget network %q? Active features stop working there.", name), yes: func() string {
			m.change(func(s *active.Settings) { s.RemoveNetwork(name) })
			return "Forgot " + name + "."
		}}
	case r.id == "showpin":
		pin, err := m.a.pins.Reveal()
		switch {
		case err == nil:
			m.pin = pin
			m.ok("Your Drop PIN is shown below.")
		case err == security.ErrNoPIN:
			m.newPIN("Created your Drop PIN.")
		default:
			m.fail("This PIN was created before it could be shown: generate a new one.")
		}
	case r.id == "newpin":
		m.confirm = &confirmState{prompt: "Generate a new PIN? The old one stops working immediately.", yes: func() string {
			m.newPIN("New PIN created.")
			return m.msg
		}}
	}
	return m, nil
}

func (m *setupModel) newPIN(okMsg string) {
	pin, err := security.GeneratePIN(m.a.cfg.Security.PINLength)
	if err == nil {
		err = m.a.pins.Set(pin)
	}
	if err == nil {
		err = m.a.limiter.Reset()
	}
	if err != nil {
		m.fail("Could not create a PIN: " + err.Error())
		return
	}
	m.pin = pin
	m.ok(okMsg)
}

func (m *setupModel) ask(label, initial string, ok func(string) string) {
	m.in = &inputState{label: label, buf: []rune(initial), ok: ok}
}

// toggleActive turns file active sharing on or off. When something is still
// missing it takes the user to the place that fixes it.
func (m *setupModel) toggleActive(st active.Settings) tea.Cmd {
	if st.Enabled {
		m.change(func(s *active.Settings) { s.Enabled = false })
		m.ok("Active sharing is OFF. Every transfer asks again.")
		return nil
	}
	switch {
	case len(st.Devices) == 0:
		m.sc = scAllowed
		m.fail("Not ready yet: allow a trusted device first.")
	case len(st.Networks) == 0:
		m.sc = scNetworks
		m.fail("Not ready yet: save the network you are on first.")
	case st.Dir == "":
		m.fail("Not ready yet: set the Active sharing folder (the item below), then turn it on.")
		m.cursor[scMain] = 7 // the folder row
	default:
		m.change(func(s *active.Settings) { s.Enabled = true })
		m.ok("Active sharing is ON.")
	}
	return nil
}

func (m *setupModel) toggleClipboard(st active.Settings) {
	if st.Clipboard {
		m.change(func(s *active.Settings) { s.Clipboard = false })
		m.ok("Active clipboard is OFF.")
		return
	}
	if _, err := clipboard.System(); err != nil {
		m.fail(err.Error())
		return
	}
	switch {
	case len(st.Devices) == 0:
		m.sc = scAllowed
		m.fail("Not ready yet: allow a trusted device first.")
	case len(st.Networks) == 0:
		m.sc = scNetworks
		m.fail("Not ready yet: save the network you are on first.")
	default:
		m.change(func(s *active.Settings) { s.Clipboard = true })
		m.ok("Active clipboard is ON: allowed devices can put text on your clipboard; just paste.")
	}
}

func (m *setupModel) addNetwork(st active.Settings) {
	if !m.probed {
		m.fail("Still detecting your network: try again in a moment.")
		return
	}
	if m.here == "" {
		m.fail("Not connected to a router, so there is no network to save.")
		return
	}
	def := m.wifi
	if def == "" {
		def = fmt.Sprintf("Network %d", len(st.Networks)+1)
	}
	m.ask("Name for this network", def, func(v string) string {
		name := active.Clean(v)
		if name == "" {
			m.bad = true
			return "A network needs a name."
		}
		m.change(func(s *active.Settings) { s.AddNetwork(active.Network{Name: name, GatewayMAC: m.here, SSID: m.wifi}) })
		return fmt.Sprintf("Saved %q. Active features work on this network now.", name)
	})
}

// addTrusted leaves the menu, waits for one device to send something with the
// PIN (the receiver then offers to trust it), and comes back.
func (m *setupModel) addTrusted() tea.Cmd {
	return tea.Exec(&trustExec{a: m.a}, func(err error) tea.Msg { return trustDoneMsg{err} })
}

type trustExec struct {
	a      *app
	in     io.Reader
	out    io.Writer
	errOut io.Writer
}

func (t *trustExec) SetStdin(r io.Reader)  { t.in = r }
func (t *trustExec) SetStdout(w io.Writer) { t.out = w }
func (t *trustExec) SetStderr(w io.Writer) { t.errOut = w }

func (t *trustExec) Run() error {
	fmt.Fprint(os.Stderr, "\n── Add a trusted device ──\n\n"+
		"On the OTHER device, run:   drop <any file>   (or: drop clipboard), choose this device and enter this PIN.\n"+
		"Here, answer y to Accept, then y to \"Trust … for future transfers?\".\n"+
		"Press Ctrl+C to go back without adding anyone.\n")
	if pin, err := t.a.pins.Reveal(); err == nil {
		printPINBox("Your Drop PIN", pin, "")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	dir, err := t.a.cfg.ResolveReceiveDir()
	if err != nil {
		return err
	}
	if err := t.a.runReceive(ctx, dir, 0, false, true, false); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

// ---- view

const (
	cReset = "\x1b[0m"
	cBold  = "\x1b[1m"
	cDim   = "\x1b[2m"
	cGreen = "\x1b[32m"
	cRed   = "\x1b[31m"
	cCyan  = "\x1b[36m"
)

func paint(code, s string) string {
	if os.Getenv("NO_COLOR") != "" {
		return s
	}
	return code + s + cReset
}

func (m *setupModel) title() string {
	switch m.sc {
	case scTrusted:
		return "Trusted devices"
	case scAllowed:
		return "Allowed devices"
	case scNetworks:
		return "Saved networks"
	case scPIN:
		return "Drop PIN"
	}
	return "Setup"
}

func (m *setupModel) View() string {
	if m.done {
		return ""
	}
	w := m.width
	if w < 30 {
		w = 30
	}
	rs := m.rows()
	cur := m.clamp(rs)
	var b strings.Builder
	crumb := "drop setup"
	if m.sc != scMain {
		crumb += " › " + m.title()
	}
	b.WriteString("\n " + paint(cBold, crumb) + "\n\n")

	labelW := 0
	for _, r := range rs {
		if n := len([]rune(r.label)); !r.sep && n > labelW {
			labelW = n
		}
	}
	if labelW > w/2 {
		labelW = w / 2
	}
	for i, r := range rs {
		if r.sep {
			b.WriteString("   " + paint(cDim, strings.Repeat("─", min(w-6, 40))) + "\n")
			continue
		}
		pointer := "  "
		if i == cur {
			pointer = paint(cCyan, "❯ ")
		}
		mark := ""
		switch r.state {
		case "yes":
			mark = paint(cGreen, "[x]") + " "
		case "no":
			mark = paint(cDim, "[ ]") + " "
		case "here":
			mark = paint(cGreen, "● ")
		}
		label := shorten2(r.label, labelW)
		label += strings.Repeat(" ", max(labelW-len([]rune(label)), 0))
		if i == cur {
			label = paint(cBold, label)
		}
		room := w - 3 - labelW - 2 - 6
		val := ""
		switch {
		case r.state == "on":
			val = "  " + paint(cGreen, "● ON")
		case r.state == "off":
			val = "  " + paint(cDim, "○ off")
		case r.value != "" && room > 3:
			val = "  " + paint(cDim, shorten2(r.value, room))
		}
		b.WriteString(" " + pointer + mark + label + val + "\n")
	}
	if cur >= 0 {
		b.WriteString("\n")
		for _, ln := range wrapText(rs[cur].desc, w-3, 3) {
			b.WriteString(" " + paint(cDim, ln) + "\n")
		}
	}

	switch {
	case m.in != nil:
		b.WriteString("\n " + paint(cBold, m.in.label) + "\n > " + string(m.in.buf) + "█\n")
		b.WriteString(" " + paint(cDim, "Enter to save · Esc to cancel · Ctrl+U to clear") + "\n")
		return b.String()
	case m.confirm != nil:
		b.WriteString("\n " + paint(cBold, shorten2(m.confirm.prompt, w-3)) + "\n " + paint(cDim, "Enter / y = yes · Esc / n = no") + "\n")
		return b.String()
	}
	if m.pin != "" {
		b.WriteString("\n " + paint(cBold, "Your Drop PIN:  ") + paint(cGreen, m.pin) + "\n")
	}
	if m.msg != "" {
		col := cGreen
		if m.bad {
			col = cRed
		}
		b.WriteString("\n " + paint(col, shorten2(m.msg, w-3)) + "\n")
	}
	if m.sc == scMain {
		b.WriteString("\n " + paint(cDim, shorten2(m.nextStep(m.settings()), w-3)) + "\n")
	}
	help := "↑ ↓ move · Enter select · Esc back"
	if m.sc == scMain {
		help = "↑ ↓ move · Enter select / toggle · Esc quit"
	}
	if m.sc == scAllowed {
		help = "↑ ↓ move · Space / Enter allow or not · Esc back"
	}
	b.WriteString("\n " + paint(cDim, shorten2(help, w-3)) + "\n")
	return b.String()
}

// wrapText breaks s into at most maxLines lines of at most width runes at word boundaries.
func wrapText(s string, width, maxLines int) []string {
	if width < 10 {
		width = 10
	}
	var lines []string
	cur := ""
	for _, word := range strings.Fields(s) {
		switch {
		case cur == "":
			cur = word
		case len([]rune(cur))+1+len([]rune(word)) <= width:
			cur += " " + word
		default:
			lines = append(lines, cur)
			cur = word
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	if len(lines) > maxLines {
		lines = lines[:maxLines]
		lines[maxLines-1] = shorten2(lines[maxLines-1]+"…", width)
	}
	for i, l := range lines {
		lines[i] = shorten2(l, width)
	}
	return lines
}
