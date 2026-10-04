package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/thameem/drop/internal/active"
	"github.com/thameem/drop/internal/clipboard"
	"github.com/thameem/drop/internal/config"
	"github.com/thameem/drop/internal/notify"
	"github.com/thameem/drop/internal/project"
	"github.com/thameem/drop/internal/security"
	"github.com/thameem/drop/internal/transfer"
)

func newClipboardCmd(verbose *bool) *cobra.Command {
	var o sendOptions
	cmd := &cobra.Command{
		Use:   "clipboard",
		Short: "Pick what you copied and send it to a nearby device",
		Long: `Shows what is on your clipboard (and, if history is on, what you copied before)
and sends your choice to a nearby device that is running "drop receive".

  ↑ ↓      move          Space  select / unselect
  a        select all    Enter  send the selected entries (or the highlighted one)
  Esc      cancel

Clipboard transfers always need the receiver's Drop PIN (or a trusted device),
and the receiver is asked before its clipboard is replaced. Text only.

Your system keeps no history for programs to read, so earlier copies are only
available if you turn history on: "drop clipboard history on".`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := loadApp(*verbose)
			if err != nil {
				return err
			}
			return a.runClipboard(cmd.Context(), o)
		},
	}
	cmd.Flags().StringVar(&o.to, "to", "", "target device name, nickname, ID, or host:port (skips the device menu)")
	cmd.Flags().DurationVar(&o.timeout, "timeout", 3*time.Second, "how long to search for devices")
	cmd.AddCommand(newClipboardLiveCmd(verbose), newClipboardHistoryCmd(verbose), newClipboardWatchCmd(verbose))
	return cmd
}

func (a *app) runClipboard(ctx context.Context, o sendOptions) error {
	if !hasTTY() || !isTTY(os.Stderr) {
		return usageErr("`drop clipboard` is interactive and needs a terminal")
	}
	be, err := clipboard.System()
	if err != nil {
		return withCode(ExitUnavailable, err)
	}
	hist := clipboard.OpenHistory(a.cfgDir)
	cur, _ := be.Read()
	if a.cfg.Clipboard.History {
		_ = hist.Add(cur) // make sure the latest copy is in the list even if the recorder just missed it
	}
	entries := collectClipEntries(cur, hist.List())
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "Your clipboard is empty (or not text).")
		if !a.cfg.Clipboard.History {
			fmt.Fprintln(os.Stderr, "To keep earlier copies for this list: drop clipboard history on")
		}
		return nil
	}
	items := make([]clipItem, len(entries))
	for i, e := range entries {
		items[i] = newClipItem(e.Text, e.At)
	}
	chosen := []int{0}
	if len(items) == 1 {
		// Just copied something and nothing else to choose from: go straight to the device.
		fmt.Fprintf(os.Stderr, "Sending your clipboard (%s)\n", humanBytes(int64(items[0].size)))
	} else if chosen, err = pickClipboard(items, a.cfg.Clipboard.History); err != nil {
		return err
	}
	var texts []string
	var flagged []string
	for _, i := range chosen {
		texts = append(texts, items[i].text)
		if items[i].secret != "" {
			flagged = append(flagged, items[i].secret)
		}
	}
	payload, err := transfer.EncodeClipboard(texts)
	if err != nil {
		return usageErr("%v", err)
	}
	if len(flagged) > 0 && !confirmTTY(fmt.Sprintf("A selected entry looks like a secret (%s). Send anyway? [y/N] ", flagged[0])) {
		return withCode(ExitGeneral, fmt.Errorf("cancelled"))
	}
	return a.deliver(ctx, o, job{ttype: security.TransferClipboard, text: payload, what: plural(len(texts), "clipboard entry", "clipboard entries")})
}

// collectClipEntries puts the current clipboard first, then history without repeats.
func collectClipEntries(current string, hist []clipboard.Entry) []clipboard.Entry {
	var out []clipboard.Entry
	if clipboard.Recordable(current) {
		out = append(out, clipboard.Entry{Text: current, At: time.Now()})
	}
	for _, e := range hist {
		if e.Text != current {
			out = append(out, e)
		}
	}
	return out
}

func confirmTTY(prompt string) bool {
	f, err := openTTY()
	if err != nil {
		return false
	}
	defer f.Close()
	fmt.Fprint(os.Stderr, prompt)
	ans, _ := bufio.NewReader(f).ReadString('\n')
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(ans)), "y")
}

// ---- picker

type clipItem struct {
	text   string
	oneRow string // single-line preview
	size   int
	at     time.Time
	secret string // kind of secret it looks like, "" if none
}

func newClipItem(text string, at time.Time) clipItem {
	flat := strings.Join(strings.Fields(sanitizeText(text)), " ")
	extra := ""
	if n := strings.Count(strings.TrimRight(text, "\r\n"), "\n"); n > 0 {
		extra = fmt.Sprintf(" (+%d lines)", n)
	}
	kind, _ := project.ScanText(text)
	return clipItem{text: text, oneRow: flat + extra, size: len(text), at: at, secret: kind}
}

type clipPicker struct {
	items    []clipItem
	cursor   int
	selected map[int]bool
	width    int
	height   int
	history  bool
	done     bool
	cancel   bool
}

func (m clipPicker) Init() tea.Cmd { return nil }

func (m clipPicker) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch k := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = k.Width, k.Height
	case tea.KeyMsg:
		switch k.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.items)-1 {
				m.cursor++
			}
		case " ", "x":
			m.selected[m.cursor] = !m.selected[m.cursor]
			if !m.selected[m.cursor] {
				delete(m.selected, m.cursor)
			}
		case "a":
			if len(m.selected) == len(m.items) {
				m.selected = map[int]bool{}
			} else {
				for i := range m.items {
					m.selected[i] = true
				}
			}
		case "enter":
			m.done = true
			return m, tea.Quit
		case "esc", "q", "ctrl+c":
			m.cancel = true
			return m, tea.Quit
		}
	}
	return m, nil
}

// result is the chosen indexes in list order: the selection, or the highlighted entry if none.
func (m clipPicker) result() []int {
	if len(m.selected) == 0 {
		return []int{m.cursor}
	}
	var out []int
	for i := range m.items {
		if m.selected[i] {
			out = append(out, i)
		}
	}
	return out
}

func (m clipPicker) View() string {
	w, h := m.width, m.height
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}
	rows := h - 6 // title, blank, status, blank, help, spare
	if rows < 3 {
		rows = 3
	}
	start := 0
	if m.cursor >= rows {
		start = m.cursor - rows + 1
	}
	end := min(start+rows, len(m.items))
	var b strings.Builder
	b.WriteString("Clipboard\n\n")
	for i := start; i < end; i++ {
		it := m.items[i]
		cur, box := "  ", "[ ]"
		if i == m.cursor {
			cur = "❯ "
		}
		if m.selected[i] {
			box = "[x]"
		}
		tag := ""
		if it.secret != "" {
			tag = " ⚠ " + it.secret
		}
		// Fixed columns: cursor(2) + box(3) + space + tag + size/age, the rest is preview.
		meta := "  " + humanBytes(int64(it.size)) + tag
		room := w - 2 - 3 - 1 - len([]rune(meta)) - 1
		if room < 8 {
			room = 8
		}
		fmt.Fprintf(&b, "%s%s %s%s\n", cur, box, shorten2(it.oneRow, room), meta)
	}
	if len(m.items) > end || start > 0 {
		fmt.Fprintf(&b, "  … %d of %d shown\n", end-start, len(m.items))
	} else {
		b.WriteString("\n")
	}
	status := fmt.Sprintf("%d selected", len(m.selected))
	if len(m.selected) == 0 {
		status = "nothing selected: Enter sends the highlighted entry"
	}
	b.WriteString(status + "\n")
	if !m.history {
		b.WriteString(shorten2("Only the current clipboard is listed. Keep earlier copies: drop clipboard history on", w-1) + "\n")
	}
	help := "↑ ↓ Navigate   Space Select   a All   Enter Send   Esc Cancel"
	if w < 64 {
		help = "↑↓ move  Space select  a all  Enter send  Esc"
	}
	b.WriteString("\n" + shorten2(help, w-1) + "\n")
	return b.String()
}

// shorten2 trims s to n runes, keeping the start (what you recognise a copy by).
func shorten2(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return "…"
	}
	return string(r[:n-1]) + "…"
}

func pickClipboard(items []clipItem, history bool) ([]int, error) {
	m := clipPicker{items: items, selected: map[int]bool{}, history: history}
	final, err := tea.NewProgram(m, tea.WithOutput(os.Stderr), tea.WithInputTTY()).Run()
	if err != nil {
		return nil, fmt.Errorf("menu: %w", err)
	}
	fm := final.(clipPicker)
	if fm.cancel || !fm.done {
		return nil, errPickCancelled
	}
	return fm.result(), nil
}

// ---- history on/off, recorder

func newClipboardHistoryCmd(verbose *bool) *cobra.Command {
	cmd := &cobra.Command{Use: "history", Short: "Keep a local list of what you copy, for `drop clipboard`"}
	cmd.AddCommand(
		&cobra.Command{Use: "on", Short: "Start remembering what you copy (runs a small background recorder)", Args: cobra.NoArgs,
			Long: `Starts a small background program that notes each text you copy, so
"drop clipboard" can offer earlier copies.

Be aware: EVERYTHING you copy as text is remembered, including passwords. It is
kept only on this computer, in a private file (up to 50 entries of up to 64 KiB),
and sent nowhere unless you pick an entry in "drop clipboard". Turn it off with
"drop clipboard history off" and erase the list with "drop clipboard history clear".`,
			RunE: func(cmd *cobra.Command, args []string) error {
				a, err := loadApp(*verbose)
				if err != nil {
					return err
				}
				if _, err := clipboard.System(); err != nil {
					return withCode(ExitUnavailable, err)
				}
				exe, err := os.Executable()
				if err != nil {
					return err
				}
				if r, err := filepath.EvalSymlinks(exe); err == nil {
					exe = r
				}
				a.cfg.Clipboard.History = true
				if err := config.Save(a.cfgDir, a.cfg); err != nil {
					return withCode(ExitGeneral, err)
				}
				if err := installService(clipSvc, exe, filepath.Join(a.cfgDir, clipSvc.logName)); err != nil {
					return withCode(ExitGeneral, fmt.Errorf("history is enabled but the recorder could not start: %w\nYou can run it yourself with `drop clipboard watch`", err))
				}
				fmt.Println("✓ Clipboard history is on. Everything you copy as text is now remembered on this computer (see `drop clipboard history on --help`).")
				return nil
			}},
		&cobra.Command{Use: "off", Short: "Stop remembering (the list is kept until you clear it)", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				a, err := loadApp(*verbose)
				if err != nil {
					return err
				}
				a.cfg.Clipboard.History = false
				if err := config.Save(a.cfgDir, a.cfg); err != nil {
					return withCode(ExitGeneral, err)
				}
				if err := uninstallService(clipSvc); err != nil {
					return withCode(ExitGeneral, err)
				}
				fmt.Println("✓ Clipboard history is off. Erase what was kept with: drop clipboard history clear")
				return nil
			}},
		&cobra.Command{Use: "clear", Short: "Erase the remembered list", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				a, err := loadApp(*verbose)
				if err != nil {
					return err
				}
				if err := clipboard.OpenHistory(a.cfgDir).Clear(); err != nil {
					return withCode(ExitGeneral, err)
				}
				fmt.Println("✓ Clipboard history erased.")
				return nil
			}},
		&cobra.Command{Use: "status", Short: "Show whether history is on", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				a, err := loadApp(*verbose)
				if err != nil {
					return err
				}
				_, running := serviceState(clipSvc)
				n := len(clipboard.OpenHistory(a.cfgDir).List())
				fmt.Printf("Clipboard history: %s; recorder %s; %s remembered\n", onOff(a.cfg.Clipboard.History), map[bool]string{true: "running", false: "not running"}[running], plural(n, "entry", "entries"))
				return nil
			}},
	)
	return cmd
}

func onOff(b bool) string {
	if b {
		return "ON"
	}
	return "off"
}

func newClipboardWatchCmd(verbose *bool) *cobra.Command {
	var logPath string
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Record what you copy, in the foreground (what the history recorder runs)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if logPath != "" {
				if f, err := openServiceLog(logPath); err == nil {
					os.Stderr, os.Stdout = f, f
				}
			}
			a, err := loadApp(*verbose)
			if err != nil {
				return err
			}
			be, err := clipboard.System()
			if err != nil {
				return withCode(ExitUnavailable, err)
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			interval := time.Second
			if runtime.GOOS == "windows" {
				interval = 2 * time.Second // PowerShell is slow to start
			}
			watchClipboard(ctx, be, clipboard.OpenHistory(a.cfgDir), func() bool {
				c, err := config.Load(a.cfgDir)
				return err == nil && c.Clipboard.History
			}, interval)
			return nil
		},
	}
	cmd.Flags().StringVar(&logPath, "log", "", "append output to this file")
	return cmd
}

// watchClipboard records each change of the clipboard while enabled() is true.
func watchClipboard(ctx context.Context, be clipboard.Backend, hist *clipboard.History, enabled func() bool, every time.Duration) {
	last, _ := be.Read() // what is there when we start is recorded on the first enabled tick
	first := true
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !enabled() {
			continue
		}
		cur, err := be.Read()
		if err != nil || (cur == last && !first) {
			continue
		}
		first = false
		last = cur
		_ = hist.Add(cur)
	}
}

// ---- receiving

// clipboardText is what ends up on the clipboard: the entry itself, or all of
// them, one per line, so a normal paste gives everything that was sent.
func clipboardText(items []string) string {
	if len(items) == 1 {
		return items[0]
	}
	return strings.Join(items, "\n")
}

// applyClipboard puts items on this computer's clipboard. note says if control
// characters had to be removed.
func applyClipboard(items []string) (note string, err error) {
	be, err := clipboard.System()
	if err != nil {
		return "", err
	}
	text := clipboardText(items)
	if hasHazardousControls(text) {
		text, note = sanitizeText(text), " (terminal control characters were removed)"
	}
	return note, be.Write(text)
}

func pasteKey() string {
	if runtime.GOOS == "darwin" {
		return "Cmd+V"
	}
	return "Ctrl+V"
}

// onClipboardReceived is the interactive receiver: show what arrived and put it on the clipboard.
func (a *app) onClipboardReceived(inc transfer.Incoming, items []string) {
	from := a.labelAt(context.Background(), inc.KeyID, inc.From.Name, hostPart(inc.Addr))
	fmt.Fprintf(os.Stderr, "✓ %s from %s — SHA-256 verified\n", plural(len(items), "clipboard entry", "clipboard entries"), from)
	for i, it := range items {
		shown := sanitizeText(it)
		more := ""
		if r := []rune(shown); len(r) > 2000 {
			shown, more = string(r[:2000]), fmt.Sprintf("\n… (+%d more characters)", len(r)-2000)
		}
		if len(items) > 1 {
			fmt.Printf("── %d/%d ──\n", i+1, len(items))
		}
		fmt.Print(shown + more)
		if !strings.HasSuffix(shown, "\n") {
			fmt.Println()
		}
	}
	note, err := applyClipboard(items)
	switch {
	case errors.Is(err, clipboard.ErrUnavailable):
		fmt.Fprintln(os.Stderr, "(no clipboard tool here, so nothing was copied)")
	case err != nil:
		fmt.Fprintf(os.Stderr, "could not copy to your clipboard: %v\n", err)
	case len(items) > 1:
		fmt.Fprintf(os.Stderr, "✓ All %d entries are on your clipboard, one per line%s. Paste with %s.\n", len(items), note, pasteKey())
	default:
		fmt.Fprintf(os.Stderr, "✓ It is on your clipboard%s. Paste with %s.\n", note, pasteKey())
	}
}

// onClipboardInBackground is the background receiver: no terminal, so copy and
// tell the user with a notification (which never contains the text itself).
func (a *app) onClipboardInBackground(inc transfer.Incoming, items []string) {
	from := a.labelAt(context.Background(), inc.KeyID, inc.From.Name, hostPart(inc.Addr))
	note, err := applyClipboard(items)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ clipboard from %s could not be copied: %v\n", from, err)
		notify.Show("drop", "Clipboard from "+from+" could not be copied")
		return
	}
	fmt.Fprintf(os.Stderr, "✓ clipboard from %s copied (%s)%s\n", from, plural(len(items), "entry", "entries"), note)
	notify.Show("Clipboard from "+from, "Ready: paste with "+pasteKey())
}

// hasHazardousControls reports control characters other than tab, newline and
// carriage return, such as terminal escape sequences.
func hasHazardousControls(s string) bool {
	for _, r := range s {
		if (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return true
		}
	}
	return false
}

// ---- live clipboard (receiving without a terminal)

func newClipboardLiveCmd(verbose *bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "live",
		Short: "Let chosen devices put text on this computer's clipboard, no terminal needed",
		Long: `Live clipboard makes this computer receive clipboard transfers by itself. When an
allowed device sends you its clipboard, it lands on your clipboard at once, you
get a notification, and you just paste (Cmd+V on Mac, Ctrl+V on Windows/Linux).
Nobody has to open a terminal or run "drop receive" here.

It only applies when ALL of these hold, otherwise you are asked as usual:
  • live clipboard is on
  • the sender is a trusted device you allowed ("drop active allow <device>")
  • you are on a saved network ("drop active network add")
  • the sender is on that same local network

It reuses the devices and networks of active sharing but has its own on/off
switch. It replaces your clipboard when something arrives, so only allow
devices you trust; turn it off any time with "drop clipboard live off".`,
	}
	var devices []string
	var network string
	on := &cobra.Command{Use: "on", Short: "Turn live clipboard on", Args: cobra.NoArgs,
		Example: "  drop clipboard live on --device \"Work PC\" --network Home\n  drop clipboard live on",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withActive(*verbose, func(a *app, st *active.Settings) error {
				if _, err := clipboard.System(); err != nil {
					return withCode(ExitUnavailable, err)
				}
				for _, q := range devices {
					d, err := a.matchTrusted(q)
					if err != nil {
						return err
					}
					st.Allow(d.ID)
					fmt.Printf("✓ %s may now send its clipboard here.\n", a.label(d.ID, d.Name))
				}
				if network != "" {
					n, err := a.currentNetwork(cmd.Context(), network)
					if err != nil {
						return err
					}
					st.AddNetwork(n)
					fmt.Printf("✓ Saved this network as %q.\n", n.Name)
				}
				var need []string
				if len(st.Devices) == 0 {
					need = append(need, "allow a trusted device (--device <name>, or drop active allow <device>)")
				}
				if len(st.Networks) == 0 {
					need = append(need, "save this network (--network <name>, or drop active network add <name>)")
				}
				if len(need) > 0 {
					return usageErr("cannot turn on yet: %s", strings.Join(need, "; "))
				}
				st.Clipboard = true
				fmt.Println("✓ Live clipboard is on. Allowed devices on a saved network can now put text on your clipboard; paste with " + pasteKey() + ".")
				return nil
			})
		}}
	on.Flags().StringArrayVar(&devices, "device", nil, "trusted device to allow (repeatable)")
	on.Flags().StringVar(&network, "network", "", "name to save the network you are on now under")
	cmd.AddCommand(on,
		&cobra.Command{Use: "off", Short: "Turn live clipboard off (settings are kept)", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				return withActive(*verbose, func(a *app, st *active.Settings) error {
					st.Clipboard = false
					fmt.Println("✓ Live clipboard is off. Incoming clipboards ask first again.")
					return nil
				})
			}},
		&cobra.Command{Use: "status", Short: "Show whether live clipboard is on and working", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				a, err := loadApp(*verbose)
				if err != nil {
					return err
				}
				st, err := a.active.Load()
				if err != nil {
					return err
				}
				_, running := serviceState(activeSvc)
				here, _ := a.currentRouter(cmd.Context())
				switch {
				case !st.Clipboard:
					fmt.Println("Live clipboard: OFF (turn on: drop clipboard live on)")
				case !st.HasNetwork(here):
					fmt.Println("Live clipboard: ON, waiting: you are not on a saved network, so incoming clipboards still ask")
				case running:
					fmt.Println("Live clipboard: ON and working: allowed devices can send you their clipboard")
				default:
					fmt.Println("Live clipboard: ON, but the background receiver is not running (drop active service start); `drop receive` also works")
				}
				fmt.Println("  Allowed devices and saved networks are shared with active sharing: see `drop active status`.")
				return nil
			}},
	)
	return cmd
}
