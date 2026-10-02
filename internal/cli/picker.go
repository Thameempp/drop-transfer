package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/thameem/drop/internal/discovery"
)

var errPickCancelled = errors.New("selection cancelled")

type pickerModel struct {
	title  string
	items  []string
	cursor int
	chosen int // -1 until Enter
	quit   bool
}

func (m pickerModel) Init() tea.Cmd { return nil }

func (m pickerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.items)-1 {
				m.cursor++
			}
		case "enter":
			m.chosen = m.cursor
			return m, tea.Quit
		case "esc", "q", "ctrl+c":
			m.quit = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m pickerModel) View() string {
	var b strings.Builder
	b.WriteString(m.title + "\n\n")
	for i, it := range m.items {
		cur := "  "
		if i == m.cursor {
			cur = "❯ "
		}
		fmt.Fprintf(&b, "%s%s\n", cur, it)
	}
	b.WriteString("\n↑ ↓ Navigate   Enter Select   Esc Cancel\n")
	return b.String()
}

// pickOne shows an interactive menu on stderr (stdout stays clean for pipes)
// and returns the chosen index.
func pickOne(title string, items []string) (int, error) {
	final, err := tea.NewProgram(pickerModel{title: title, items: items, chosen: -1}, tea.WithOutput(os.Stderr), tea.WithInputTTY()).Run()
	if err != nil {
		return -1, fmt.Errorf("menu: %w", err)
	}
	m := final.(pickerModel)
	if m.chosen < 0 {
		return -1, errPickCancelled
	}
	return m.chosen, nil
}

// pickPeer lets the user choose among discovered devices.
func pickPeer(peers []discovery.Peer, trusted func(id string) bool, label func(id, name string) string) (discovery.Peer, error) {
	items := make([]string, len(peers))
	for i, p := range peers {
		items[i] = fmt.Sprintf("%s  (%s)", label(p.ID, p.Name), sanitizeLabel(p.OS))
		if trusted != nil && trusted(p.ID) {
			items[i] += "  ✓ Trusted"
		}
	}
	i, err := pickOne("Nearby Devices", items)
	if err != nil {
		return discovery.Peer{}, err
	}
	return peers[i], nil
}
