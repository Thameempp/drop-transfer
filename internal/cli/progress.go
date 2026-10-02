package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// progressBar renders transfer progress. It is the only place that knows about
// terminals; transfer code just calls Update. On non-terminals it stays silent.
type progressBar struct {
	w     io.Writer
	tty   bool
	label string // text before the bar; the file name part is trimmed to fit
	short string // label to use when space is tight (e.g. just "[3/12]")
	name  string // current file name (may be empty)

	mu    sync.Mutex
	start time.Time
	last  time.Time
	drawn bool
}

func newProgress(w io.Writer, tty bool, label string) *progressBar {
	return &progressBar{w: w, tty: tty, label: label}
}

// Update is a transfer.ProgressFunc.
func (p *progressBar) Update(done, total int64) {
	if !p.tty {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.start.IsZero() {
		p.start = now
	}
	if done < total && now.Sub(p.last) < 100*time.Millisecond {
		return
	}
	p.last = now
	frac := 1.0
	if total > 0 {
		frac = float64(done) / float64(total)
	}
	elapsed := now.Sub(p.start).Seconds()
	speed := 0.0
	if elapsed > 0 {
		speed = float64(done) / elapsed
	}
	eta := ""
	if speed > 0 && done < total {
		eta = "  ETA " + humanDuration(time.Duration(float64(total-done)/speed*float64(time.Second)))
	}
	rate := "—"
	if elapsed >= 0.2 && done > 0 { // a sub-200 ms sample is noise, not a speed
		rate = humanBytes(int64(speed)) + "/s"
	}
	fmt.Fprint(p.w, "\r\033[K"+p.render(frac, humanBytes(done), humanBytes(total), rate, eta, termWidth(p.w)))
	p.drawn = true
}

// render builds one line that never exceeds width-1 columns. A line wider than
// the terminal wraps, and every redraw would then land on a new row. When space
// is short it drops, in order: the ETA, the speed, the total size, the label
// and finally shrinks the bar; the file name is trimmed before any of those.
func (p *progressBar) render(frac float64, done, total, rate, eta string, width int) string {
	pct := fmt.Sprintf(" %3.0f%%", frac*100)
	variants := []string{
		pct + "  " + done + " / " + total + "  " + rate + eta,
		pct + "  " + done + " / " + total + "  " + rate,
		pct + "  " + done + " / " + total,
		pct + "  " + done,
		pct,
	}
	limit := width - 1
	stats := variants[len(variants)-1]
	for _, v := range variants {
		if limit-len([]rune(v)) >= 12 { // room for a bar of at least 10
			stats = v
			break
		}
	}
	avail := limit - len([]rune(stats))
	barW := 20
	if avail < 60 {
		barW = 10
	}
	if avail < barW+1 {
		return bar(frac, max(avail-1, 0)) + stats
	}
	room := avail - barW - 1 // columns left for the text before the bar
	text := p.label
	if p.name != "" {
		if r := room - len([]rune(p.label)) - 1; r >= 16 {
			text += " " + shorten(p.name, r)
		} else if r := room - len([]rune(p.short)) - 1; p.short != "" && r >= 8 {
			text = p.short + " " + shorten(p.name, r)
		} else {
			text = shorten(p.name, room)
		}
	}
	if len([]rune(text)) > room {
		text = shorten(text, room)
	}
	if room <= 0 || text == "" {
		return bar(frac, barW) + stats
	}
	return text + " " + bar(frac, barW) + stats
}

// termWidth returns the terminal's width in columns (80 if unknown).
func termWidth(w io.Writer) int {
	if f, ok := w.(*os.File); ok {
		if cols, _, err := term.GetSize(int(f.Fd())); err == nil && cols > 20 {
			return cols
		}
	}
	return 80
}

// SetFile shows which file is being transferred: verb ("Receiving"), count
// ("[3/12]", may be empty) and the name, which is trimmed to fit the terminal.
func (p *progressBar) SetFile(verb, count, name string) {
	p.mu.Lock()
	p.label, p.short, p.name = strings.TrimSpace(verb+" "+count), count, name
	p.mu.Unlock()
}

// SetLabel changes the text shown before the bar (e.g. the current file).
func (p *progressBar) SetLabel(label string) {
	p.mu.Lock()
	p.label = label
	p.mu.Unlock()
}

// Finish ends the progress line so following output starts clean.
func (p *progressBar) Finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.drawn {
		fmt.Fprintln(p.w)
		p.drawn = false
	}
}
