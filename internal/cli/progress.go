package cli

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// progressBar renders transfer progress. It is the only place that knows about
// terminals; transfer code just calls Update. On non-terminals it stays silent.
type progressBar struct {
	w     io.Writer
	tty   bool
	label string

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
	fmt.Fprintf(p.w, "\r\033[K%s %s %3.0f%%  %s / %s  %s%s",
		p.label, bar(frac, 24), frac*100, humanBytes(done), humanBytes(total), rate, eta)
	p.drawn = true
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
