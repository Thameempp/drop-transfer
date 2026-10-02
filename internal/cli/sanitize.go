package cli

import (
	"strings"

	"github.com/thameem/drop/internal/security"
)

// sanitizeLabel cleans peer-supplied display text (see security.CleanLabel).
func sanitizeLabel(s string) string { return security.CleanLabel(s) }

// sanitizeText removes terminal control sequences from received text before it
// is shown on a terminal, keeping newlines and tabs.
func sanitizeText(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r == '\r':
			// drop: a bare CR can overwrite earlier text on screen
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			// drop ESC and other C0/C1 controls
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
