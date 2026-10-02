package cli

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/term"
)

var errInputCancelled = errors.New("input cancelled")

// openTTY opens the controlling terminal directly, so prompts work even when
// stdin carries piped data (e.g. `echo hi | drop --text`).
func openTTY() (*os.File, error) {
	name := "/dev/tty"
	if runtime.GOOS == "windows" {
		name = "CONIN$"
	}
	return os.OpenFile(name, os.O_RDWR, 0)
}

// hasTTY reports whether an interactive terminal is available.
func hasTTY() bool {
	f, err := openTTY()
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// readSecret prompts on stderr and reads a line from the terminal, echoing '*'
// for each character. The value is never written anywhere else.
func readSecret(prompt string) (string, error) {
	f, err := openTTY()
	if err != nil {
		return "", fmt.Errorf("no terminal to read the PIN from: %w", err)
	}
	defer f.Close()
	fd := int(f.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		return "", fmt.Errorf("terminal: %w", err)
	}
	defer term.Restore(fd, old)

	fmt.Fprint(os.Stderr, prompt)
	var buf []byte
	one := make([]byte, 1)
	for {
		if _, err := f.Read(one); err != nil {
			fmt.Fprint(os.Stderr, "\r\n")
			return "", errInputCancelled
		}
		switch c := one[0]; {
		case c == '\r' || c == '\n':
			fmt.Fprint(os.Stderr, "\r\n")
			return string(buf), nil
		case c == 3 || c == 4 || c == 27: // Ctrl-C, Ctrl-D, Esc
			fmt.Fprint(os.Stderr, "\r\n")
			return "", errInputCancelled
		case c == 127 || c == 8:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				fmt.Fprint(os.Stderr, "\b \b")
			}
		case c >= '0' && c <= '9' || c >= 0x20 && c < 0x7f:
			buf = append(buf, c)
			fmt.Fprint(os.Stderr, "*")
		}
	}
}
