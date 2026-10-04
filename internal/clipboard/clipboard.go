// Package clipboard reads and writes the system clipboard (text only) and keeps
// an optional local history of what was copied.
package clipboard

import (
	"bytes"
	"errors"
	"os/exec"
	"runtime"
	"strings"
)

// ErrUnavailable means no clipboard tool was found on this system.
var ErrUnavailable = errors.New("no clipboard tool found (on Linux install wl-clipboard, xclip or xsel)")

// Backend is a way to reach the system clipboard.
type Backend interface {
	Read() (string, error)
	Write(text string) error
}

// System returns the clipboard of this machine, or ErrUnavailable.
func System() (Backend, error) {
	switch runtime.GOOS {
	case "darwin":
		return cmdBackend{read: []string{"pbpaste"}, write: []string{"pbcopy"}}, nil
	case "windows":
		return windowsBackend{}, nil
	}
	for _, c := range []cmdBackend{
		{read: []string{"wl-paste", "--no-newline"}, write: []string{"wl-copy"}},
		{read: []string{"xclip", "-selection", "clipboard", "-o"}, write: []string{"xclip", "-selection", "clipboard", "-i"}},
		{read: []string{"xsel", "--clipboard", "--output"}, write: []string{"xsel", "--clipboard", "--input"}},
	} {
		if _, err := exec.LookPath(c.read[0]); err == nil {
			return c, nil
		}
	}
	return nil, ErrUnavailable
}

type cmdBackend struct{ read, write []string }

func (c cmdBackend) Read() (string, error) {
	out, err := exec.Command(c.read[0], c.read[1:]...).Output()
	if err != nil {
		return "", nil // an empty or non-text clipboard is not an error
	}
	return string(out), nil
}

func (c cmdBackend) Write(text string) error {
	cmd := exec.Command(c.write[0], c.write[1:]...)
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

// windowsBackend uses PowerShell, which is present on every supported Windows.
type windowsBackend struct{}

const psUTF8 = "[Console]::OutputEncoding=[Text.Encoding]::UTF8;[Console]::InputEncoding=[Text.Encoding]::UTF8;"

func (windowsBackend) Read() (string, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psUTF8+"Get-Clipboard -Raw").Output()
	if err != nil {
		return "", nil
	}
	return strings.TrimSuffix(string(bytes.TrimPrefix(out, []byte("\xef\xbb\xbf"))), "\r\n"), nil
}

func (windowsBackend) Write(text string) error {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psUTF8+"Set-Clipboard -Value ([Console]::In.ReadToEnd())")
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}
