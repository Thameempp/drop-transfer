// Package notify shows a short desktop notification, best effort. It is used
// when something arrives while nobody is looking at a terminal.
package notify

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// Show displays title and body. It never fails and never blocks long: a missing
// notification tool just means no notification. The text is passed to the
// tools as arguments or environment variables, never spliced into a script, so
// text from a remote device cannot inject commands.
func Show(title, body string) {
	cmd := command(runtime.GOOS, title, body)
	if cmd == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
		c.Env = cmd.Env
		_ = c.Run()
	}()
}

// command builds the notification command for an OS (nil if none applies).
func command(goos, title, body string) *exec.Cmd {
	switch goos {
	case "darwin":
		return exec.Command("osascript",
			"-e", "on run argv",
			"-e", "display notification (item 1 of argv) with title (item 2 of argv)",
			"-e", "end run",
			body, title)
	case "linux":
		if p, err := exec.LookPath("notify-send"); err == nil {
			return exec.Command(p, "--app-name=drop", "--", title, body)
		}
	case "windows":
		cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
			`Add-Type -AssemblyName System.Windows.Forms,System.Drawing;`+
				`$n=New-Object System.Windows.Forms.NotifyIcon;$n.Icon=[System.Drawing.SystemIcons]::Information;$n.Visible=$true;`+
				`$n.ShowBalloonTip(4000,$env:DROP_NOTIFY_TITLE,$env:DROP_NOTIFY_BODY,[System.Windows.Forms.ToolTipIcon]::Info);`+
				`Start-Sleep -Seconds 5;$n.Dispose()`)
		cmd.Env = append(os.Environ(), "DROP_NOTIFY_TITLE="+title, "DROP_NOTIFY_BODY="+body)
		return cmd
	}
	return nil
}
