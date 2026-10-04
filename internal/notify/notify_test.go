package notify

import (
	"strings"
	"testing"
)

func TestTextNeverReachesAScript(t *testing.T) {
	evil := `"; do shell script "touch /tmp/pwned"; "`
	c := command("darwin", evil, evil)
	script := strings.Join(c.Args[:len(c.Args)-2], " ") // everything except the two data arguments
	if strings.Contains(script, "pwned") || strings.Contains(script, "shell script") {
		t.Fatalf("remote text ended up in the AppleScript: %s", script)
	}
	if c.Args[len(c.Args)-2] != evil || c.Args[len(c.Args)-1] != evil {
		t.Fatal("text must travel as arguments")
	}
	w := command("windows", evil, evil)
	if strings.Contains(strings.Join(w.Args, " "), "pwned") {
		t.Fatal("remote text ended up in the PowerShell script")
	}
	found := 0
	for _, e := range w.Env {
		if e == "DROP_NOTIFY_BODY="+evil || e == "DROP_NOTIFY_TITLE="+evil {
			found++
		}
	}
	if found != 2 {
		t.Fatal("text must travel in the environment")
	}
	if command("plan9", "a", "b") != nil {
		t.Fatal("unknown OS must do nothing")
	}
}
