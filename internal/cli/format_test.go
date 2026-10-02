package cli

import (
	"context"
	"github.com/thameem/drop/internal/transport"
	"strings"
	"testing"
	"time"
)

func TestHumanBytes(t *testing.T) {
	for in, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KB", 43315: "42.3 KB", 5 << 20: "5.0 MB", 3 << 30: "3.0 GB"} {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestHumanDuration(t *testing.T) {
	if got := humanDuration(1200 * time.Millisecond); got != "1.2s" {
		t.Fatal(got)
	}
	if got := humanDuration(95 * time.Second); got != "1m35s" {
		t.Fatal(got)
	}
}

func TestBarClamps(t *testing.T) {
	if bar(-1, 4) != "░░░░" || bar(2, 4) != "████" || bar(0.5, 4) != "██░░" {
		t.Fatal("bar")
	}
}

func TestExitCodes(t *testing.T) {
	if codeFor(withCode(ExitUsage, errTest)) != ExitUsage {
		t.Fatal("code lost")
	}
}

var errTest = &exitError{code: 1}

func TestIsHostPort(t *testing.T) {
	for in, want := range map[string]bool{
		"127.0.0.1:80": true, "localhost:4000": true, "[::1]:9": true,
		"localhost": false, "windows-pc": false, "host:0": false, "host:99999": false, "host:abc": false,
	} {
		if got := isHostPort(in); got != want {
			t.Errorf("isHostPort(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSanitizeTextStripsTerminalControls(t *testing.T) {
	in := "ok\x1b[2J\x1b]0;pwned\x07line\r\nnext\ttab\x00"
	got := sanitizeText(in)
	if strings.ContainsAny(got, "\x1b\x07\x00\r") || !strings.Contains(got, "\n") || !strings.Contains(got, "\t") {
		t.Fatalf("%q", got)
	}
	if got := sanitizeLabel("evil\x1b[2J\nname"); got != "evil[2Jname" {
		t.Fatalf("%q", got)
	}
}

func TestDialAnySkipsUnreachableAddresses(t *testing.T) {
	l, err := transport.TCP{}.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		if c, err := l.Accept(); err == nil {
			c.Close()
		}
	}()
	a := &app{tr: transport.TCP{}}
	// The first address is a closed port (a Docker/VPN-style dead interface).
	conn, err := a.dialAny(context.Background(), []string{"127.0.0.1:1", l.Addr()})
	if err != nil {
		t.Fatalf("did not fall through to the working address: %v", err)
	}
	conn.Close()
	if _, err := a.dialAny(context.Background(), []string{"127.0.0.1:1"}); err == nil {
		t.Fatal("expected an error when nothing is reachable")
	}
	if _, err := a.dialAny(context.Background(), nil); err == nil {
		t.Fatal("expected an error for no addresses")
	}
}

func TestProgressLineNeverExceedsTerminalWidth(t *testing.T) {
	p := newProgress(nil, true, "")
	p.SetFile("Receiving", "[12/340]", "x")
	p.name = "some/very/long/path/to/Movie.Name.2024.1080p.BluRay.x265.10bit-GROUP.mkv"
	for _, w := range []int{20, 30, 40, 60, 80, 120} {
		line := p.render(0.456, "1.2 GB", "4.5 GB", "31.2 MB/s", "  ETA 1m2s", w)
		if n := len([]rune(line)); n > w-1 {
			t.Errorf("width %d: line has %d columns: %q", w, n, line)
		}
	}
	line := p.render(0.5, "1 GB", "2 GB", "10 MB/s", "", 120)
	if !strings.Contains(line, "[12/340]") || !strings.Contains(line, "50%") {
		t.Errorf("missing file counter or percent: %q", line)
	}
}
