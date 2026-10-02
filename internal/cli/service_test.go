package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/thameem/drop/internal/active"
	"github.com/thameem/drop/internal/discovery"
)

func TestLaunchdPlistEscapesAndRunsServe(t *testing.T) {
	p := launchdPlist("/Users/a&b/bin/drop", "/Users/a&b/l<og>", "/tmp/h")
	for _, want := range []string{"<string>/Users/a&amp;b/bin/drop</string>", "<string>serve</string>", "/Users/a&amp;b/l&lt;og&gt;", "DROP_HOME", "<key>RunAtLoad</key><true/>", "<key>KeepAlive</key><true/>"} {
		if !strings.Contains(p, want) {
			t.Errorf("plist missing %q:\n%s", want, p)
		}
	}
	if strings.Contains(launchdPlist("/x/drop", "/l", ""), "DROP_HOME") {
		t.Error("DROP_HOME written when unset")
	}
}

func TestSystemdUnitQuotesPaths(t *testing.T) {
	u := systemdUnit(`/home/my user/drop`, `/home/my user/service.log`, "")
	if !strings.Contains(u, `ExecStart="/home/my user/drop" active serve --log "/home/my user/service.log"`) {
		t.Errorf("unit:\n%s", u)
	}
	if !strings.Contains(u, "WantedBy=default.target") || !strings.Contains(u, "Restart=on-failure") {
		t.Errorf("unit:\n%s", u)
	}
}

func TestWindowsTaskCommandQuotesApostrophes(t *testing.T) {
	c := windowsTaskCommand(`C:\Users\O'Neil\drop.exe`, `C:\Users\O'Neil\s.log`)
	if !strings.Contains(c, `& 'C:\Users\O''Neil\drop.exe' active serve --log 'C:\Users\O''Neil\s.log'`) || !strings.Contains(c, "-WindowStyle Hidden") {
		t.Errorf("command: %s", c)
	}
}

func TestAddressNicknames(t *testing.T) {
	if ip, ok := parseIPArg(" 192.168.1.8:5050 "); !ok || ip != "192.168.1.8" {
		t.Fatalf("%q %v", ip, ok)
	}
	for _, bad := range []string{"mom", "::1", "999.1.1.1", ""} {
		if _, ok := parseIPArg(bad); ok {
			t.Errorf("%q accepted as address", bad)
		}
	}
	if !isAddrKey("mac:aa:bb") || !isAddrKey("ip:1.2.3.4") || isAddrKey("0123abcd") {
		t.Fatal("isAddrKey")
	}
	ps := []discovery.Peer{{ID: "a", Addrs: []string{"192.168.1.8:1", "[fe80::1]:1"}}, {ID: "b", Addrs: []string{"192.168.1.9:2"}}}
	if got := peersAtIP(ps, "192.168.1.9"); len(got) != 1 || got[0].ID != "b" {
		t.Fatalf("%+v", got)
	}
	if hostOf(ps[0]) != "192.168.1.8" {
		t.Fatal("hostOf")
	}
	if describeKey("mac:aa:bb") != "device aa:bb" || describeKey("ip:1.2.3.4") != "address 1.2.3.4" {
		t.Fatal("describeKey")
	}
}

func TestNickAtPrefersIDThenHardwareThenIP(t *testing.T) {
	dir := t.TempDir()
	a := &app{names: active.OpenNames(dir), neigh: map[string]string{"192.168.1.8": "aa:bb:cc:dd:ee:01"}}
	ctx := context.Background()
	a.names.Set("ip:192.168.1.50", "Printer")
	a.names.Set("mac:aa:bb:cc:dd:ee:01", "Mom")
	a.names.Set("deviceid1", "Office")
	if got := a.nickAt(ctx, "", "192.168.1.8"); got != "Mom" {
		t.Fatalf("by hardware address: %q", got) // the same device after a DHCP change keeps its name
	}
	a.neigh["192.168.1.99"] = "aa:bb:cc:dd:ee:01"
	if got := a.nickAt(ctx, "", "192.168.1.99"); got != "Mom" {
		t.Fatalf("new IP, same hardware: %q", got)
	}
	if got := a.nickAt(ctx, "", "192.168.1.50"); got != "Printer" {
		t.Fatalf("by ip: %q", got)
	}
	if got := a.nickAt(ctx, "deviceid1", "192.168.1.8"); got != "Office" {
		t.Fatalf("id wins: %q", got)
	}
	if got := a.nickAt(ctx, "", "10.0.0.1"); got != "" {
		t.Fatalf("unknown: %q", got)
	}
	if got := a.ipForKey(ctx, "mac:aa:bb:cc:dd:ee:01"); got != "192.168.1.8" && got != "192.168.1.99" {
		t.Fatalf("ipForKey %q", got)
	}
}
