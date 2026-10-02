package discovery

import (
	"net"
	"testing"
)

func TestParseProcRoute(t *testing.T) {
	in := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
	ip, ok := parseProcRoute(in)
	if !ok || !ip.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Fatalf("got %v %v", ip, ok)
	}
	if _, ok := parseProcRoute("Iface\tDestination\tGateway\n"); ok {
		t.Fatal("no route should not match")
	}
}

func TestParseWindowsRoute(t *testing.T) {
	in := `IPv4 Route Table
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.19     35
          0.0.0.0          0.0.0.0         On-link      10.0.0.5     5000
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
`
	ip, ok := parseWindowsRoute(in)
	if !ok || !ip.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Fatalf("got %v %v", ip, ok)
	}
}

func TestOnLinkRejectsPublicAndGarbage(t *testing.T) {
	for _, s := range []string{"8.8.8.8", "127.0.0.1", "::1"} {
		if OnLink(net.ParseIP(s)) {
			t.Errorf("%s on link", s)
		}
	}
}

func TestWiFiNameParsers(t *testing.T) {
	if got := parseNetworksetup("Current Wi-Fi Network: My Home WiFi\n"); got != "My Home WiFi" {
		t.Fatalf("%q", got)
	}
	if parseNetworksetup("You are not associated with an AirPort network.\n") != "" || parseNetworksetup("Current Wi-Fi Network: <redacted>") != "" {
		t.Fatal("unassociated/redacted must give no name")
	}
	if got := parseNmcli("no:Other\nyes:Cafe Net\n"); got != "Cafe Net" {
		t.Fatalf("%q", got)
	}
	netsh := "    Name                   : Wi-Fi\n    SSID                   : Home 5G\n    BSSID                  : aa:bb:cc:dd:ee:ff\n"
	if got := parseNetsh(netsh); got != "Home 5G" {
		t.Fatalf("%q", got)
	}
}
