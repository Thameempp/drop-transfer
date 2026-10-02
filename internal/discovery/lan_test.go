package discovery

import (
	"bufio"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestParseArpMacOS(t *testing.T) {
	out := `? (192.168.1.1) at 6c:22:f7:c6:62:d3 on en0 ifscope [ethernet]
? (192.168.1.4) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.11) at 3a:cf:6:1b:c8:b on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (169.254.9.9) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
`
	got := ParseArp(out)
	if len(got) != 2 || got[0].IP != "192.168.1.1" || got[0].MAC != "6c:22:f7:c6:62:d3" {
		t.Fatalf("%+v", got)
	}
	if got[1].MAC != "3a:cf:06:1b:c8:0b" {
		t.Fatalf("single-digit octets not padded: %q", got[1].MAC)
	}
}

func TestParseArpWindows(t *testing.T) {
	out := `
Interface: 192.168.1.20 --- 0xb
  Internet Address      Physical Address      Type
  192.168.1.1           6c-22-f7-c6-62-d3     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
`
	got := ParseArp(out)
	if len(got) != 1 || got[0].IP != "192.168.1.1" || got[0].MAC != "6c:22:f7:c6:62:d3" {
		t.Fatalf("%+v", got)
	}
}

func TestParseProcArpLinux(t *testing.T) {
	in := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         6c:22:f7:c6:62:d3     *        wlan0
192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        wlan0
192.168.1.20     0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
`
	got := parseProcArp(bufio.NewScanner(strings.NewReader(in)))
	if len(got) != 2 || got[0].IP != "192.168.1.1" || got[1].IP != "192.168.1.20" {
		t.Fatalf("%+v", got)
	}
}

func TestNormalizeAndPrivateMAC(t *testing.T) {
	if normalizeMAC("AA-BB-CC-DD-EE-FF") != "aa:bb:cc:dd:ee:ff" || normalizeMAC("1:2:3:4:5") != "" || normalizeMAC("zz") != "" {
		t.Fatal("normalizeMAC")
	}
	for mac, want := range map[string]bool{
		"6a:8f:9c:c0:f2:75": true, // locally administered bit set: a random "private" MAC
		"be:bd:aa:e4:3e:b4": true,
		"6c:22:f7:c6:62:d3": false, // globally unique (real vendor MAC)
		"84:e6:57:bf:48:e5": false,
		"":                  false,
	} {
		if IsPrivateMAC(mac) != want {
			t.Errorf("IsPrivateMAC(%q) != %v", mac, want)
		}
	}
}

func TestSubnetTargets(t *testing.T) {
	// /24: 253 targets, never the network, broadcast or ourselves.
	got := SubnetTargets(net.ParseIP("192.168.1.6"), net.CIDRMask(24, 32))
	if len(got) != 253 || got[0] != "192.168.1.1" || got[len(got)-1] != "192.168.1.254" {
		t.Fatalf("len=%d first=%s", len(got), got[0])
	}
	for _, ip := range got {
		if ip == "192.168.1.6" || ip == "192.168.1.0" || ip == "192.168.1.255" {
			t.Fatalf("unexpected target %s", ip)
		}
	}
	// A /16 is clipped to the surrounding /24: never 65,000 packets.
	if n := len(SubnetTargets(net.ParseIP("10.20.30.40"), net.CIDRMask(16, 32))); n != 253 {
		t.Fatalf("/16 not clipped: %d targets", n)
	}
	// A /26 stays small and inside its own range.
	small := SubnetTargets(net.ParseIP("192.168.1.70"), net.CIDRMask(26, 32))
	if len(small) != 61 || small[0] != "192.168.1.65" || small[len(small)-1] != "192.168.1.126" {
		t.Fatalf("/26: %d %v", len(small), small[:2])
	}
	if SubnetTargets(net.ParseIP("::1"), net.CIDRMask(64, 128)) != nil {
		t.Fatal("IPv6 should yield nothing")
	}
}

func TestReverseNameAndMdnsAnswer(t *testing.T) {
	if got := reverseName("192.168.1.50"); got != "50.1.168.192.in-addr.arpa." {
		t.Fatal(got)
	}
	if reverseName("::1") != "" || reverseName("junk") != "" {
		t.Fatal("non-IPv4 accepted")
	}
	m := new(dns.Msg)
	m.Response = true
	m.Answer = []dns.RR{&dns.PTR{
		Hdr: dns.RR_Header{Name: "50.1.168.192.in-addr.arpa.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 120},
		Ptr: "Thameems-iPhone.local.",
	}}
	b, _ := m.Pack()
	ip, name, ok := parseReverseAnswer(b)
	if !ok || ip != "192.168.1.50" || name != "Thameems-iPhone" {
		t.Fatalf("%v %q %q", ok, ip, name)
	}
	if _, _, ok := parseReverseAnswer([]byte("garbage")); ok {
		t.Fatal("garbage parsed")
	}
	// An answer for some other kind of name must be ignored.
	m.Answer = []dns.RR{&dns.PTR{Hdr: dns.RR_Header{Name: "_http._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET}, Ptr: "x.local."}}
	b, _ = m.Pack()
	if _, _, ok := parseReverseAnswer(b); ok {
		t.Fatal("non-reverse PTR accepted")
	}
}

func nbstatReply(names ...[3]any) []byte {
	// header(12) + encoded name(34) + type/class/ttl/rdlen(10) + count + entries
	p := make([]byte, 12)
	p = append(p, 0x20)
	p = append(p, "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"...)
	p = append(p, 0)
	p = append(p, 0, 0x21, 0, 1, 0, 0, 0, 0, 0, 0)
	p = append(p, byte(len(names)))
	for _, n := range names {
		e := make([]byte, 18)
		copy(e, strings.Repeat(" ", 15))
		copy(e, n[0].(string))
		e[15] = n[1].(byte)
		e[16], e[17] = byte(n[2].(uint16)>>8), byte(n[2].(uint16))
		p = append(p, e...)
	}
	return p
}

func TestParseNbstat(t *testing.T) {
	// A group name (domain) comes first; the machine name is the unique 0x00 entry.
	r := nbstatReply([3]any{"WORKGROUP", byte(0x00), uint16(0x8400)}, [3]any{"WINDOWS-PC", byte(0x00), uint16(0x0400)}, [3]any{"WINDOWS-PC", byte(0x20), uint16(0x0400)})
	if name, ok := parseNbstat(r); !ok || name != "WINDOWS-PC" {
		t.Fatalf("%q %v", name, ok)
	}
	// Only group/non-workstation names: nothing usable.
	if _, ok := parseNbstat(nbstatReply([3]any{"WORKGROUP", byte(0x00), uint16(0x8400)})); ok {
		t.Fatal("group name used as a machine name")
	}
	// Truncated, empty and hostile inputs must not panic.
	for _, bad := range [][]byte{nil, {1, 2, 3}, r[:20], r[:50], append(r[:12:12], 0xC0), {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 'a'}} {
		parseNbstat(bad)
	}
	if q := nbstatQuery(); len(q) != 50 || q[12] != 0x20 {
		t.Fatalf("query malformed (%d bytes)", len(q))
	}
}

func TestFriendlyServiceAndDescribe(t *testing.T) {
	h := Host{Services: []string{"_airplay._tcp", "_raop._tcp", "_companion-link._tcp", "_ssh._tcp", "_airplay._tcp"}}
	if d := h.Describe(); !strings.HasPrefix(d, "AirPlay, AirPlay audio, Apple device") || !strings.Contains(d, "+1") {
		t.Fatalf("%q", d)
	}
	if FriendlyService("_weird-thing._tcp") != "weird-thing" {
		t.Fatal(FriendlyService("_weird-thing._tcp"))
	}
	if (Host{MAC: "6a:8f:9c:c0:f2:75"}).Describe() == (Host{MAC: "84:e6:57:bf:48:e5"}).Describe() {
		t.Fatal("private-MAC devices should be described differently from vendor-MAC ones")
	}
	if (Host{}).Describe() != "" {
		t.Fatal("unknown host should have an empty description")
	}
}

func TestSortHostsReadyFirstThenNamedThenByIP(t *testing.T) {
	hs := []Host{
		{IP: "192.168.1.9"},
		{IP: "192.168.1.100", Name: "printer", NameFrom: "mDNS"},
		{IP: "192.168.1.2"},
		{IP: "192.168.1.50", Name: "Windows-PC", NameFrom: "drop", Drop: &Peer{}},
		{IP: "192.168.1.3", Name: "tv", NameFrom: "mDNS"},
	}
	sortHosts(hs)
	var got []string
	for _, h := range hs {
		got = append(got, h.IP)
	}
	want := "192.168.1.50 192.168.1.3 192.168.1.100 192.168.1.2 192.168.1.9" // numeric, not lexical, IP order
	if strings.Join(got, " ") != want {
		t.Fatalf("got  %v\nwant %s", got, want)
	}
}
