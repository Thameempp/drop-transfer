package discovery

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

// Neighbor is an entry of the operating system's neighbor (ARP) table: a
// device on the local network that this machine has recently exchanged
// packets with.
type Neighbor struct {
	IP  string
	MAC string // normalised "aa:bb:cc:dd:ee:ff"
}

var (
	ipv4Re = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	macRe  = regexp.MustCompile(`\b([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b`)
)

// ReadNeighbors returns the current neighbor table.
func ReadNeighbors(ctx context.Context) []Neighbor {
	// Preferred on macOS/BSD: ask the kernel directly. It needs no helper
	// program and is not affected by how child processes are launched.
	if ns, ok := readNeighborsKernel(); ok && len(ns) > 0 {
		return ns
	}
	switch runtime.GOOS {
	case "linux":
		if f, err := os.Open("/proc/net/arp"); err == nil {
			defer f.Close()
			return parseProcArp(bufio.NewScanner(f))
		}
		fallthrough
	default:
		// macOS, BSD and Windows all print `arp -a` lines containing an IPv4 and a MAC.
		args := []string{"-a"}
		if runtime.GOOS != "windows" {
			args = append(args, "-n") // numeric: do not wait on reverse DNS
		}
		out, err := exec.CommandContext(ctx, "arp", args...).Output()
		if err != nil {
			return nil
		}
		return ParseArp(string(out))
	}
}

// ParseArp parses `arp -a` output (macOS/BSD "? (1.2.3.4) at aa:bb:… on en0",
// Windows "  1.2.3.4   aa-bb-… dynamic"). Incomplete entries, broadcast and
// multicast addresses are dropped.
func ParseArp(out string) []Neighbor {
	var res []Neighbor
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "incomplete") {
			continue
		}
		ip := ipv4Re.FindString(line)
		mac := macRe.FindString(line)
		if n, ok := makeNeighbor(ip, mac); ok {
			res = append(res, n)
		}
	}
	return res
}

func parseProcArp(sc *bufio.Scanner) []Neighbor {
	var res []Neighbor
	first := true
	for sc.Scan() {
		if first { // header
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		// IP address, HW type, Flags, HW address, Mask, Device
		if len(f) < 4 || f[2] == "0x0" {
			continue // flags 0 = incomplete
		}
		if n, ok := makeNeighbor(f[0], f[3]); ok {
			res = append(res, n)
		}
	}
	return res
}

func makeNeighbor(ip, mac string) (Neighbor, bool) {
	p := net.ParseIP(ip)
	if p == nil || p.To4() == nil || mac == "" {
		return Neighbor{}, false
	}
	if p.IsMulticast() || p.IsUnspecified() || p.IsLoopback() || p.IsLinkLocalUnicast() || strings.HasSuffix(ip, ".255") {
		return Neighbor{}, false
	}
	m := normalizeMAC(mac)
	if m == "" || m == "ff:ff:ff:ff:ff:ff" || m == "00:00:00:00:00:00" || strings.HasPrefix(m, "01:00:5e") || strings.HasPrefix(m, "33:33") {
		return Neighbor{}, false
	}
	return Neighbor{IP: p.To4().String(), MAC: m}, true
}

// normalizeMAC pads single-digit octets (macOS prints "3a:cf:6:1b:c8:b").
func normalizeMAC(s string) string {
	parts := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return r == ':' || r == '-' })
	if len(parts) != 6 {
		return ""
	}
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
		if len(parts[i]) != 2 {
			return ""
		}
	}
	return strings.Join(parts, ":")
}

// IsPrivateMAC reports whether a MAC is locally administered, i.e. randomised.
// Modern phones use a different random MAC per network, so such a device
// cannot be identified by its address.
func IsPrivateMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	var b byte
	for _, c := range mac[:2] {
		b <<= 4
		switch {
		case c >= '0' && c <= '9':
			b |= byte(c - '0')
		case c >= 'a' && c <= 'f':
			b |= byte(c-'a') + 10
		}
	}
	return b&0x02 != 0
}
