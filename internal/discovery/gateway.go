package discovery

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// DefaultGateway returns the IPv4 address of the router this machine uses to
// reach the outside, or an error if it cannot be determined.
func DefaultGateway() (net.IP, error) { return defaultGateway() }

// CurrentRouterMAC returns the hardware address of the default gateway. It
// identifies "the network I am on" without depending on a Wi-Fi name. The
// result is "" if the gateway or its address cannot be found.
func CurrentRouterMAC(ctx context.Context) (string, error) {
	gw, err := DefaultGateway()
	if err != nil {
		return "", err
	}
	for attempt := 0; attempt < 2; attempt++ {
		for _, n := range ReadNeighbors(ctx) {
			if n.IP == gw.String() {
				return n.MAC, nil
			}
		}
		// Not in the neighbor table yet: talk to the router once so the OS resolves it.
		if c, err := net.DialTimeout("udp", net.JoinHostPort(gw.String(), "9"), time.Second); err == nil {
			c.Write([]byte{0})
			c.Close()
		}
		select {
		case <-time.After(400 * time.Millisecond):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	return "", errors.New("could not find the router's hardware address")
}

// OnLink reports whether ip is on a directly attached private IPv4 network of
// this machine (not through a VPN or other point-to-point tunnel).
func OnLink(ip net.IP) bool {
	if ip = ip.To4(); ip == nil || !ip.IsPrivate() {
		return false
	}
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && ipn.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// parseProcRoute finds the default gateway in Linux /proc/net/route content.
func parseProcRoute(content string) (net.IP, bool) {
	for i, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 4 || f[1] != "00000000" {
			continue
		}
		var b [4]byte
		if len(f[2]) != 8 {
			continue
		}
		ok := true
		for j := 0; j < 4; j++ { // little-endian hex
			var v byte
			for _, c := range f[2][6-2*j : 8-2*j] {
				v <<= 4
				switch {
				case c >= '0' && c <= '9':
					v |= byte(c - '0')
				case c >= 'A' && c <= 'F':
					v |= byte(c-'A') + 10
				case c >= 'a' && c <= 'f':
					v |= byte(c-'a') + 10
				default:
					ok = false
				}
			}
			b[j] = v
		}
		if ok && b != [4]byte{} {
			return net.IPv4(b[0], b[1], b[2], b[3]), true
		}
	}
	return nil, false
}

// parseWindowsRoute finds the default gateway in `route print -4` output
// ("0.0.0.0  0.0.0.0  <gateway>  <interface>  <metric>"), preferring the lowest metric.
func parseWindowsRoute(out string) (net.IP, bool) {
	var best net.IP
	bestMetric := int(^uint(0) >> 1)
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != "0.0.0.0" || f[1] != "0.0.0.0" {
			continue
		}
		gw := net.ParseIP(f[2]).To4()
		if gw == nil {
			continue // "On-link"
		}
		m := 0
		for _, c := range f[4] {
			if c < '0' || c > '9' {
				m = bestMetric
				break
			}
			m = m*10 + int(c-'0')
		}
		if m < bestMetric {
			best, bestMetric = gw, m
		}
	}
	return best, best != nil
}
