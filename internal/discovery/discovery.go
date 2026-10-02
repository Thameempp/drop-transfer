// Package discovery finds nearby drop devices on the local network.
package discovery

import (
	"context"
	"net"
	"strings"
	"time"
)

// ServiceType is the DNS-SD service drop advertises.
const ServiceType = "_drop._tcp"

// Service is what a running receiver advertises. It deliberately carries no
// secrets: only a device ID, display name, OS and protocol capabilities.
type Service struct {
	ID       string
	Name     string
	OS       string
	Port     int
	Versions []int
}

// Peer is a discovered device.
type Peer struct {
	ID       string
	Name     string
	OS       string
	Addrs    []string // host:port, usable with Transport.Dial
	Versions []int
}

// Advertiser announces a Service until the returned stop func is called.
type Advertiser interface {
	Advertise(svc Service) (stop func(), err error)
}

// Browser lists devices seen within the timeout.
type Browser interface {
	Browse(ctx context.Context, timeout time.Duration) ([]Peer, error)
	// BrowseUntil is Browse that also stops early as soon as done(peers so far)
	// returns true (e.g. the device the user named has appeared).
	BrowseUntil(ctx context.Context, timeout time.Duration, done func([]Peer) bool) ([]Peer, error)
}

// Exact returns the peers whose name equals (case-insensitively) or whose ID
// equals query. Used to stop searching early only when the match is certain.
func Exact(peers []Peer, query string) []Peer {
	var out []Peer
	for _, p := range peers {
		if strings.EqualFold(p.Name, query) || strings.EqualFold(p.ID, query) {
			out = append(out, p)
		}
	}
	return out
}

// Match returns peers whose name equals (case-insensitively) or, failing that,
// starts with / contains the query. An exact match wins outright.
func Match(peers []Peer, query string) []Peer {
	q := strings.ToLower(query)
	var exact, prefix, contains []Peer
	for _, p := range peers {
		n := strings.ToLower(p.Name)
		switch {
		case n == q || strings.EqualFold(p.ID, query):
			exact = append(exact, p)
		case strings.HasPrefix(n, q):
			prefix = append(prefix, p)
		case strings.Contains(n, q):
			contains = append(contains, p)
		}
	}
	switch {
	case len(exact) > 0:
		return exact
	case len(prefix) > 0:
		return prefix
	}
	return contains
}

// OrderAddrs puts the addresses most likely to be reachable first and drops
// ones that never are. On a machine with several interfaces (Wi-Fi, Docker, VPN,
// link-local) a device advertises all of them; trying them in arbitrary order
// can mean waiting on an unreachable one. Order: private LAN IPv4, other IPv4,
// IPv6; loopback and link-local are dropped.
func OrderAddrs(addrs []string) []string {
	rank := func(a string) int {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			return -1
		}
		ip := net.ParseIP(host)
		switch {
		case ip == nil, ip.IsLoopback(), ip.IsLinkLocalUnicast(), ip.IsUnspecified():
			return -1
		case ip.To4() != nil && ip.IsPrivate():
			return 0
		case ip.To4() != nil:
			return 1
		}
		return 2
	}
	var out []string
	for r := 0; r <= 2; r++ {
		for _, a := range addrs {
			if rank(a) == r {
				out = append(out, a)
			}
		}
	}
	return out
}
