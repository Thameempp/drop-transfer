package cli

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/thameem/drop/internal/discovery"
)

// A nickname is stored under a key. For a device running drop the key is its
// device ID (stable, tied to its key). For anything else it is its address:
// "mac:aa:bb:.." (stable across DHCP changes) or, if the hardware address is
// unknown, "ip:1.2.3.4". Nicknames never leave this machine.
const (
	macKeyPrefix = "mac:"
	ipKeyPrefix  = "ip:"
)

func isAddrKey(k string) bool {
	return strings.HasPrefix(k, macKeyPrefix) || strings.HasPrefix(k, ipKeyPrefix)
}

// parseIPArg accepts "192.168.1.8" or "192.168.1.8:1234" and returns the IPv4.
func parseIPArg(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return "", false
	}
	return ip.To4().String(), true
}

// neighborMACs maps IPv4 to hardware address from the OS neighbor table. It is
// read once per command.
func (a *app) neighborMACs(ctx context.Context) map[string]string {
	if a.neigh == nil {
		a.neigh = map[string]string{}
		for _, n := range discovery.ReadNeighbors(ctx) {
			a.neigh[n.IP] = n.MAC
		}
	}
	return a.neigh
}

// nickAt finds the nickname of a device: by its device ID, else by the
// hardware address behind ip, else by ip itself.
func (a *app) nickAt(ctx context.Context, id, ip string) string {
	if id != "" {
		if n := a.names.Get(id); n != "" {
			return n
		}
	}
	if ip == "" {
		return ""
	}
	if mac := a.neighborMACs(ctx)[ip]; mac != "" {
		if n := a.names.Get(macKeyPrefix + mac); n != "" {
			return n
		}
	}
	return a.names.Get(ipKeyPrefix + ip)
}

// labelAt is label() that also knows nicknames given by address.
func (a *app) labelAt(ctx context.Context, id, name, ip string) string {
	return nickDisplay(a.nickAt(ctx, id, ip), sanitizeLabel(name))
}

// ipForKey is the current IPv4 of a nickname key given by address ("" if the
// device is not on the network right now).
func (a *app) ipForKey(ctx context.Context, key string) string {
	switch {
	case strings.HasPrefix(key, ipKeyPrefix):
		return strings.TrimPrefix(key, ipKeyPrefix)
	case strings.HasPrefix(key, macKeyPrefix):
		mac := strings.TrimPrefix(key, macKeyPrefix)
		for ip, m := range a.neighborMACs(ctx) {
			if strings.EqualFold(m, mac) {
				return ip
			}
		}
	}
	return ""
}

// describeKey is how a nickname's device is shown in lists.
func describeKey(key string) string {
	switch {
	case strings.HasPrefix(key, macKeyPrefix):
		return "device " + strings.TrimPrefix(key, macKeyPrefix)
	case strings.HasPrefix(key, ipKeyPrefix):
		return "address " + strings.TrimPrefix(key, ipKeyPrefix)
	}
	if len(key) >= 8 {
		return key[:8]
	}
	return key
}

// peersAtIP returns the discovered drop devices reachable at ip.
func peersAtIP(peers []discovery.Peer, ip string) []discovery.Peer {
	var out []discovery.Peer
	for _, p := range peers {
		for _, addr := range p.Addrs {
			if h, _, err := net.SplitHostPort(addr); err == nil && h == ip {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// resolveAddress turns an address into the best key to hang a nickname on: the
// device ID if a drop device answers there, else its hardware address, else the IP.
func (a *app) resolveAddress(ctx context.Context, ip string) (devRef, error) {
	if ip == "" {
		return devRef{}, usageErr("empty address")
	}
	if peers, err := a.disc.Browse(ctx, 2*time.Second); err == nil {
		if m := peersAtIP(peers, ip); len(m) > 0 && m[0].ID != a.identity.ID {
			return devRef{ID: m[0].ID, Name: m[0].Name}, nil
		}
	}
	// Make the OS learn the address, then look it up.
	if c, err := net.DialTimeout("udp", net.JoinHostPort(ip, "9"), time.Second); err == nil {
		c.Write([]byte{0})
		c.Close()
		time.Sleep(300 * time.Millisecond)
	}
	a.neigh = nil
	if mac := a.neighborMACs(ctx)[ip]; mac != "" {
		return devRef{ID: macKeyPrefix + mac, Name: ip}, nil
	}
	if !discovery.OnLink(net.ParseIP(ip)) {
		return devRef{}, usageErr("%s is not on your local network", ip)
	}
	return devRef{ID: ipKeyPrefix + ip, Name: ip}, nil
}

func nickDisplay(nick, name string) string {
	switch {
	case nick == "":
		return name
	case name == "" || strings.EqualFold(nick, name):
		return nick
	}
	return fmt.Sprintf("%s (%s)", nick, name)
}
