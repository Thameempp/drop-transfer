package discovery

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/grandcat/zeroconf"
)

// MDNS implements Advertiser and Browser using mDNS/DNS-SD.
type MDNS struct{}

func (MDNS) Advertise(svc Service) (func(), error) {
	vers := make([]string, len(svc.Versions))
	for i, v := range svc.Versions {
		vers[i] = strconv.Itoa(v)
	}
	txt := []string{
		"id=" + svc.ID,
		"name=" + svc.Name,
		"os=" + svc.OS,
		"v=" + strings.Join(vers, ","),
	}
	// The instance name must be unique on the LAN; the device ID is.
	srv, err := zeroconf.Register(svc.ID, ServiceType, "local.", svc.Port, txt, nil)
	if err != nil {
		return nil, fmt.Errorf("advertise via mDNS: %w", err)
	}
	return srv.Shutdown, nil
}

func (m MDNS) Browse(ctx context.Context, timeout time.Duration) ([]Peer, error) {
	return m.BrowseUntil(ctx, timeout, nil)
}

func (MDNS) BrowseUntil(ctx context.Context, timeout time.Duration, stop func([]Peer) bool) ([]Peer, error) {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return nil, fmt.Errorf("start mDNS resolver: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	entries := make(chan *zeroconf.ServiceEntry)
	var peers []Peer
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range entries {
			if p, ok := fromEntry(e); ok {
				peers = append(peers, p)
				if stop != nil && stop(dedupe(peers)) {
					cancel() // found what we were looking for: do not wait out the timeout
				}
			}
		}
	}()
	if err := resolver.Browse(ctx, ServiceType, "local.", entries); err != nil {
		return nil, fmt.Errorf("browse mDNS: %w", err)
	}
	<-ctx.Done()
	<-done // Browse closes entries once ctx ends
	return dedupe(peers), nil
}

func fromEntry(e *zeroconf.ServiceEntry) (Peer, bool) {
	txt := map[string]string{}
	for _, kv := range e.Text {
		if k, v, ok := strings.Cut(kv, "="); ok {
			txt[k] = v
		}
	}
	id := txt["id"]
	if id == "" || e.Port == 0 {
		return Peer{}, false
	}
	p := Peer{ID: id, Name: txt["name"], OS: txt["os"]}
	if p.Name == "" {
		p.Name = id[:min(8, len(id))]
	}
	for _, s := range strings.Split(txt["v"], ",") {
		if v, err := strconv.Atoi(s); err == nil {
			p.Versions = append(p.Versions, v)
		}
	}
	port := strconv.Itoa(e.Port)
	for _, ip := range e.AddrIPv4 {
		p.Addrs = append(p.Addrs, net.JoinHostPort(ip.String(), port))
	}
	for _, ip := range e.AddrIPv6 {
		if ip.IsLinkLocalUnicast() {
			continue // needs a zone id we do not have
		}
		p.Addrs = append(p.Addrs, net.JoinHostPort(ip.String(), port))
	}
	return p, len(p.Addrs) > 0
}

func dedupe(in []Peer) []Peer {
	seen := map[string]int{}
	var out []Peer
	for _, p := range in {
		if i, ok := seen[p.ID]; ok {
			out[i].Addrs = appendUnique(out[i].Addrs, p.Addrs...)
			continue
		}
		seen[p.ID] = len(out)
		out = append(out, p)
	}
	return out
}

func appendUnique(dst []string, src ...string) []string {
	for _, s := range src {
		found := false
		for _, d := range dst {
			if d == s {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, s)
		}
	}
	return dst
}
