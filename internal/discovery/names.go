package discovery

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Names are looked up in three increasingly general ways, each filling in only
// devices that still have none: reverse mDNS (Apple devices, Linux with Avahi,
// many IoT devices), NetBIOS (Windows PCs, Samba), then the system's reverse DNS
// (routers that run a DNS server). All are best effort: plenty of devices,
// especially phones, answer none of them.

// reverseName returns the in-addr.arpa name for an IPv4 address.
func reverseName(ip string) string {
	p := net.ParseIP(ip).To4()
	if p == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", p[3], p[2], p[1], p[0])
}

// parseReverseAnswer extracts (ip, hostname) from an mDNS reply to a reverse PTR query.
func parseReverseAnswer(packet []byte) (ip, name string, ok bool) {
	var m dns.Msg
	if err := m.Unpack(packet); err != nil {
		return "", "", false
	}
	for _, rr := range append(append([]dns.RR{}, m.Answer...), m.Extra...) {
		ptr, isPtr := rr.(*dns.PTR)
		if !isPtr {
			continue
		}
		h := strings.TrimSuffix(ptr.Hdr.Name, ".")
		if !strings.HasSuffix(h, ".in-addr.arpa") {
			continue
		}
		parts := strings.Split(strings.TrimSuffix(h, ".in-addr.arpa"), ".")
		if len(parts) != 4 {
			continue
		}
		ip = parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
		if n := cleanHost(ptr.Ptr); n != "" && net.ParseIP(ip) != nil {
			return ip, n, true
		}
	}
	return "", "", false
}

// mdnsReverseNames asks the network, via multicast DNS, what each address is
// called. A query sent from a non-5353 port is answered by unicast, so we only
// need to listen on our own socket.
func mdnsReverseNames(ctx context.Context, ips []string, wait time.Duration) map[string]string {
	out := map[string]string{}
	if len(ips) == 0 {
		return out
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return out
	}
	defer conn.Close()
	group := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

	send := func() {
		for _, ip := range ips {
			q := new(dns.Msg)
			q.SetQuestion(reverseName(ip), dns.TypePTR)
			if b, err := q.Pack(); err == nil {
				conn.WriteToUDP(b, group)
			}
		}
	}
	send()
	deadline := time.Now().Add(wait)
	conn.SetReadDeadline(deadline)
	resend := time.AfterFunc(wait/2, send) // UDP is lossy: ask twice
	defer resend.Stop()
	buf := make([]byte, 4096)
	for ctx.Err() == nil {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if ip, name, ok := parseReverseAnswer(buf[:n]); ok {
			out[ip] = name
		}
	}
	return out
}

// nbstatQuery is a NetBIOS "node status" request for the wildcard name.
func nbstatQuery() []byte {
	q := []byte{0x13, 0x37, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20}
	q = append(q, "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"...)
	return append(q, 0, 0, 0x21, 0, 1)
}

// parseNbstat returns the machine name from a node status response: the first
// unique "workstation" (suffix 0x00) name.
func parseNbstat(p []byte) (string, bool) {
	if len(p) < 13 {
		return "", false
	}
	i := 12
	// skip the answer's name (a label sequence, possibly compressed)
	for i < len(p) {
		l := int(p[i])
		if l == 0 {
			i++
			break
		}
		if l&0xC0 == 0xC0 {
			i += 2
			break
		}
		i += 1 + l
	}
	i += 10 // type, class, ttl, rdlength
	if i >= len(p) {
		return "", false
	}
	count := int(p[i])
	i++
	for n := 0; n < count && i+18 <= len(p); n, i = n+1, i+18 {
		name := strings.TrimRight(string(p[i:i+15]), " \x00")
		suffix := p[i+15]
		flags := binary.BigEndian.Uint16(p[i+16 : i+18])
		if suffix == 0x00 && flags&0x8000 == 0 && name != "" && isPrintable(name) {
			return name, true
		}
	}
	return "", false
}

func isPrintable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}

func nbstatName(ip string, timeout time.Duration) (string, bool) {
	c, err := net.DialTimeout("udp4", net.JoinHostPort(ip, "137"), timeout)
	if err != nil {
		return "", false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(nbstatQuery()); err != nil {
		return "", false
	}
	buf := make([]byte, 1024)
	n, err := c.Read(buf)
	if err != nil {
		return "", false
	}
	return parseNbstat(buf[:n])
}

// resolveNames fills in names for hosts that have none.
func resolveNames(ctx context.Context, hosts []Host) {
	unnamed := func() []int {
		var idx []int
		for i := range hosts {
			if hosts[i].NameFrom == "" {
				idx = append(idx, i)
			}
		}
		return idx
	}

	// 1) reverse mDNS, all at once
	if idx := unnamed(); len(idx) > 0 {
		ips := make([]string, len(idx))
		for k, i := range idx {
			ips[k] = hosts[i].IP
		}
		names := mdnsReverseNames(ctx, ips, 1500*time.Millisecond)
		for _, i := range idx {
			if n, ok := names[hosts[i].IP]; ok {
				hosts[i].Name, hosts[i].NameFrom = n, "mDNS"
			}
		}
	}
	// 2) NetBIOS, 3) system reverse DNS: per host, in parallel
	var wg sync.WaitGroup
	sem := make(chan struct{}, 24)
	for _, i := range unnamed() {
		wg.Add(1)
		sem <- struct{}{}
		go func(h *Host) {
			defer wg.Done()
			defer func() { <-sem }()
			if n, ok := nbstatName(h.IP, 700*time.Millisecond); ok {
				h.Name, h.NameFrom = n, "NetBIOS"
				return
			}
			cctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			defer cancel()
			if names, err := net.DefaultResolver.LookupAddr(cctx, h.IP); err == nil && len(names) > 0 {
				if n := cleanHost(names[0]); n != "" && n != h.IP {
					h.Name, h.NameFrom = n, "reverse DNS"
				}
			}
		}(&hosts[i])
	}
	wg.Wait()
}
