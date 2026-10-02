package discovery

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"
)

// Host is any device found on the local network, whether or not it runs drop.
type Host struct {
	Name     string   // best available name; the IP address if nothing better is known
	NameFrom string   // "drop", "mDNS", "NetBIOS", "reverse DNS" or "" (unknown)
	IP       string   // primary IPv4 address
	Addrs    []string // all addresses
	MAC      string
	Services []string // advertised mDNS service types, e.g. "_airplay._tcp"
	Drop     *Peer    // non-nil when the device is running `drop receive`
}

// ScanOptions controls LAN discovery.
type ScanOptions struct {
	// Timeout bounds each discovery phase.
	Timeout time.Duration
	// Probe sends one tiny UDP packet to every address of the local subnet so
	// that the operating system learns which neighbors exist (it fills the ARP
	// table). Without it only devices this machine has recently talked to appear.
	Probe bool
}

// maxServiceTypes bounds how many advertised service types are browsed.
const maxServiceTypes = 24

// ScanLAN finds devices on the local network from three sources: mDNS (every
// advertised service type, plus drop itself), the neighbor table, and several
// name lookups. Devices that advertise nothing and have a randomised MAC (many
// phones) can still appear, but only by address.
//
// Phases: (1) in parallel: drop peers, the list of advertised service types, and
// the subnet probe; then read the neighbor table. (2) in parallel: browse each
// advertised type, and look up names for the devices found in (1).
func ScanLAN(ctx context.Context, o ScanOptions) ([]Host, error) {
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Second
	}
	self := localIPs()

	// ---- phase 1
	var (
		peers []Peer
		types []string
		wg    sync.WaitGroup
	)
	wg.Add(3)
	go func() { defer wg.Done(); peers, _ = MDNS{}.Browse(ctx, o.Timeout) }() // a failed drop browse still leaves the other sources
	go func() { defer wg.Done(); types = browseServiceTypes(ctx, o.Timeout) }()
	go func() {
		defer wg.Done()
		if o.Probe {
			probeSubnets(ctx)
		}
	}()
	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	hosts := map[string]*Host{} // keyed by IPv4
	get := func(ip string) *Host {
		h, ok := hosts[ip]
		if !ok {
			h = &Host{IP: ip, Name: ip}
			hosts[ip] = h
		}
		return h
	}
	for _, n := range ReadNeighbors(ctx) {
		if !self[n.IP] {
			get(n.IP).MAC = n.MAC
		}
	}
	for i := range peers {
		p := &peers[i]
		for _, a := range p.Addrs {
			// Not filtered by our own IP: another drop identity on this machine is
			// a legitimate peer. The caller excludes this device by its ID.
			host, _, err := net.SplitHostPort(a)
			if err != nil {
				continue
			}
			if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
				h := get(ip.To4().String())
				h.Drop = p
				h.Name, h.NameFrom = p.Name, "drop"
			}
		}
	}

	// ---- phase 2
	var typeList []string
	seenType := map[string]bool{}
	for _, t := range types {
		if t != ServiceType && !seenType[t] && len(typeList) < maxServiceTypes {
			seenType[t] = true
			typeList = append(typeList, t)
		}
	}
	sort.Strings(typeList)
	var unnamed []Host // copies for the lookups, merged back below
	for _, h := range hosts {
		if h.NameFrom == "" {
			unnamed = append(unnamed, Host{IP: h.IP})
		}
	}
	var entries []*zeroconf.ServiceEntry
	wg.Add(2)
	go func() { defer wg.Done(); entries = browseTypes(ctx, typeList, o.Timeout) }()
	go func() { defer wg.Done(); resolveNames(ctx, unnamed) }()
	wg.Wait()

	for _, e := range entries {
		for _, a4 := range e.AddrIPv4 {
			ip := a4.String()
			if self[ip] {
				continue
			}
			h := get(ip)
			if name := cleanHost(e.HostName); name != "" && h.NameFrom == "" {
				h.Name, h.NameFrom = name, "mDNS"
			}
			h.Services = addUnique(h.Services, serviceOf(e))
			for _, a6 := range e.AddrIPv6 {
				if !a6.IsLinkLocalUnicast() {
					h.Addrs = addUnique(h.Addrs, a6.String())
				}
			}
		}
	}
	for _, u := range unnamed { // names from the lookups fill only what is still unnamed
		if h := hosts[u.IP]; h != nil && h.NameFrom == "" && u.NameFrom != "" {
			h.Name, h.NameFrom = u.Name, u.NameFrom
		}
	}

	out := make([]Host, 0, len(hosts))
	for _, h := range hosts {
		h.Addrs = append([]string{h.IP}, h.Addrs...)
		out = append(out, *h)
	}
	sortHosts(out)
	return out, nil
}

// browseServiceTypes asks "what service types exist on this network?" using
// the DNS-SD meta query.
func browseServiceTypes(ctx context.Context, timeout time.Duration) []string {
	r, err := zeroconf.NewResolver(nil)
	if err != nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ch := make(chan *zeroconf.ServiceEntry)
	var types []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range ch {
			t := strings.TrimSuffix(strings.TrimSuffix(e.Instance, "."), ".local")
			if strings.HasPrefix(t, "_") {
				types = append(types, t)
			}
		}
	}()
	if err := r.Browse(cctx, "_services._dns-sd._udp", "local.", ch); err != nil {
		return nil
	}
	<-cctx.Done()
	<-done
	return types
}

// browseTypes browses several service types concurrently and returns every
// instance seen.
func browseTypes(ctx context.Context, types []string, timeout time.Duration) []*zeroconf.ServiceEntry {
	var mu sync.Mutex
	var all []*zeroconf.ServiceEntry
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, t := range types {
		wg.Add(1)
		sem <- struct{}{}
		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()
			r, err := zeroconf.NewResolver(nil)
			if err != nil {
				return
			}
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			ch := make(chan *zeroconf.ServiceEntry)
			done := make(chan struct{})
			go func() {
				defer close(done)
				for e := range ch {
					mu.Lock()
					all = append(all, e)
					mu.Unlock()
				}
			}()
			if err := r.Browse(cctx, t, "local.", ch); err != nil {
				return
			}
			<-cctx.Done()
			<-done
		}(t)
	}
	wg.Wait()
	return all
}

func serviceOf(e *zeroconf.ServiceEntry) string {
	return strings.TrimSuffix(e.Service, ".")
}

func cleanHost(h string) string {
	h = strings.TrimSuffix(strings.TrimSuffix(h, "."), ".local")
	return strings.TrimSpace(h)
}

func addUnique(list []string, s string) []string {
	if s == "" {
		return list
	}
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// sortHosts lists devices that run drop first, then named devices, then by address.
func sortHosts(hosts []Host) {
	sort.SliceStable(hosts, func(i, j int) bool {
		a, b := hosts[i], hosts[j]
		if (a.Drop != nil) != (b.Drop != nil) {
			return a.Drop != nil
		}
		if (a.NameFrom != "") != (b.NameFrom != "") {
			return a.NameFrom != ""
		}
		return ipLess(a.IP, b.IP)
	})
}

func ipLess(a, b string) bool {
	x, y := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if x == nil || y == nil {
		return a < b
	}
	return string(x) < string(y)
}

// localIPs returns this machine's own addresses.
func localIPs() map[string]bool {
	out := map[string]bool{}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			out[ipn.IP.String()] = true
		}
	}
	return out
}

// SubnetTargets returns the IPv4 addresses to probe for an interface address:
// its subnet, but never more than the surrounding /24 (a /16 sweep would send
// 65,000 packets), excluding the network, broadcast and our own address.
func SubnetTargets(ip net.IP, mask net.IPMask) []string {
	v4 := ip.To4()
	if v4 == nil || len(mask) != 4 && len(mask) != 16 {
		return nil
	}
	if len(mask) == 16 {
		mask = mask[12:]
	}
	ones, _ := mask.Size()
	if ones < 24 {
		mask = net.CIDRMask(24, 32)
	}
	base := make(net.IP, 4)
	for i := range base {
		base[i] = v4[i] & mask[i]
	}
	var out []string
	cur := make(net.IP, 4)
	copy(cur, base)
	for {
		cur = nextIP(cur)
		inSubnet := true
		for i := range cur {
			if cur[i]&mask[i] != base[i] {
				inSubnet = false
			}
		}
		if !inSubnet {
			break
		}
		isBroadcast := true
		for i := range cur {
			if cur[i]|mask[i] != 0xff {
				isBroadcast = false
			}
		}
		if isBroadcast || cur.Equal(v4) {
			continue
		}
		out = append(out, cur.String())
	}
	return out
}

func nextIP(ip net.IP) net.IP {
	n := make(net.IP, len(ip))
	copy(n, ip)
	for i := len(n) - 1; i >= 0; i-- {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
	return n
}

// probeSubnets sends a single one-byte UDP datagram (to the discard port) to
// every address of each local private subnet. The datagram itself is ignored;
// what matters is that the operating system must resolve each address (ARP) to
// send it, which populates the neighbor table with the devices that exist.
func probeSubnets(ctx context.Context) {
	targets := subnetTargets()
	sem := make(chan struct{}, 128)
	var wg sync.WaitGroup
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			c, err := net.DialTimeout("udp", net.JoinHostPort(ip, "9"), 500*time.Millisecond)
			if err != nil {
				return
			}
			c.Write([]byte{0})
			c.Close()
		}(t)
	}
	wg.Wait()
	// Give ARP a moment to resolve the replies before the table is read.
	select {
	case <-time.After(1200 * time.Millisecond):
	case <-ctx.Done():
	}
}

// FriendlyService turns an mDNS service type into something readable.
func FriendlyService(t string) string {
	known := map[string]string{
		"_airplay._tcp": "AirPlay", "_raop._tcp": "AirPlay audio", "_companion-link._tcp": "Apple device",
		"_ssh._tcp": "SSH", "_sftp-ssh._tcp": "SFTP", "_smb._tcp": "file sharing", "_afpovertcp._tcp": "file sharing",
		"_http._tcp": "web server", "_https._tcp": "web server", "_ipp._tcp": "printer", "_printer._tcp": "printer",
		"_pdl-datastream._tcp": "printer", "_googlecast._tcp": "Chromecast", "_spotify-connect._tcp": "Spotify",
		"_hap._tcp": "HomeKit", "_homekit._tcp": "HomeKit", "_workstation._tcp": "computer", "_device-info._tcp": "device",
		"_adisk._tcp": "Time Machine disk", "_rfb._tcp": "screen sharing", "_sleep-proxy._udp": "Apple TV/AirPort",
		"_drop._tcp": "drop", "_services._dns-sd._udp": "",
	}
	if f, ok := known[t]; ok {
		return f
	}
	return strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(t, "_"), "._tcp"), "._udp")
}

// Describe summarises a host in a few words for display.
func (h Host) Describe() string {
	var parts []string
	seen := map[string]bool{}
	for _, s := range h.Services {
		f := FriendlyService(s)
		if f != "" && !seen[f] {
			seen[f] = true
			parts = append(parts, f)
		}
	}
	if len(parts) > 3 {
		parts = append(parts[:3], fmt.Sprintf("+%d", len(parts)-3))
	}
	d := strings.Join(parts, ", ")
	if d == "" && h.MAC != "" {
		if IsPrivateMAC(h.MAC) {
			return "phone/tablet or privacy-MAC device"
		}
		return "unidentified device"
	}
	return d
}

// subnetTargets lists every address to probe on the local private subnets.
func subnetTargets() []string {
	ifaces, _ := net.Interfaces()
	var targets []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && ipn.IP.IsPrivate() {
				targets = append(targets, SubnetTargets(ipn.IP, ipn.Mask)...)
			}
		}
	}
	return targets
}
