package discovery

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// BeaconPort is the UDP port a receiver answers direct discovery queries on.
//
// mDNS relies on multicast, which many routers do not forward between Wi-Fi
// and wired clients (or at all, with "AP isolation" or IGMP filtering). Plain
// unicast UDP does work on such networks, so a sender also asks every address
// of its subnet directly and a running receiver replies.
const BeaconPort = 53317

// beaconQueryMin is the minimum size of a query. Replies are smaller, so the
// responder can never be used to amplify spoofed traffic.
const beaconQueryMin = 256

var beaconMagic = []byte("drop-discover-v1")

type beaconReply struct {
	Drop int    `json:"drop"`
	ID   string `json:"id"`
	Name string `json:"name"`
	OS   string `json:"os"`
	Port int    `json:"port"`
	V    []int  `json:"v"`
}

func beaconQuery() []byte {
	q := make([]byte, beaconQueryMin)
	copy(q, beaconMagic)
	return q
}

// serveBeacon answers discovery queries for svc until the returned stop is called.
func serveBeacon(svc Service, port int) (func(), error) {
	pc, err := net.ListenPacket("udp4", net.JoinHostPort("", strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	reply, _ := json.Marshal(beaconReply{Drop: 1, ID: svc.ID, Name: truncate(svc.Name, 64), OS: truncate(svc.OS, 16), Port: svc.Port, V: svc.Versions})
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n >= beaconQueryMin && strings.HasPrefix(string(buf[:n]), string(beaconMagic)) {
				pc.WriteTo(reply, from)
			}
		}
	}()
	return func() { pc.Close() }, nil
}

// beaconScan sends a query to each target (IPv4 addresses) and collects replies
// until timeout. Targets may include broadcast addresses.
func beaconScan(ctx context.Context, timeout time.Duration, targets []string, port int, add func(Peer)) {
	pc, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return
	}
	defer pc.Close()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	go func() { <-ctx.Done(); pc.Close() }()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // send, repeating once in case the first round is dropped
		defer wg.Done()
		q := beaconQuery()
		for round := 0; round < 2; round++ {
			for _, t := range targets {
				if ctx.Err() != nil {
					return
				}
				if ip := net.ParseIP(t); ip != nil {
					pc.WriteTo(q, &net.UDPAddr{IP: ip, Port: port})
				}
			}
			select {
			case <-time.After(300 * time.Millisecond):
			case <-ctx.Done():
				return
			}
		}
	}()

	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		var r beaconReply
		ua, ok := from.(*net.UDPAddr)
		if !ok || json.Unmarshal(buf[:n], &r) != nil || r.Drop != 1 || r.ID == "" || r.Port <= 0 || r.Port > 65535 {
			continue
		}
		p := Peer{ID: truncate(r.ID, 64), Name: truncate(r.Name, 64), OS: truncate(r.OS, 16), Versions: r.V,
			Addrs: []string{net.JoinHostPort(ua.IP.String(), strconv.Itoa(r.Port))}}
		if p.Name == "" {
			p.Name = p.ID[:min(8, len(p.ID))]
		}
		add(p)
	}
	wg.Wait()
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
