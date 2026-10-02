package discovery

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func scan(t *testing.T, port int) []Peer {
	t.Helper()
	var mu sync.Mutex
	var got []Peer
	beaconScan(context.Background(), time.Second, []string{"127.0.0.1"}, port, func(p Peer) {
		mu.Lock()
		got = append(got, p)
		mu.Unlock()
	})
	return got
}

func TestBeaconFindsReceiverWithoutMulticast(t *testing.T) {
	port := freeUDPPort(t)
	stop, err := serveBeacon(Service{ID: "abc123", Name: "laptop", OS: "linux", Port: 4242, Versions: []int{2}}, port)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	got := dedupe(scan(t, port))
	if len(got) != 1 || got[0].ID != "abc123" || got[0].Name != "laptop" || len(got[0].Addrs) != 1 || got[0].Addrs[0] != "127.0.0.1:4242" {
		t.Fatalf("got %+v", got)
	}
}

func TestBeaconIgnoresShortQueries(t *testing.T) {
	port := freeUDPPort(t)
	stop, err := serveBeacon(Service{ID: "abc123", Name: "laptop", Port: 4242}, port)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	c, _ := net.Dial("udp4", net.JoinHostPort("127.0.0.1", itoa(port)))
	defer c.Close()
	c.Write(beaconMagic) // too short to be a valid (non-amplifying) query
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := c.Read(make([]byte, 1500)); err == nil {
		t.Fatalf("short query got a %d byte reply", n)
	}
}

func TestBeaconNothingListening(t *testing.T) {
	if got := scan(t, freeUDPPort(t)); len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
