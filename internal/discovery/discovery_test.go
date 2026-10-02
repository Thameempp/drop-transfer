package discovery

import "testing"

func TestMatch(t *testing.T) {
	peers := []Peer{{ID: "aa", Name: "MacBook-Pro"}, {ID: "bb", Name: "Windows-PC"}, {ID: "cc", Name: "windows-laptop"}}
	cases := map[string]int{"macbook-pro": 1, "win": 2, "pc": 1, "nothing": 0, "bb": 1}
	for q, want := range cases {
		if got := Match(peers, q); len(got) != want {
			t.Errorf("Match(%q) = %d peers, want %d", q, len(got), want)
		}
	}
}

func TestDedupeMergesAddrs(t *testing.T) {
	out := dedupe([]Peer{{ID: "a", Addrs: []string{"1:1"}}, {ID: "a", Addrs: []string{"1:1", "2:1"}}})
	if len(out) != 1 || len(out[0].Addrs) != 2 {
		t.Fatalf("%+v", out)
	}
}

func TestOrderAddrs(t *testing.T) {
	got := OrderAddrs([]string{
		"[fe80::1]:9", "169.254.3.4:9", "127.0.0.1:9", "8.8.8.8:9", "172.17.0.1:9", "192.168.1.6:9", "[2001:db8::1]:9", "10.0.0.5:9", "bad", "0.0.0.0:9",
	})
	want := []string{"172.17.0.1:9", "192.168.1.6:9", "10.0.0.5:9", "8.8.8.8:9", "[2001:db8::1]:9"}
	// private IPv4 first (in the order given), then public IPv4, then IPv6; loopback, link-local, unspecified and junk dropped
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	if len(OrderAddrs([]string{"127.0.0.1:9"})) != 0 {
		t.Fatal("loopback-only should yield nothing (callers fall back to the original list)")
	}
}

func TestExactIsStricterThanMatch(t *testing.T) {
	peers := []Peer{{ID: "aa", Name: "Windows-PC"}, {ID: "bb", Name: "windows-laptop"}}
	if len(Match(peers, "win")) != 2 || len(Exact(peers, "win")) != 0 {
		t.Fatal("a prefix must not count as exact (it could still be ambiguous)")
	}
	if got := Exact(peers, "WINDOWS-PC"); len(got) != 1 || got[0].ID != "aa" {
		t.Fatalf("%v", got)
	}
	if got := Exact(peers, "bb"); len(got) != 1 {
		t.Fatalf("%v", got)
	}
}
