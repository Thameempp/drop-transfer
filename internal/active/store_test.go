package active

import "testing"

func TestCheckRequiresEveryCondition(t *testing.T) {
	st := Settings{Enabled: true, Dir: "/shared", Devices: []string{"dev1"}, Networks: []Network{{Name: "Home", GatewayMAC: "aa:bb:cc:dd:ee:ff"}}}
	ok := func(s Settings, id string, trusted bool, mac string, onLink bool) bool {
		return s.Check(id, trusted, mac, onLink).OK
	}
	if !ok(st, "dev1", true, "AA:BB:CC:DD:EE:FF", true) {
		t.Fatal("all conditions met but refused")
	}
	if d := st.Check("dev1", true, "AA:BB:CC:DD:EE:FF", true); d.Dir != "/shared" {
		t.Fatalf("dir %q", d.Dir)
	}
	cases := map[string]bool{
		"not trusted on this connection": ok(st, "dev1", false, "aa:bb:cc:dd:ee:ff", true),
		"device not allowed":             ok(st, "dev2", true, "aa:bb:cc:dd:ee:ff", true),
		"empty key id":                   ok(st, "", true, "aa:bb:cc:dd:ee:ff", true),
		"other network":                  ok(st, "dev1", true, "11:22:33:44:55:66", true),
		"unknown network":                ok(st, "dev1", true, "", true),
		"sender off link":                ok(st, "dev1", true, "aa:bb:cc:dd:ee:ff", false),
	}
	for name, got := range cases {
		if got {
			t.Errorf("%s: accepted", name)
		}
	}
	off := st
	off.Enabled = false
	if ok(off, "dev1", true, "aa:bb:cc:dd:ee:ff", true) {
		t.Error("disabled but accepted")
	}
	nodir := st
	nodir.Dir = ""
	if ok(nodir, "dev1", true, "aa:bb:cc:dd:ee:ff", true) {
		t.Error("no folder but accepted")
	}
}

func TestStoreRoundTripAndEdits(t *testing.T) {
	s := OpenStore(t.TempDir())
	err := s.Update(func(st *Settings) error {
		st.Dir = "/x"
		st.Allow("a")
		st.Allow("a")
		st.AddNetwork(Network{Name: "Home", GatewayMAC: "aa:aa:aa:aa:aa:aa"})
		st.AddNetwork(Network{Name: "Home2", GatewayMAC: "AA:AA:AA:AA:AA:AA"}) // same router replaces
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	st, _ := s.Load()
	if len(st.Devices) != 1 || len(st.Networks) != 1 || st.Networks[0].Name != "Home2" || st.Dir != "/x" {
		t.Fatalf("%+v", st)
	}
	s.Update(func(st *Settings) error {
		if !st.Deny("a") || st.Deny("a") || !st.RemoveNetwork("home2") {
			t.Error("deny/remove")
		}
		return nil
	})
}

func TestNicknames(t *testing.T) {
	n := OpenNames(t.TempDir())
	if err := n.Set("id1", "  Mom's\x1b[31m laptop "); err != nil {
		t.Fatal(err)
	}
	if got := n.Get("id1"); got != "Mom's[31m laptop" {
		t.Fatalf("control characters not stripped: %q", got)
	}
	if id, ok := n.Resolve("mom's[31m LAPTOP"); !ok || id != "id1" {
		t.Fatal("resolve is case-insensitive")
	}
	if err := n.Set("id2", "MOM'S[31M LAPTOP"); err != ErrNameTaken {
		t.Fatalf("duplicate allowed: %v", err)
	}
	if err := n.Set("id1", ""); err != nil || n.Get("id1") != "" {
		t.Fatal("clear failed")
	}
	if Display("Mom", "Thameem-mac") != "Mom (Thameem-mac)" || Display("", "x") != "x" {
		t.Fatal("display")
	}
}

func TestCheckClipboardIsIndependentOfFileSettings(t *testing.T) {
	st := Settings{Clipboard: true, Devices: []string{"dev1"}, Networks: []Network{{Name: "Home", GatewayMAC: "aa:bb:cc:dd:ee:ff"}}}
	if !st.CheckClipboard("dev1", true, "AA:BB:CC:DD:EE:FF", true).OK {
		t.Fatal("live clipboard needs no folder and no file-sharing switch")
	}
	if st.Check("dev1", true, "aa:bb:cc:dd:ee:ff", true).OK {
		t.Fatal("clipboard switch must not enable file auto-accept")
	}
	cases := map[string]bool{
		"untrusted":     st.CheckClipboard("dev1", false, "aa:bb:cc:dd:ee:ff", true).OK,
		"not allowed":   st.CheckClipboard("dev2", true, "aa:bb:cc:dd:ee:ff", true).OK,
		"other network": st.CheckClipboard("dev1", true, "11:22:33:44:55:66", true).OK,
		"off link":      st.CheckClipboard("dev1", true, "aa:bb:cc:dd:ee:ff", false).OK,
	}
	for name, got := range cases {
		if got {
			t.Errorf("%s: accepted", name)
		}
	}
	off := st
	off.Clipboard = false
	if off.CheckClipboard("dev1", true, "aa:bb:cc:dd:ee:ff", true).OK {
		t.Fatal("accepted while switched off")
	}
	files := Settings{Enabled: true, Dir: "/x", Devices: st.Devices, Networks: st.Networks}
	if files.CheckClipboard("dev1", true, "aa:bb:cc:dd:ee:ff", true).OK {
		t.Fatal("file sharing alone must not enable clipboard")
	}
}
