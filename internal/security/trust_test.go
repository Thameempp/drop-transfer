package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func newKey(t *testing.T) ed25519.PublicKey {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestTrustStoreAddLookupPersist(t *testing.T) {
	dir := t.TempDir()
	st, _ := OpenTrustStore(dir, DefaultTrustExpiry)
	pub := newKey(t)
	if st.IsTrusted(pub) {
		t.Fatal("unknown key trusted")
	}
	d, err := st.Add(pub, "Windows-PC", "windows")
	if err != nil || d.ID == "" {
		t.Fatal(d, err)
	}
	if !st.IsTrusted(pub) || st.IsTrusted(newKey(t)) {
		t.Fatal("lookup wrong")
	}
	again, _ := OpenTrustStore(dir, DefaultTrustExpiry) // a restart
	if !again.IsTrusted(pub) || len(again.List()) != 1 || again.List()[0].Name != "Windows-PC" {
		t.Fatalf("not persisted: %+v", again.List())
	}
	if runtime.GOOS != "windows" {
		if m, _ := os.Stat(filepath.Join(dir, "trusted.json")); m.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", m.Mode().Perm())
		}
	}
}

// The scenario that matters: `drop receive` is running (one store instance) and
// the user runs `drop security untrust` in another terminal (another instance).
func TestRevocationByAnotherProcessTakesEffectImmediately(t *testing.T) {
	dir := t.TempDir()
	running, _ := OpenTrustStore(dir, DefaultTrustExpiry)
	cli, _ := OpenTrustStore(dir, DefaultTrustExpiry)
	pub := newKey(t)
	d, _ := cli.Add(pub, "laptop", "linux")
	if !running.IsTrusted(pub) {
		t.Fatal("a device trusted by another process is not visible")
	}
	if ok, err := cli.Remove(d.ID); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if running.IsTrusted(pub) {
		t.Fatal("revoked device still trusted by the running receiver")
	}
	cli.Add(pub, "laptop", "linux")
	if n, _ := cli.RemoveAll(); n != 1 || running.IsTrusted(pub) {
		t.Fatal("RemoveAll not honoured")
	}
}

func TestTrustFileDeletedOrCorruptedFailsClosed(t *testing.T) {
	dir := t.TempDir()
	st, _ := OpenTrustStore(dir, DefaultTrustExpiry)
	pub := newKey(t)
	st.Add(pub, "x", "y")
	os.WriteFile(filepath.Join(dir, "trusted.json"), []byte("{{garbage"), 0o600)
	if st.IsTrusted(pub) {
		t.Fatal("corrupted trust file still granted trust")
	}
	os.Remove(filepath.Join(dir, "trusted.json"))
	if st.IsTrusted(pub) {
		t.Fatal("deleted trust file still granted trust")
	}
}

func TestTamperedEntryIsRejected(t *testing.T) {
	dir := t.TempDir()
	pub := newKey(t)
	// An entry claiming an ID that is not the hash of its key.
	bad := `[{"id":"00000000000000000000000000000000","name":"x","public_key":"` + base64.StdEncoding.EncodeToString(pub) + `"}]`
	os.WriteFile(filepath.Join(dir, "trusted.json"), []byte(bad), 0o600)
	if _, err := OpenTrustStore(dir, DefaultTrustExpiry); err == nil {
		t.Fatal("hand-edited entry accepted")
	}
	// Garbage / wrong key length.
	os.WriteFile(filepath.Join(dir, "trusted.json"), []byte(`[{"id":"a","public_key":"AAAA"}]`), 0o600)
	if _, err := OpenTrustStore(dir, DefaultTrustExpiry); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestSlidingExpiry(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	clock := func() time.Time { return now }
	st, _ := openTrustStore(t.TempDir(), 30*24*time.Hour, clock)
	pub := newKey(t)
	st.Add(pub, "x", "y")

	now = now.Add(20 * 24 * time.Hour)
	if !st.IsTrusted(pub) { // used: refreshes
		t.Fatal("trust expired early")
	}
	now = now.Add(20 * 24 * time.Hour) // 40 days since adding, but only 20 since last use
	if !st.IsTrusted(pub) {
		t.Fatal("active device expired: use does not extend trust")
	}
	now = now.Add(31 * 24 * time.Hour) // idle past the limit
	if st.IsTrusted(pub) {
		t.Fatal("idle trust did not expire")
	}
	if l := st.List(); len(l) != 1 || !st.Expired(l[0]) {
		t.Fatal("expired entry should be listed as expired so the user can see and remove it")
	}
	// Re-trusting (after the PIN) revives it.
	st.Add(pub, "x", "y")
	if !st.IsTrusted(pub) {
		t.Fatal("re-trust failed")
	}
}

func TestExpiryZeroMeansNever(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	st, _ := openTrustStore(t.TempDir(), 0, func() time.Time { return now })
	pub := newKey(t)
	st.Add(pub, "x", "y")
	now = now.Add(10 * 365 * 24 * time.Hour)
	if !st.IsTrusted(pub) {
		t.Fatal("expiry disabled but trust lapsed")
	}
}

func TestTrustedNamesAreSanitized(t *testing.T) {
	st, _ := OpenTrustStore(t.TempDir(), 0)
	d, _ := st.Add(newKey(t), "evil\x1b[2J\nname", "linux\x00")
	if strings.ContainsAny(d.Name+d.OS, "\x1b\x00\n") {
		t.Fatalf("%q %q", d.Name, d.OS)
	}
	if e, _ := st.Add(newKey(t), "\x1b\x07", ""); e.Name != e.ID[:8] {
		t.Fatalf("empty name should fall back to the ID prefix: %q", e.Name)
	}
	if _, err := st.Add(ed25519.PublicKey("short"), "x", "y"); err == nil {
		t.Fatal("bad key accepted")
	}
}

func TestTrustedByHint(t *testing.T) {
	dir := t.TempDir()
	tb := OpenTrustedBy(dir)
	if tb.Has("abc") {
		t.Fatal("empty store has an entry")
	}
	tb.Set("abc", "MacBook")
	if !OpenTrustedBy(dir).Has("abc") {
		t.Fatal("not persisted")
	}
	tb.Forget("abc")
	if OpenTrustedBy(dir).Has("abc") {
		t.Fatal("not forgotten")
	}
	os.WriteFile(filepath.Join(dir, "trusted_by.json"), []byte("garbage"), 0o600)
	if OpenTrustedBy(dir).Has("abc") { // a hint only: unreadable means "no hint", never an error or a grant
		t.Fatal("garbage produced a hint")
	}
}
