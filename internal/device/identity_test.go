package device

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestIdentityPersists(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrCreate(dir, "a", "linux")
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreate(dir, "a", "linux")
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != b.ID {
		t.Fatalf("identity changed: %s vs %s", a.ID, b.ID)
	}
}

func TestIdentityFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	dir := t.TempDir()
	if _, err := LoadOrCreate(dir, "a", "linux"); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(filepath.Join(dir, "identity.json"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
}

func TestSignVerify(t *testing.T) {
	id, _ := LoadOrCreate(t.TempDir(), "a", "linux")
	sig := id.Sign([]byte("hi"))
	if !ed25519.Verify(id.PublicKey, []byte("hi"), sig) {
		t.Fatal("signature invalid")
	}
}

func TestCorruptIdentity(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "identity.json"), []byte(`{"private_key":"AA=="}`), 0o600)
	if _, err := LoadOrCreate(dir, "a", "linux"); err == nil {
		t.Fatal("expected error")
	}
}

func TestFingerprintStable(t *testing.T) {
	id, _ := LoadOrCreate(t.TempDir(), "a", "linux")
	first := Fingerprint(id.PublicKey)
	reloaded, _ := LoadOrCreate(filepath.Dir(filepath.Join(t.TempDir(), "x")), "a", "linux") // a different identity
	if first != Fingerprint(id.PublicKey) || len(first) != 95 {
		t.Fatal("fingerprint unstable or wrong length")
	}
	if Fingerprint(reloaded.PublicKey) == first {
		t.Fatal("different identities share a fingerprint")
	}
}
