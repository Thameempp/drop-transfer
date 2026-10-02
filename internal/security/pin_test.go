package security

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestValidatePIN(t *testing.T) {
	for pin, ok := range map[string]bool{"482917": true, "123456789012": true, "": false, "12345": false, "1234567890123": false, "12345a": false, " 12345": false} {
		if (ValidatePIN(pin) == nil) != ok {
			t.Errorf("ValidatePIN(%q) ok=%v", pin, !ok)
		}
	}
}

func TestGeneratePIN(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		p, err := GeneratePIN(6)
		if err != nil || ValidatePIN(p) != nil || len(p) != 6 {
			t.Fatalf("%q %v", p, err)
		}
		seen[p] = true
	}
	if len(seen) < 40 {
		t.Fatal("PINs are not random")
	}
	if _, err := GeneratePIN(3); err == nil {
		t.Fatal("short PIN allowed")
	}
}

func TestVerifierHashingAndChecking(t *testing.T) {
	v, err := NewVerifier("482917")
	if err != nil {
		t.Fatal(err)
	}
	if v.Algorithm != "argon2id" || len(v.Hash) != 32 || len(v.Salt) != 16 {
		t.Fatalf("%+v", v)
	}
	if !v.Check("482917") || v.Check("482918") || v.Check("") || v.Check("abc") {
		t.Fatal("check wrong")
	}
	v2, _ := NewVerifier("482917")
	if string(v.Hash) == string(v2.Hash) {
		t.Fatal("same PIN produced the same hash: salt not random")
	}
}

func TestPINStoreVerifierNeverContainsPlaintextAndIs0600(t *testing.T) {
	dir := t.TempDir()
	s := OpenPINStore(dir)
	if _, err := s.Load(); err != ErrNoPIN {
		t.Fatalf("got %v", err)
	}
	if err := s.Set("482917"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "pin.json"))
	if strings.Contains(string(b), "482917") {
		t.Fatal("plaintext PIN on disk")
	}
	if !strings.Contains(string(b), "argon2id") {
		t.Fatal("verifier not labelled")
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(filepath.Join(dir, "pin.json")); st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", st.Mode().Perm())
		}
	}
	if err := s.Set("12"); err == nil {
		t.Fatal("invalid PIN stored")
	}
}

func TestPINChangeInvalidatesOldPIN(t *testing.T) {
	dir := t.TempDir()
	s := OpenPINStore(dir)
	s.Set("111111")
	s.Set("222222")
	v, _ := s.Load()
	if v.Check("111111") || !v.Check("222222") {
		t.Fatal("old PIN still valid after change")
	}
}

func TestPINStoreRejectsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "pin.json"), []byte(`{"algorithm":"md5","version":1}`), 0o600)
	if _, err := OpenPINStore(dir).Load(); err == nil {
		t.Fatal("accepted a weak/unknown verifier")
	}
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestLimiterLockoutBackoffAndPersistence(t *testing.T) {
	dir := t.TempDir()
	c := &clock{t: time.Unix(1_000_000, 0)}
	cfg := LimiterConfig{MaxAttempts: 3, BaseLock: 30 * time.Second, MaxLock: 2 * time.Minute}
	l, _ := openLimiter(dir, cfg, c.now)

	for i := 0; i < 3; i++ {
		if d, _, _ := l.Begin(); d != 0 {
			t.Fatalf("locked early at %d", i)
		}
		l.Fail()
	}
	if d, _, _ := l.Begin(); d != 30*time.Second {
		t.Fatalf("first lock = %v", d)
	}
	// Persistence: a restarted receiver is still locked.
	l2, _ := openLimiter(dir, cfg, c.now)
	if d, _, _ := l2.Begin(); d == 0 {
		t.Fatal("restart cleared the lockout")
	}
	// After the lock expires, three more failures lock for double the time.
	c.t = c.t.Add(31 * time.Second)
	for i := 0; i < 3; i++ {
		l2.Begin()
		l2.Fail()
	}
	if d, _, _ := l2.Begin(); d != 60*time.Second {
		t.Fatalf("second lock = %v, want 60s", d)
	}
	// Cap.
	c.t = c.t.Add(61 * time.Second)
	for round := 0; round < 4; round++ {
		for i := 0; i < 3; i++ {
			l2.Begin()
			l2.Fail()
		}
		d, _, _ := l2.Begin()
		if d > 2*time.Minute {
			t.Fatalf("lock %v exceeds cap", d)
		}
		c.t = c.t.Add(d + time.Second)
	}
	// Success resets everything.
	l2.Begin()
	l2.Succeed()
	if d, rem, _ := l2.Begin(); d != 0 || rem != 2 {
		t.Fatalf("not reset: %v %d", d, rem)
	}
}

func TestLimiterCorruptStateFailsClosed(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "auth_state.json"), []byte("garbage"), 0o600)
	l, err := OpenLimiter(dir, DefaultLimiter())
	if err != nil {
		t.Fatal(err)
	}
	if d, _, _ := l.Begin(); d == 0 {
		t.Fatal("corrupt state became a bypass")
	}
}

func TestProductionKDFParameters(t *testing.T) {
	// The rest of the suite runs with a cheap KDF; verify what users actually get.
	ot, om, op := argonTime, argonMemKiB, argonThreads
	argonTime, argonMemKiB, argonThreads = 3, 64*1024, 4
	defer func() { argonTime, argonMemKiB, argonThreads = ot, om, op }()
	v, err := NewVerifier("482917")
	if err != nil {
		t.Fatal(err)
	}
	if v.Algorithm != "argon2id" || v.Time != 3 || v.MemoryKiB != 64*1024 || v.Threads != 4 {
		t.Fatalf("production params changed: %+v", v)
	}
	start := time.Now()
	if !v.Check("482917") {
		t.Fatal("check failed")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("verification takes %v: too slow for interactive use", d)
	}
}

func TestRevealPIN(t *testing.T) {
	dir := t.TempDir()
	s := OpenPINStore(dir)
	if _, err := s.Reveal(); err != ErrNoPIN {
		t.Fatalf("got %v", err)
	}
	if err := s.Set("482917"); err != nil {
		t.Fatal(err)
	}
	if pin, err := s.Reveal(); err != nil || pin != "482917" {
		t.Fatalf("got %q %v", pin, err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(filepath.Join(dir, "pin.txt")); st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", st.Mode().Perm())
		}
	}
	// A PIN set without a copy (older versions) or a stale copy is not revealed.
	v, _ := NewVerifier("111222")
	s.Save(v)
	if _, err := s.Reveal(); err != ErrPINNotRecoverable {
		t.Fatalf("stale copy: got %v", err)
	}
	os.Remove(filepath.Join(dir, "pin.txt"))
	if _, err := s.Reveal(); err != ErrPINNotRecoverable {
		t.Fatalf("no copy: got %v", err)
	}
}
