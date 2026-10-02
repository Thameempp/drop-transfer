package security

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/thameem/drop/internal/device"
)

// Trusted devices let a sender skip the PIN. Trust is bound to the sender's
// public key, which TLS already proves possession of; the PIN is never stored
// or reused. Compromise model: someone who steals a trusted device's identity
// key (identity.json) can send to receivers that trust it, until the receiver
// revokes it or the trust expires through disuse.

// TrustedDevice is a sender a receiver has chosen to trust.
type TrustedDevice struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	OS        string            `json:"os"`
	PublicKey ed25519.PublicKey `json:"public_key"`
	AddedAt   time.Time         `json:"added_at"`
	LastUsed  time.Time         `json:"last_used"`
}

// DefaultTrustExpiry is how long a trusted device may stay unused before it
// must authorize with the PIN again. Use refreshes it.
const DefaultTrustExpiry = 90 * 24 * time.Hour

// touchInterval bounds how often a use is written back to disk.
const touchInterval = time.Hour

// TrustStore is the receiver-side list of trusted devices (trusted.json, 0600).
// Every lookup notices changes made by other processes, so `drop security
// untrust` takes effect in an already-running `drop receive` immediately.
type TrustStore struct {
	path   string
	expiry time.Duration // 0 disables expiry
	now    func() time.Time

	mu   sync.Mutex
	devs map[string]TrustedDevice
	sig  fileSig
}

type fileSig struct {
	mod  time.Time
	size int64
	ok   bool
}

// OpenTrustStore loads dir/trusted.json (missing means empty).
func OpenTrustStore(dir string, expiry time.Duration) (*TrustStore, error) {
	return openTrustStore(dir, expiry, time.Now)
}

func openTrustStore(dir string, expiry time.Duration, now func() time.Time) (*TrustStore, error) {
	s := &TrustStore{path: filepath.Join(dir, "trusted.json"), expiry: expiry, now: now, devs: map[string]TrustedDevice{}}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *TrustStore) loadLocked() error {
	st, err := os.Stat(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		s.devs, s.sig = map[string]TrustedDevice{}, fileSig{}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", s.path, err)
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("read %s: %w", s.path, err)
	}
	var list []TrustedDevice
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("parse %s: %w", s.path, err)
	}
	devs := make(map[string]TrustedDevice, len(list))
	for _, t := range list {
		// A hand-edited entry must not be able to claim another device's ID.
		if len(t.PublicKey) != ed25519.PublicKeySize || device.IDFromPublicKey(t.PublicKey) != t.ID {
			return fmt.Errorf("parse %s: entry %q does not match its key", s.path, t.Name)
		}
		devs[t.ID] = t
	}
	s.devs, s.sig = devs, fileSig{st.ModTime(), st.Size(), true}
	return nil
}

// refreshLocked reloads when another process changed the file. If the file
// became unreadable or corrupt, trust is dropped (fail closed).
func (s *TrustStore) refreshLocked() {
	st, err := os.Stat(s.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		s.devs, s.sig = map[string]TrustedDevice{}, fileSig{}
	case err != nil:
		s.devs = map[string]TrustedDevice{}
	case !s.sig.ok || !st.ModTime().Equal(s.sig.mod) || st.Size() != s.sig.size:
		if err := s.loadLocked(); err != nil {
			s.devs = map[string]TrustedDevice{}
		}
	}
}

func (s *TrustStore) expired(t TrustedDevice) bool {
	return s.expiry > 0 && s.now().Sub(t.LastUsed) > s.expiry
}

// IsTrusted reports whether pub belongs to a trusted, unexpired device, and
// records the use (at most once per hour) so active devices do not expire.
func (s *TrustStore) IsTrusted(pub ed25519.PublicKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	t, ok := s.devs[device.IDFromPublicKey(pub)]
	if !ok || !bytes.Equal(t.PublicKey, pub) || s.expired(t) {
		return false
	}
	if s.now().Sub(t.LastUsed) > touchInterval {
		t.LastUsed = s.now()
		s.devs[t.ID] = t
		_ = s.saveLocked() // best effort: failing to record a use must not fail the transfer
	}
	return true
}

// Add trusts a device (or refreshes an existing entry) and persists the store.
func (s *TrustStore) Add(pub ed25519.PublicKey, name, osName string) (TrustedDevice, error) {
	if len(pub) != ed25519.PublicKeySize {
		return TrustedDevice{}, errors.New("invalid public key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	now := s.now()
	t := TrustedDevice{ID: device.IDFromPublicKey(pub), Name: CleanLabel(name), OS: CleanLabel(osName), PublicKey: pub, AddedAt: now, LastUsed: now}
	if t.Name == "" {
		t.Name = t.ID[:8]
	}
	if old, ok := s.devs[t.ID]; ok {
		t.AddedAt = old.AddedAt
	}
	s.devs[t.ID] = t
	return t, s.saveLocked()
}

// Remove revokes one device by ID and reports whether it existed.
func (s *TrustStore) Remove(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	if _, ok := s.devs[id]; !ok {
		return false, nil
	}
	delete(s.devs, id)
	return true, s.saveLocked()
}

// RemoveAll revokes every trusted device and returns how many there were.
func (s *TrustStore) RemoveAll() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	n := len(s.devs)
	s.devs = map[string]TrustedDevice{}
	return n, s.saveLocked()
}

// List returns all entries sorted by name, including expired ones (flagged by Expired).
func (s *TrustStore) List() []TrustedDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	out := make([]TrustedDevice, 0, len(s.devs))
	for _, t := range s.devs {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Expired reports whether a listed entry has lapsed.
func (s *TrustStore) Expired(t TrustedDevice) bool { return s.expired(t) }

func (s *TrustStore) saveLocked() error {
	list := make([]TrustedDevice, 0, len(s.devs))
	for _, t := range s.devs {
		list = append(list, t)
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("encode trusted devices: %w", err)
	}
	if err := writeFileAtomic(s.path, data); err != nil {
		return err
	}
	if st, err := os.Stat(s.path); err == nil {
		s.sig = fileSig{st.ModTime(), st.Size(), true}
	}
	return nil
}

// TrustedBy is the sender-side hint of which receivers trust this device. It is
// only used to skip the PIN prompt and to label devices in the menu; the
// receiver remains the authority and a stale hint just falls back to the PIN.
type TrustedBy struct {
	path string
	mu   sync.Mutex
	recs map[string]TrustedByRecord
}

// TrustedByRecord is one receiver that trusts us.
type TrustedByRecord struct {
	Name  string    `json:"name"`
	Since time.Time `json:"since"`
}

// OpenTrustedBy loads dir/trusted_by.json (missing means empty; unreadable means empty, as it is only a hint).
func OpenTrustedBy(dir string) *TrustedBy {
	t := &TrustedBy{path: filepath.Join(dir, "trusted_by.json"), recs: map[string]TrustedByRecord{}}
	if data, err := os.ReadFile(t.path); err == nil {
		_ = json.Unmarshal(data, &t.recs)
		if t.recs == nil {
			t.recs = map[string]TrustedByRecord{}
		}
	}
	return t
}

// Has reports whether the receiver with this device ID is believed to trust us.
func (t *TrustedBy) Has(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.recs[id]
	return ok
}

// Set records that a receiver trusts us.
func (t *TrustedBy) Set(id, name string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if r, ok := t.recs[id]; ok {
		r.Name = CleanLabel(name)
		t.recs[id] = r
	} else {
		t.recs[id] = TrustedByRecord{Name: CleanLabel(name), Since: time.Now().UTC()}
	}
	return t.saveLocked()
}

// Forget drops a stale hint.
func (t *TrustedBy) Forget(id string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.recs[id]; !ok {
		return nil
	}
	delete(t.recs, id)
	return t.saveLocked()
}

func (t *TrustedBy) saveLocked() error {
	data, err := json.MarshalIndent(t.recs, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(t.path, data)
}

// CleanLabel strips control characters from peer-supplied display text and
// bounds its length, so a hostile device name cannot inject terminal escapes.
func CleanLabel(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r != 0x7f && !(r >= 0x80 && r < 0xa0) {
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if r := []rune(out); len(r) > 64 {
		out = string(r[:64])
	}
	return out
}
