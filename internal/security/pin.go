package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
)

// PIN length bounds. The default is 6 digits; longer PINs are allowed.
const (
	DefaultPINLength = 6
	MinPINLength     = 6
	MaxPINLength     = 12
)

// Argon2id parameters for new verifiers (RFC 9106 "second recommended" profile
// scaled to interactive use). They are stored with the verifier so they can be
// raised later without invalidating existing PINs.
var (
	argonTime    uint32 = 3
	argonMemKiB  uint32 = 64 * 1024
	argonThreads uint8  = 4
)

const (
	argonKeyLen = 32
	saltLen     = 16
	verifierAlg = "argon2id"
	verifierVer = 1
)

// ReduceKDFCostForTests lowers the Argon2id cost so test suites that create many
// verifiers run quickly. It must never be called by production code; verifiers
// created afterwards are deliberately weak.
func ReduceKDFCostForTests() { argonTime, argonMemKiB, argonThreads = 1, 256, 1 }

// Limits a sender accepts for receiver-supplied Argon2 parameters, so a hostile
// receiver cannot make the sender allocate unbounded memory or time.
const (
	maxArgonTime    = 10
	maxArgonMemKiB  = 256 * 1024
	maxArgonThreads = 16
)

var (
	// ErrInvalidPIN is returned for PINs that are empty, too short/long or non-numeric.
	ErrInvalidPIN = errors.New("a Drop PIN must be 6 to 12 digits")
	// ErrNoPIN means no PIN has been configured on this device.
	ErrNoPIN = errors.New("no Drop PIN is configured")
	// ErrPINNotRecoverable: a PIN is set, but only its hash is known.
	ErrPINNotRecoverable = errors.New("the current PIN cannot be shown")
)

// ValidatePIN checks format only.
func ValidatePIN(pin string) error {
	if len(pin) < MinPINLength || len(pin) > MaxPINLength {
		return ErrInvalidPIN
	}
	for _, r := range pin {
		if r < '0' || r > '9' {
			return ErrInvalidPIN
		}
	}
	return nil
}

// GeneratePIN returns a uniformly random numeric PIN.
func GeneratePIN(length int) (string, error) {
	if length < MinPINLength || length > MaxPINLength {
		return "", ErrInvalidPIN
	}
	out := make([]byte, length)
	ten := big.NewInt(10)
	for i := range out {
		n, err := rand.Int(rand.Reader, ten)
		if err != nil {
			return "", fmt.Errorf("generate PIN: %w", err)
		}
		out[i] = byte('0' + n.Int64())
	}
	return string(out), nil
}

// Verifier is what a receiver stores instead of the PIN: an Argon2id hash with
// its salt and parameters. It is persisted as pin.json (mode 0600).
//
// Honest note: the verifier is the PAKE password, so anyone who steals the file
// can impersonate this receiver to senders, and can brute-force a 6-digit PIN
// offline (Argon2id makes each guess expensive, but the space is only 10^6).
// Protect the file like a credential.
type Verifier struct {
	Algorithm string `json:"algorithm"`
	Version   int    `json:"version"`
	Salt      []byte `json:"salt"`
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
	Hash      []byte `json:"pin_hash"`
}

// NewVerifier derives a verifier for pin with a fresh random salt.
func NewVerifier(pin string) (*Verifier, error) {
	if err := ValidatePIN(pin); err != nil {
		return nil, err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return &Verifier{
		Algorithm: verifierAlg, Version: verifierVer, Salt: salt,
		Time: argonTime, MemoryKiB: argonMemKiB, Threads: argonThreads,
		Hash: argon2.IDKey([]byte(pin), salt, argonTime, argonMemKiB, argonThreads, argonKeyLen),
	}, nil
}

// Check reports whether pin matches the verifier (constant-time compare).
func (v *Verifier) Check(pin string) bool {
	if ValidatePIN(pin) != nil {
		return false
	}
	got := argon2.IDKey([]byte(pin), v.Salt, v.Time, v.MemoryKiB, v.Threads, argonKeyLen)
	return subtle.ConstantTimeCompare(got, v.Hash) == 1
}

// password is the PAKE input derived from the verifier. The receiver holds it
// as hex(Hash); a sender reproduces it from the PIN and the receiver's params.
func (v *Verifier) password() string { return hex.EncodeToString(v.Hash) }

// passwordFromPIN is the sender-side derivation.
func passwordFromPIN(pin string, p paramsView) (string, error) {
	if err := ValidatePIN(pin); err != nil {
		return "", err
	}
	if len(p.Salt) < 8 || len(p.Salt) > 64 || p.Time == 0 || p.Time > maxArgonTime ||
		p.MemoryKiB < 8 || p.MemoryKiB > maxArgonMemKiB || p.Threads == 0 || p.Threads > maxArgonThreads {
		return "", errors.New("receiver sent unacceptable PIN parameters")
	}
	h := argon2.IDKey([]byte(pin), p.Salt, p.Time, p.MemoryKiB, p.Threads, argonKeyLen)
	return hex.EncodeToString(h), nil
}

type paramsView struct {
	Salt      []byte
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
}

func (v *Verifier) params() paramsView {
	return paramsView{v.Salt, v.Time, v.MemoryKiB, v.Threads}
}

// PINStore persists the verifier.
type PINStore struct{ path string }

// OpenPINStore returns the store for dir.
func OpenPINStore(dir string) *PINStore { return &PINStore{path: filepath.Join(dir, "pin.json")} }

// Load returns the stored verifier or ErrNoPIN.
func (s *PINStore) Load() (*Verifier, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoPIN
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", s.path, err)
	}
	var v Verifier
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.path, err)
	}
	if v.Algorithm != verifierAlg || v.Version != verifierVer || len(v.Hash) != argonKeyLen || len(v.Salt) < 8 {
		return nil, fmt.Errorf("parse %s: unsupported or corrupt PIN verifier", s.path)
	}
	return &v, nil
}

// Save replaces the verifier atomically with 0600 permissions.
func (s *PINStore) Save(v *Verifier) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode verifier: %w", err)
	}
	return writeFileAtomic(s.path, data)
}

// Set derives and stores a verifier for pin, plus a 0600 copy of the PIN so
// the owner can look it up again (see Reveal).
func (s *PINStore) Set(pin string) error {
	v, err := NewVerifier(pin)
	if err != nil {
		return err
	}
	if err := s.Save(v); err != nil {
		return err
	}
	return writeFileAtomic(s.revealPath(), []byte(pin+"\n"))
}

func (s *PINStore) revealPath() string { return filepath.Join(filepath.Dir(s.path), "pin.txt") }

// Reveal returns the current PIN. It fails with ErrNoPIN if none is set, and
// with ErrPINNotRecoverable if the PIN was created before copies were kept (or
// the copy no longer matches the verifier).
func (s *PINStore) Reveal() (string, error) {
	v, err := s.Load()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(s.revealPath())
	if err != nil {
		return "", ErrPINNotRecoverable
	}
	pin := strings.TrimSpace(string(data))
	if !v.Check(pin) {
		return "", ErrPINNotRecoverable
	}
	return pin, nil
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}
