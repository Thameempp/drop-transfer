// Package active holds the settings for "active sharing" (auto-accepting files
// from chosen trusted devices on a saved network into a dedicated folder) and
// the private nicknames given to devices.
package active

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Network identifies a local network by its router's hardware address. The
// Wi-Fi name is not used: operating systems hide it from programs, and it is
// trivial to copy. A router address is also valid on Ethernet.
type Network struct {
	Name       string `json:"name"`
	GatewayMAC string `json:"gateway_mac"`
	SSID       string `json:"ssid,omitempty"` // Wi-Fi name when it was known; a label only, never matched
}

// Settings is the stored active-sharing configuration.
type Settings struct {
	Enabled bool `json:"enabled"`
	// Clipboard turns on live clipboard sharing: allowed devices on a saved
	// network can put text on this computer's clipboard with no prompt. It is
	// independent of Enabled (file active sharing) and needs no folder.
	Clipboard bool      `json:"clipboard"`
	Dir       string    `json:"dir"`
	Devices   []string  `json:"devices"` // trusted device IDs (hash of the device key)
	Networks  []Network `json:"networks"`
}

// Store persists Settings in active.json (0600). Every read goes to disk, so a
// running `drop receive` notices changes made by other commands at once.
type Store struct {
	path string
	mu   sync.Mutex
}

func OpenStore(dir string) *Store { return &Store{path: filepath.Join(dir, "active.json")} }

func (s *Store) Load() (Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *Store) loadLocked() (Settings, error) {
	var st Settings
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("read %s: %w", s.path, err)
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return Settings{}, fmt.Errorf("parse %s: %w", s.path, err)
	}
	return st, nil
}

// Update applies fn to the current settings and saves the result.
func (s *Store) Update(fn func(*Settings) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return err
	}
	if err := fn(&st); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, data)
}

func (st Settings) HasDevice(id string) bool {
	for _, d := range st.Devices {
		if d == id {
			return true
		}
	}
	return false
}

func (st Settings) HasNetwork(mac string) bool {
	for _, n := range st.Networks {
		if strings.EqualFold(n.GatewayMAC, mac) {
			return true
		}
	}
	return false
}

// Allow adds a device ID (idempotent).
func (st *Settings) Allow(id string) {
	if !st.HasDevice(id) {
		st.Devices = append(st.Devices, id)
	}
}

// Deny removes a device ID and reports whether it was present.
func (st *Settings) Deny(id string) bool {
	for i, d := range st.Devices {
		if d == id {
			st.Devices = append(st.Devices[:i], st.Devices[i+1:]...)
			return true
		}
	}
	return false
}

// AddNetwork saves a network, replacing one with the same router address or name.
func (st *Settings) AddNetwork(n Network) {
	out := st.Networks[:0:0]
	for _, o := range st.Networks {
		if !strings.EqualFold(o.GatewayMAC, n.GatewayMAC) && !strings.EqualFold(o.Name, n.Name) {
			out = append(out, o)
		}
	}
	st.Networks = append(out, n)
}

// RemoveNetwork deletes a network by name and reports whether it existed.
func (st *Settings) RemoveNetwork(name string) bool {
	for i, n := range st.Networks {
		if strings.EqualFold(n.Name, name) {
			st.Networks = append(st.Networks[:i], st.Networks[i+1:]...)
			return true
		}
	}
	return false
}

// Decision is the outcome of Check.
type Decision struct {
	OK     bool
	Dir    string
	Reason string // why not, for display; empty when OK or when active sharing is simply off
}

// trustedCircle is the part of the decision shared by files and clipboard: a
// trusted, allowed sender on a saved network, on the local link. The reason is
// for display; empty with ok=false means "simply not applicable".
func (st Settings) trustedCircle(keyID string, trusted bool, gatewayMAC string, onLink bool) (reason string, ok bool) {
	switch {
	case !trusted || keyID == "" || !st.HasDevice(keyID):
		return "", false
	case gatewayMAC == "":
		return "the current network could not be identified", false
	case !st.HasNetwork(gatewayMAC):
		return "this is not a saved network", false
	case !onLink:
		return "the sender is not on your local network", false
	}
	return "", true
}

// Check decides whether an incoming file or folder is auto-accepted. keyID must
// be the device ID derived from the TLS-verified key and trusted must say the
// sender was recognized as a trusted device on this connection; both come from
// the receiver, never from what the sender claims. gatewayMAC is the router this
// machine is currently using ("" if unknown) and onLink says whether the
// sender's address is on a directly attached private network.
func (st Settings) Check(keyID string, trusted bool, gatewayMAC string, onLink bool) Decision {
	switch {
	case !st.Enabled:
		return Decision{}
	case st.Dir == "":
		return Decision{Reason: "no active-sharing folder is set"}
	}
	if reason, ok := st.trustedCircle(keyID, trusted, gatewayMAC, onLink); !ok {
		return Decision{Reason: reason}
	}
	return Decision{OK: true, Dir: st.Dir}
}

// CheckClipboard decides whether an incoming clipboard transfer is applied
// without asking. Same sender, network and link rules as Check.
func (st Settings) CheckClipboard(keyID string, trusted bool, gatewayMAC string, onLink bool) Decision {
	if !st.Clipboard {
		return Decision{}
	}
	if reason, ok := st.trustedCircle(keyID, trusted, gatewayMAC, onLink); !ok {
		return Decision{Reason: reason}
	}
	return Decision{OK: true}
}

// Names stores private nicknames: device ID to the name only this user sees.
type Names struct {
	path string
	mu   sync.Mutex
}

func OpenNames(dir string) *Names { return &Names{path: filepath.Join(dir, "nicknames.json")} }

func (n *Names) all() map[string]string {
	m := map[string]string{}
	if data, err := os.ReadFile(n.path); err == nil {
		_ = json.Unmarshal(data, &m) // a damaged file only loses cosmetic names
	}
	return m
}

// Get returns the nickname for a device ID, or "".
func (n *Names) Get(id string) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.all()[id]
}

// List returns every nickname, keyed by device ID.
func (n *Names) List() map[string]string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.all()
}

// Resolve returns the device ID whose nickname equals q (case-insensitive).
func (n *Names) Resolve(q string) (string, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for id, name := range n.all() {
		if strings.EqualFold(name, strings.TrimSpace(q)) {
			return id, true
		}
	}
	return "", false
}

// ErrNameTaken: another device already has that nickname.
var ErrNameTaken = errors.New("another device already has that name")

// Set gives a device a nickname; an empty nickname removes it.
func (n *Names) Set(id, nick string) error {
	nick = Clean(nick)
	n.mu.Lock()
	defer n.mu.Unlock()
	m := n.all()
	if nick == "" {
		delete(m, id)
	} else {
		for other, name := range m {
			if other != id && strings.EqualFold(name, nick) {
				return ErrNameTaken
			}
		}
		m[id] = nick
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(n.path, data)
}

// Clean makes a nickname safe to print: no control characters, at most 32 runes.
func Clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r != 0x7f && !(r >= 0x80 && r < 0xa0) {
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if r := []rune(out); len(r) > 32 {
		out = strings.TrimSpace(string(r[:32]))
	}
	return out
}

// Display shows a device as "nickname (real name)" when it has a nickname.
func Display(nick, name string) string {
	switch {
	case nick == "":
		return name
	case name == "" || strings.EqualFold(nick, name):
		return nick
	}
	return nick + " (" + name + ")"
}

// SortedNetworks returns networks ordered by name, for stable display.
func (st Settings) SortedNetworks() []Network {
	out := append([]Network(nil), st.Networks...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
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
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
