package security

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LimiterConfig sets brute-force protection thresholds.
type LimiterConfig struct {
	MaxAttempts int           // failed attempts allowed before a lockout (default 3)
	BaseLock    time.Duration // first lockout length (default 30s); doubles each time
	MaxLock     time.Duration // cap (default 1h)
}

// DefaultLimiter returns the secure defaults.
func DefaultLimiter() LimiterConfig {
	return LimiterConfig{MaxAttempts: 3, BaseLock: 30 * time.Second, MaxLock: time.Hour}
}

type limiterState struct {
	Failures    int       `json:"failures"`
	Lockouts    int       `json:"lockouts"`
	LockedUntil time.Time `json:"locked_until"`
}

// Limiter counts PIN attempts across ALL peers (an attacker controls their
// address, so per-IP limits would be useless) and persists across restarts so
// killing the receiver does not reset the counter.
//
// An attempt is counted when it STARTS and refunded only on success, so an
// attacker cannot probe and then drop the connection to avoid being counted.
// Trade-off: anyone on the LAN can deliberately lock the receiver out.
type Limiter struct {
	cfg  LimiterConfig
	path string
	now  func() time.Time

	mu sync.Mutex
	st limiterState
}

// OpenLimiter loads (or initialises) limiter state in dir.
func OpenLimiter(dir string, cfg LimiterConfig) (*Limiter, error) {
	return openLimiter(dir, cfg, time.Now)
}

func openLimiter(dir string, cfg LimiterConfig, now func() time.Time) (*Limiter, error) {
	d := DefaultLimiter()
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = d.MaxAttempts
	}
	if cfg.BaseLock <= 0 {
		cfg.BaseLock = d.BaseLock
	}
	if cfg.MaxLock < cfg.BaseLock {
		cfg.MaxLock = cfg.BaseLock
	}
	l := &Limiter{cfg: cfg, path: filepath.Join(dir, "auth_state.json"), now: now}
	data, err := os.ReadFile(l.path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &l.st); err != nil {
			// A corrupt counter must not become a bypass: start locked for one base period.
			l.st = limiterState{Lockouts: 1, LockedUntil: now().Add(cfg.BaseLock)}
		}
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("read %s: %w", l.path, err)
	}
	return l, nil
}

// Begin registers the start of an attempt. If the device is locked it returns
// the remaining lock time instead. The returned remaining is the number of
// attempts left INCLUDING this one's failure (i.e. after it fails).
func (l *Limiter) Begin() (lockedFor time.Duration, remainingAfterFail int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Before(l.st.LockedUntil) {
		return l.st.LockedUntil.Sub(now), 0, nil
	}
	if l.st.Failures >= l.cfg.MaxAttempts { // earlier attempts were abandoned
		l.lockLocked(now)
		return l.st.LockedUntil.Sub(now), 0, l.saveLocked()
	}
	l.st.Failures++
	remaining := l.cfg.MaxAttempts - l.st.Failures
	return 0, remaining, l.saveLocked()
}

// Fail is called when verification failed. It applies a lockout once the
// allowance is used up and returns how long the device is now locked for.
func (l *Limiter) Fail() (lockedFor time.Duration, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if l.st.Failures >= l.cfg.MaxAttempts {
		l.lockLocked(now)
		return l.st.LockedUntil.Sub(now), l.saveLocked()
	}
	return 0, nil
}

// Succeed resets the counters after a successful authentication.
func (l *Limiter) Succeed() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.st = limiterState{}
	return l.saveLocked()
}

// Reset clears all state (used when the PIN is changed).
func (l *Limiter) Reset() error { return l.Succeed() }

func (l *Limiter) lockLocked(now time.Time) {
	d := l.cfg.BaseLock
	for i := 0; i < l.st.Lockouts && d < l.cfg.MaxLock; i++ {
		d *= 2
	}
	if d > l.cfg.MaxLock {
		d = l.cfg.MaxLock
	}
	l.st.Lockouts++
	l.st.Failures = 0
	l.st.LockedUntil = now.Add(d)
}

func (l *Limiter) saveLocked() error {
	data, err := json.Marshal(l.st)
	if err != nil {
		return err
	}
	return writeFileAtomic(l.path, data)
}
