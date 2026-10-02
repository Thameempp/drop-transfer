package cli

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/thameem/drop/internal/active"
	"github.com/thameem/drop/internal/config"
	"github.com/thameem/drop/internal/device"
	"github.com/thameem/drop/internal/discovery"
	"github.com/thameem/drop/internal/security"
	"github.com/thameem/drop/internal/transfer"
	"github.com/thameem/drop/internal/transport"
)

// Version is overridden at build time via -ldflags "-X .../internal/cli.Version=...".
var Version = "0.1.0-dev"

// app bundles the dependencies commands need, built once per invocation.
type app struct {
	cfgDir    string
	cfg       config.Config
	identity  *device.Identity
	pins      *security.PINStore
	limiter   *security.Limiter
	trust     *security.TrustStore // receiver side: devices that may skip the PIN
	trustedBy *security.TrustedBy  // sender side: receivers believed to trust us
	active    *active.Store        // active-sharing settings
	names     *active.Names        // private device nicknames
	tr        transport.Transport
	disc      interface {
		discovery.Advertiser
		discovery.Browser
	}
	verbose bool
	neigh   map[string]string // lazily read neighbor table: IPv4 to MAC
}

func loadApp(verbose bool) (*app, error) {
	dir, err := config.Dir()
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(dir)
	if err != nil {
		return nil, err
	}
	name := cfg.Device.Name
	if name == "" {
		name = hostName()
	}
	id, err := device.LoadOrCreate(dir, name, runtime.GOOS)
	if err != nil {
		return nil, err
	}
	sc := cfg.Security
	lim, err := security.OpenLimiter(dir, security.LimiterConfig{
		MaxAttempts: sc.MaxAttempts,
		BaseLock:    time.Duration(sc.LockoutSeconds) * time.Second,
		MaxLock:     time.Duration(sc.LockoutMaxSeconds) * time.Second,
	})
	if err != nil {
		return nil, err
	}
	trust, err := security.OpenTrustStore(dir, time.Duration(sc.TrustExpiryDays)*24*time.Hour)
	if err != nil {
		return nil, err
	}
	return &app{trust: trust, trustedBy: security.OpenTrustedBy(dir), active: active.OpenStore(dir), names: active.OpenNames(dir), cfgDir: dir, cfg: cfg, identity: id, pins: security.OpenPINStore(dir), limiter: lim, tr: transport.TCP{}, disc: discovery.MDNS{}, verbose: verbose}, nil
}

func (a *app) self() transfer.Self {
	return transfer.Self{ID: a.identity.ID, Name: a.identity.Name, OS: a.identity.OS}
}

func (a *app) debugf(format string, args ...any) {
	if a.verbose {
		fmt.Fprintf(os.Stderr, "[drop] "+format+"\n", args...)
	}
}

func hostName() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "drop-device"
	}
	return strings.TrimSuffix(h, ".local")
}

func isTTY(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

func (a *app) policy() security.Policy {
	return security.Policy{TextRequiresPIN: a.cfg.Security.TextRequiresPIN}
}
