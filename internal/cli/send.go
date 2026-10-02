package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/thameem/drop/internal/discovery"
	"github.com/thameem/drop/internal/filesystem"
	"github.com/thameem/drop/internal/project"
	"github.com/thameem/drop/internal/security"
	"github.com/thameem/drop/internal/transfer"
	"github.com/thameem/drop/internal/transport"
)

type sendOptions struct {
	to      string
	timeout time.Duration
	text    bool

	// Directory transfers.
	dryRun         bool
	explain        bool
	includeSecrets bool
	all            bool
}

func addSendFlags(cmd *cobra.Command, o *sendOptions) {
	cmd.Flags().StringVar(&o.to, "to", "", "target device name, ID, or host:port (skips the menu)")
	cmd.Flags().DurationVar(&o.timeout, "timeout", 3*time.Second, "how long to search for devices")
	cmd.Flags().BoolVar(&o.text, "text", false, "send plain text read from stdin (no PIN by default)")
	cmd.Flags().BoolVar(&o.dryRun, "dry-run", false, "folders: show what would be sent and excluded, then stop")
	cmd.Flags().BoolVar(&o.explain, "explain", false, "folders: list every excluded item and why")
	cmd.Flags().BoolVar(&o.includeSecrets, "include-secrets", false, "folders: also send files that look like secrets (.env, keys, tokens)")
	cmd.Flags().BoolVar(&o.all, "all", false, "folders: no project rules (send node_modules, .git, ignored files...); secrets stay excluded unless --include-secrets")
}

func newSendCmd(verbose *bool) *cobra.Command {
	var o sendOptions
	cmd := &cobra.Command{
		Use:     "send <path>",
		Short:   "Send a file or folder (or --text from stdin) to a nearby device",
		Example: "  drop send main.py\n  drop send src/\n  drop send --to windows main.py\n  echo hello | drop send --text",
		Args:    cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSend(cmd, *verbose, o, args)
		},
	}
	addSendFlags(cmd, &o)
	return cmd
}

// maxPINPrompts bounds interactive re-prompts; the receiver enforces the real limit.
const maxPINPrompts = 10

func runSend(cmd *cobra.Command, verbose bool, o sendOptions, args []string) error {
	var (
		ttype security.TransferType
		path  string
		text  []byte
		what  string
		scan  *filesystem.ScanResult
		err   error
	)
	if o.text {
		if len(args) != 0 {
			return usageErr("--text reads from stdin; do not pass a path")
		}
		if text, err = readStdinText(); err != nil {
			return err
		}
		ttype, what = security.TransferText, "text"
	} else {
		if len(args) != 1 {
			return usageErr("expected exactly one file path, got %d", len(args))
		}
		path = args[0]
		st, err := os.Stat(path)
		if err != nil {
			return usageErr("cannot read %s: %v", path, err)
		}
		ttype, what = security.TransferFile, path
		if st.IsDir() {
			if scan, err = scanFolder(path, o); err != nil {
				return err
			}
			ttype, what = security.TransferFolder, scan.Name+"/"
			if scan.Files+scan.Dirs == 0 && len(scan.Excluded) > 0 && !o.dryRun {
				return usageErr("nothing to send: every file in %s was excluded (see above); use --all or --include-secrets to override", path)
			}
			if o.dryRun {
				fmt.Fprintln(os.Stderr, "\nDry run: nothing was sent.")
				return nil
			}
		} else if why, ok := project.SensitiveName(filepath.Base(path)); ok && !o.includeSecrets {
			// An explicitly named file is the user's call, but say so.
			fmt.Fprintf(os.Stderr, "Note: %s looks like a sensitive file (%s). Sending it because you named it.\n", filepath.Base(path), why)
		}
	}

	ctx := cmd.Context()
	a, err := loadApp(verbose)
	if err != nil {
		return err
	}
	return a.deliver(ctx, o, job{ttype: ttype, path: path, text: text, scan: scan, what: what})
}

// job is one thing to send: exactly one of path (file), text, or scan (folder)
// is meaningful for the given transfer type.
type job struct {
	ttype security.TransferType
	path  string
	text  []byte
	scan  *filesystem.ScanResult
	what  string // shown to the user
}

// deliver picks the target, obtains the PIN and runs the send, re-prompting
// after a wrong PIN while the receiver still allows attempts.
func (a *app) deliver(ctx context.Context, o sendOptions, j job) error {
	ttype, path, text, scan, what := j.ttype, j.path, j.text, j.scan, j.what
	pol := a.policy()
	needPIN := pol.RequiresAuthorization(ttype)

	tgt, err := a.resolveTarget(ctx, o)
	if err != nil {
		return err
	}

	// A receiver that trusts this device needs no PIN: try without one. If the
	// belief is stale the transfer layer says so and we fall back to the PIN.
	trustedHint := tgt.id != "" && a.trustedBy.Has(tgt.id)
	pin, fromEnv := "", false
	if needPIN && !trustedHint {
		if pin, fromEnv, err = a.obtainPIN(tgt.label); err != nil {
			return err
		}
	}

	for prompt := 0; ; prompt++ {
		res, err := a.sendOnce(ctx, tgt, ttype, path, text, scan, what, pin, pol)
		if err == nil {
			a.recordTrust(tgt, res)
			return nil
		}
		if errors.Is(err, transfer.ErrPINRequired) && pin == "" {
			if tgt.id != "" {
				_ = a.trustedBy.Forget(tgt.id)
			}
			fmt.Fprintf(os.Stderr, "%s no longer trusts this device; its Drop PIN is needed.\n", tgt.label)
			if pin, fromEnv, err = a.obtainPIN(tgt.label); err != nil {
				return err
			}
			continue
		}
		var ae *security.AuthError
		if errors.As(err, &ae) && errors.Is(err, security.ErrWrongPIN) {
			fmt.Fprintln(os.Stderr, "✗ Incorrect Drop PIN")
			if ae.AttemptsRemaining > 0 && !fromEnv && prompt < maxPINPrompts {
				fmt.Fprintf(os.Stderr, "\nAttempts remaining: %d\n\n", ae.AttemptsRemaining)
				if pin, _, err = a.obtainPIN(tgt.label); err != nil {
					return err
				}
				continue
			}
			if ae.RetryAfter > 0 {
				return withCode(ExitAuth, fmt.Errorf("%s is now temporarily locked. Try again in %s", tgt.label, humanDuration(ae.RetryAfter)))
			}
			return withCode(ExitAuth, errors.New("authentication failed"))
		}
		if errors.As(err, &ae) && errors.Is(err, security.ErrLocked) {
			return withCode(ExitAuth, fmt.Errorf("%s is temporarily locked after too many incorrect PINs. Try again in %s", tgt.label, humanDuration(ae.RetryAfter)))
		}
		return err
	}
}

// sendOnce makes one complete attempt: connect, secure, authorize, transfer.
func (a *app) sendOnce(ctx context.Context, tgt target, ttype security.TransferType, path string, text []byte, scan *filesystem.ScanResult, what, pin string, pol security.Policy) (*transfer.SendResult, error) {
	a.debugf("connecting to %s (%v) via %s", tgt.label, tgt.addrs, a.tr.Name())
	raw, err := a.dialAny(ctx, tgt.addrs)
	if err != nil {
		return nil, withCode(ExitUnavailable, fmt.Errorf("could not reach %s: %w\n\n"+
			"Possible causes:\n  • the device is offline or not running `drop receive`\n"+
			"  • a firewall is blocking the connection\n  • network isolation is enabled", tgt.label, err))
	}
	defer raw.Close()

	check := security.Any()
	if tgt.id != "" {
		check = security.ExpectID(tgt.id)
	}
	conn, err := security.Client(raw, a.identity, check)
	if err != nil {
		if errors.Is(err, security.ErrPeerMismatch) {
			return nil, withCode(ExitAuth, fmt.Errorf("the device that answered is not the %s you selected; refusing to continue", tgt.label))
		}
		return nil, withCode(ExitUnavailable, fmt.Errorf("could not establish a secure connection to %s: %w", tgt.label, err))
	}
	defer conn.Close()
	a.debugf("[transfer] secure channel established")

	interactive := isTTY(os.Stderr)
	if pol.RequiresAuthorization(ttype) && pin != "" && interactive {
		fmt.Fprint(os.Stderr, "Authenticating…\r")
	}
	pb := newProgress(os.Stderr, interactive, "")
	opts := transfer.SendOptions{
		Progress: pb.Update, PIN: pin, Policy: pol, Logf: a.debugf,
		OnFile: func(i, n int, p string) { pb.SetLabel(fmt.Sprintf("[%d/%d] %s", i, n, shorten(p, 32))) },
		OnAuthenticated: func() {
			if interactive {
				fmt.Fprint(os.Stderr, "\033[K")
			}
			fmt.Fprintln(os.Stderr, "✓ Authenticated")
		},
	}
	if interactive {
		fmt.Fprint(os.Stderr, "\033[K")
	}
	fmt.Fprintf(os.Stderr, "Sending %s → %s\n", what, tgt.label)
	var res *transfer.SendResult
	// Dispatch on what is being sent, not on its policy classification: a
	// "changed files" send is a folder transfer that is classified as git.
	switch {
	case scan != nil:
		res, err = transfer.SendFolder(ctx, conn, a.self(), scan, opts)
	case ttype == security.TransferText:
		res, err = transfer.SendText(ctx, conn, a.self(), text, opts)
	default:
		res, err = transfer.SendFile(ctx, conn, a.self(), path, opts)
	}
	pb.Finish()
	if err != nil {
		var ae *security.AuthError
		if errors.As(err, &ae) || errors.Is(err, transfer.ErrPINRequired) {
			return nil, err
		}
		if errors.Is(err, transfer.ErrUnauthorized) || errors.Is(err, security.ErrInvalidPIN) {
			return nil, withCode(ExitAuth, err)
		}
		return nil, fmt.Errorf("failed to send %s: %w", what, err)
	}
	if res.UsedTrust {
		fmt.Fprintln(os.Stderr, "✓ Trusted device (no PIN needed)")
	}
	switch {
	case ttype == security.TransferText:
		fmt.Println("✓ Sent")
	case scan != nil:
		fmt.Printf("%s, %s transferred\nSHA-256 verified ✓ (every file and the whole tree)\nTransfer complete\n", plural(res.Files, "file", "files"), humanBytes(res.Size))
	default:
		fmt.Printf("%s transferred\nSHA-256 verified ✓\nTransfer complete\n", humanBytes(res.Size))
	}
	a.debugf("[verify] sha256 verified")
	return res, nil
}

// recordTrust remembers that a receiver trusts this device (so the next send
// skips the PIN prompt), and tells the user when trust was just granted.
func (a *app) recordTrust(tgt target, res *transfer.SendResult) {
	if res == nil || (!res.TrustGranted && !res.UsedTrust) {
		return
	}
	id := res.Peer.ID
	if err := a.trustedBy.Set(id, tgt.label); err != nil {
		a.debugf("could not remember trusted receiver: %v", err)
	}
	if res.TrustGranted {
		fmt.Fprintf(os.Stderr, "✓ %s now trusts this device: no PIN needed next time.\n", sanitizeLabel(tgt.label))
	}
}

// obtainPIN reads the PIN from $DROP_PIN (automation) or prompts on the
// terminal. The PIN is never logged or echoed.
func (a *app) obtainPIN(label string) (pin string, fromEnv bool, err error) {
	if env := os.Getenv("DROP_PIN"); env != "" {
		if err := security.ValidatePIN(env); err != nil {
			return "", true, usageErr("DROP_PIN is not a valid Drop PIN: %v", err)
		}
		return env, true, nil
	}
	if !hasTTY() {
		return "", false, usageErr("this transfer needs the Drop PIN of %s: run in a terminal, or set DROP_PIN", label)
	}
	fmt.Fprintf(os.Stderr, "\n%s\n\n", label)
	for {
		pin, err = readSecret("Enter Drop PIN:\n> ")
		if err != nil {
			return "", false, err
		}
		if verr := security.ValidatePIN(pin); verr != nil {
			fmt.Fprintf(os.Stderr, "✗ %v\n", verr)
			continue
		}
		return pin, false, nil
	}
}

func readStdinText() ([]byte, error) {
	if isTTY(os.Stdin) {
		fmt.Fprintln(os.Stderr, "Type or paste text, then press Ctrl-D on an empty line to send:")
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, transfer.MaxTextSize+1))
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	if len(data) == 0 {
		return nil, usageErr("no text provided on stdin")
	}
	if len(data) > transfer.MaxTextSize {
		return nil, usageErr("text is larger than %s; send it as a file instead", humanBytes(transfer.MaxTextSize))
	}
	return data, nil
}

type target struct {
	addrs []string // candidate host:port addresses, most promising first
	label string
	id    string // discovered device ID, empty for direct host:port
}

// peerTarget builds a target from a discovered device.
func peerTarget(p discovery.Peer) target {
	addrs := discovery.OrderAddrs(p.Addrs)
	if len(addrs) == 0 {
		addrs = p.Addrs
	}
	return target{addrs: addrs, label: p.Name, id: p.ID}
}

// resolveTarget finds the device to send to, from --to or the interactive menu.
func (a *app) resolveTarget(ctx context.Context, o sendOptions) (target, error) {
	if o.to != "" && isHostPort(o.to) {
		return target{addrs: []string{o.to}, label: o.to}, nil
	}
	if o.to == "" && !(hasTTY() && isTTY(os.Stderr)) {
		return target{}, usageErr("no terminal available for the device menu; pass --to <device>")
	}

	if isTTY(os.Stderr) {
		fmt.Fprint(os.Stderr, "Searching for nearby devices…\r")
	}
	query := o.to
	if query == "localhost" || query == "self" {
		query = a.identity.ID
	}
	// With --to, stop as soon as that exact device shows up instead of waiting
	// out the whole timeout; without it, collect everyone for the menu.
	var stop func([]discovery.Peer) bool
	if query != "" {
		stop = func(ps []discovery.Peer) bool { return len(discovery.Exact(ps, query)) == 1 }
	}
	peers, err := a.disc.BrowseUntil(ctx, o.timeout, stop)
	if err == nil && len(withoutSelfIf(peers, query == "", a.identity.ID)) == 0 && ctx.Err() == nil {
		// mDNS is best-effort UDP: one more, longer look before giving up.
		peers, err = a.disc.BrowseUntil(ctx, 2*o.timeout, stop)
	}
	if isTTY(os.Stderr) {
		fmt.Fprint(os.Stderr, "\033[K")
	}
	if err != nil {
		return target{}, withCode(ExitUnavailable, err)
	}
	cands := peers
	waiting := "`drop receive`"

	if o.to != "" {
		m := discovery.Match(cands, query)
		switch len(m) {
		case 0:
			return target{}, withCode(ExitUnavailable, fmt.Errorf("no nearby device matches %q (found %d); run %s on the other device, or `drop devices` to see what is visible", o.to, len(cands), waiting))
		case 1:
			return peerTarget(m[0]), nil
		}
		names := ""
		for _, p := range m {
			names += "\n  • " + p.Name
		}
		return target{}, usageErr("%q matches several devices:%s\nBe more specific.", o.to, names)
	}

	cands = withoutSelf(cands, a.identity.ID)
	if len(cands) == 0 {
		return target{}, withCode(ExitUnavailable, fmt.Errorf("no nearby devices found\n\n"+
			"On the other device run %s. If it is running, check that both\n"+
			"devices are on the same network and that no firewall blocks mDNS (UDP 5353)", waiting))
	}
	p, err := pickPeer(cands, a.trustedBy.Has)
	if err != nil {
		return target{}, err
	}
	return peerTarget(p), nil
}

// withoutSelfIf drops this device from peers when drop is true.
func withoutSelfIf(peers []discovery.Peer, drop bool, id string) []discovery.Peer {
	if !drop {
		return peers
	}
	return withoutSelf(peers, id)
}

func withoutSelf(peers []discovery.Peer, id string) []discovery.Peer {
	var out []discovery.Peer
	for _, p := range peers {
		if p.ID != id {
			out = append(out, p)
		}
	}
	return out
}

// dialAny tries each candidate address in turn. A device advertises every
// interface it has, and some (Docker, VPN, a second network) are unreachable
// from here, so a failed address must not end the attempt.
func (a *app) dialAny(ctx context.Context, addrs []string) (transport.Conn, error) {
	if len(addrs) == 0 {
		return nil, errors.New("the device advertised no usable network address")
	}
	var last error
	for i, addr := range addrs {
		// Give the last candidate longer; earlier ones fail fast.
		wait := 4 * time.Second
		if i == len(addrs)-1 {
			wait = 10 * time.Second
		}
		dctx, cancel := context.WithTimeout(ctx, wait)
		conn, err := a.tr.Dial(dctx, addr)
		cancel()
		if err == nil {
			a.debugf("connected via %s", addr)
			return conn, nil
		}
		a.debugf("address %s failed: %v", addr, err)
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}
