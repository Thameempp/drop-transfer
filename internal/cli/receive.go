package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/thameem/drop/internal/discovery"
	"github.com/thameem/drop/internal/protocol"
	"github.com/thameem/drop/internal/security"
	"github.com/thameem/drop/internal/transfer"
	"github.com/thameem/drop/internal/transport"
)

func newReceiveCmd(verbose *bool) *cobra.Command {
	var (
		dir    string
		port   int
		yes    bool
		once   bool
		newPIN bool
	)
	cmd := &cobra.Command{
		Use:     "receive",
		Short:   "Wait for incoming files",
		Example: "  drop receive\n  drop receive --dir ~/inbox --once",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := loadApp(*verbose)
			if err != nil {
				return err
			}
			if dir == "" {
				if dir, err = a.cfg.ResolveReceiveDir(); err != nil {
					return err
				}
			}
			if !yes && !isTTY(os.Stdin) {
				return usageErr("no terminal to ask for confirmation; pass --yes to accept transfers automatically")
			}
			return a.runReceive(cmd.Context(), dir, port, yes, once, newPIN)
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "destination directory (default ~/Downloads)")
	cmd.Flags().IntVar(&port, "port", 0, "TCP port to listen on (default: random free port)")
	cmd.Flags().BoolVar(&yes, "yes", false, "accept incoming transfers without asking")
	cmd.Flags().BoolVar(&newPIN, "new-pin", false, "generate and show a new Drop PIN (the old one stops working)")
	cmd.Flags().BoolVar(&once, "once", false, "exit after one transfer")
	return cmd
}

func (a *app) runReceive(ctx context.Context, dir string, port int, yes, once, newPIN bool) error {
	if err := a.ensurePIN(newPIN); err != nil {
		return err
	}
	l, err := a.tr.Listen(net.JoinHostPort("", strconv.Itoa(port)))
	if err != nil {
		return withCode(ExitGeneral, err)
	}
	defer l.Close()
	_, portStr, _ := net.SplitHostPort(l.Addr())
	p, _ := strconv.Atoi(portStr)

	stop, err := a.disc.Advertise(discovery.Service{
		ID: a.identity.ID, Name: a.identity.Name, OS: a.identity.OS, Port: p, Versions: protocol.SupportedVersions,
	})
	if err != nil {
		// Receiving still works by direct address, so degrade rather than fail.
		fmt.Fprintf(os.Stderr, "warning: %v\n  Other devices will not see this one; they can use --to <host>:%d\n", err, p)
	} else {
		defer stop()
	}

	fmt.Fprintf(os.Stderr, "%s is ready to receive on port %d → %s\nCtrl+C to stop.\n", a.identity.Name, p, dir)

	in := bufio.NewReader(os.Stdin)
	var pbMu sync.Mutex
	var pb *progressBar
	r := &transfer.Receiver{
		Self:   a.self(),
		Dir:    dir,
		Policy: a.policy(),
		Trust:  a.trust,
		// No plaintext mode: every connection is upgraded to TLS 1.3 first.
		Upgrade: func(c transport.Conn) (transport.Conn, error) {
			return security.Server(c, a.identity, security.Any())
		},
		Auth: &security.Authenticator{SelfID: a.identity.ID, PINs: a.pins, Limiter: a.limiter, Logf: a.debugf},
		Logf: a.debugf,
		OnError: func(addr string, err error) {
			a.debugf("connection from %s failed: %v", addr, err)
			var ae *security.AuthError
			if errors.As(err, &ae) {
				fmt.Fprintf(os.Stderr, "✗ failed Drop PIN attempt from %s\n", addr)
			}
		},
		Approver: transfer.ApproverFunc(func(ctx context.Context, inc transfer.Incoming) transfer.Decision {
			return approve(in, dir, yes, inc)
		}),
		OnProgress: func(inc transfer.Incoming, done, total int64) {
			pbMu.Lock()
			if pb == nil {
				pb = newProgress(os.Stderr, isTTY(os.Stderr), "Receiving "+inc.Name)
			}
			p := pb
			pbMu.Unlock()
			p.Update(done, total)
		},
		OnFile: func(inc transfer.Incoming, i, n int, path string) {
			pbMu.Lock()
			if pb == nil {
				pb = newProgress(os.Stderr, isTTY(os.Stderr), "")
			}
			p := pb
			pbMu.Unlock()
			p.SetLabel(fmt.Sprintf("Receiving [%d/%d] %s", i, n, shorten(sanitizeLabel(path), 32)))
		},
		OnText: func(inc transfer.Incoming, data []byte) {
			text := string(data)
			if isTTY(os.Stdout) {
				text = sanitizeText(text)
			}
			fmt.Fprintf(os.Stderr, "✓ text from %s (%s) — SHA-256 verified\n", sanitizeLabel(inc.From.Name), humanBytes(inc.Size))
			fmt.Print(text)
			if !strings.HasSuffix(text, "\n") {
				fmt.Println()
			}
		},
		OnResult: func(rec *transfer.Received, inc *transfer.Incoming, err error) {
			pbMu.Lock()
			if pb != nil {
				pb.Finish()
				pb = nil
			}
			pbMu.Unlock()
			if err != nil {
				var ae *security.AuthError
				if errors.As(err, &ae) {
					fmt.Fprintf(os.Stderr, "✗ %s failed Drop PIN authentication\n", sanitizeLabel(inc.From.Name))
					return
				}
				fmt.Fprintf(os.Stderr, "✗ %s from %s: %v\n", inc.Name, sanitizeLabel(inc.From.Name), err)
				return
			}
			if rec != nil && rec.TrustGranted {
				fmt.Fprintf(os.Stderr, "✓ %s is now a trusted device\n", sanitizeLabel(inc.From.Name))
			}
			if inc.Type == security.TransferText {
				return
			}
			if inc.Type == security.TransferFolder {
				fmt.Printf("✓ %s/ (%s, %s) from %s — every file and the whole tree SHA-256 verified\n  saved to %s\n",
					inc.Name, plural(inc.Files, "file", "files"), humanBytes(inc.Size), sanitizeLabel(inc.From.Name), rec.Path)
				return
			}
			fmt.Printf("✓ %s (%s) from %s — SHA-256 verified\n  saved to %s\n", inc.Name, humanBytes(inc.Size), sanitizeLabel(inc.From.Name), rec.Path)
		},
	}

	if once {
		_, err := r.HandleOne(ctx, l)
		if err != nil && ctx.Err() == nil {
			return withCode(codeFor(err), err)
		}
		return ctx.Err()
	}
	return r.Serve(ctx, l)
}

// approve asks the user (or auto-accepts with --yes). Authorization (the PIN)
// has already happened by the time this is called; this is the consent step.
// Existing files are never replaced without an explicit choice.
func approve(in *bufio.Reader, dir string, yes bool, inc transfer.Incoming) transfer.Decision {
	if yes {
		return transfer.Decision{Accept: true, Conflict: transfer.ConflictRename}
	}
	authLine := "✓ Authorized (Drop PIN)"
	switch {
	case !inc.Authorized:
		authLine = "not required (plain text)"
	case inc.AuthMethod == "trusted":
		authLine = "✓ Trusted device"
	}
	what := "File: " + inc.Name
	switch inc.Type {
	case security.TransferText:
		what = "Text"
	case security.TransferFolder:
		what = fmt.Sprintf("Folder: %s (%s in %s)\n  Destination: %s", inc.Name, plural(inc.Files, "file", "files"), plural(inc.Dirs, "subfolder", "subfolders"), filepath.Join(dir, inc.Name))
	}
	fmt.Fprintf(os.Stderr, "\nIncoming transfer\n\n  From: %s (%s)\n  %s\n  Size: %s\n  Authentication: %s\n\nAccept? [Y/n] ",
		sanitizeLabel(inc.From.Name), inc.Addr, what, humanBytes(inc.Size), authLine)
	if ans := readLine(in); ans != "" && !strings.HasPrefix(strings.ToLower(ans), "y") {
		return transfer.Decision{Reason: "declined by user"}
	}
	d := transfer.Decision{Accept: true, Conflict: transfer.ConflictRename}
	// Offer trust only to a sender that just proved the PIN, never with --yes
	// (which must not silently widen who can send here).
	if inc.AuthMethod == "pin" {
		fp := inc.Fingerprint
		if len(fp) > 23 {
			fp = fp[:23] + "…"
		}
		fmt.Fprintf(os.Stderr, "Trust %s for future transfers? It will no longer need the PIN.\n  (device key %s; revoke any time with `drop security untrust`) [y/N] ", sanitizeLabel(inc.From.Name), fp)
		if strings.HasPrefix(strings.ToLower(readLine(in)), "y") {
			d.Trust = true
		}
	}
	if inc.Type == security.TransferFolder {
		// Existing folders are never merged or replaced: the new one is saved beside it.
		if _, err := os.Lstat(filepath.Join(dir, inc.Name)); err == nil {
			fmt.Fprintf(os.Stderr, "%s already exists. It will not be modified.\n  [r] Save as a new folder (default)  [s] Skip: ", inc.Name)
			switch strings.ToLower(readLine(in)) {
			case "s", "skip":
				return transfer.Decision{Reason: "skipped by user (folder exists)"}
			}
		}
	}
	if inc.Type == security.TransferFile {
		if _, err := os.Lstat(filepath.Join(dir, inc.Name)); err == nil {
			fmt.Fprintf(os.Stderr, "%s already exists.\n  [r] Rename (default)  [p] Replace  [s] Skip: ", inc.Name)
			switch strings.ToLower(readLine(in)) {
			case "p", "replace":
				d.Conflict = transfer.ConflictReplace
			case "s", "skip":
				return transfer.Decision{Reason: "skipped by user (file exists)"}
			}
		}
	}
	return d
}

func readLine(r *bufio.Reader) string {
	s, _ := r.ReadString('\n')
	return strings.TrimSpace(s)
}

// ensurePIN creates a PIN on first use so receiving works with zero setup. The
// PIN is shown once; only an Argon2id verifier is stored.
func (a *app) ensurePIN(renew bool) error {
	_, err := a.pins.Load()
	if err == nil && !renew {
		// Only a hash is stored, so the PIN cannot be shown again.
		fmt.Fprintln(os.Stderr, "\nSenders need your Drop PIN (shown when it was created; it cannot be shown again).\nForgot it? Run `drop receive --new-pin`.")
		return nil
	}
	if err != nil && !errors.Is(err, security.ErrNoPIN) {
		return err
	}
	pin, err := security.GeneratePIN(a.cfg.Security.PINLength)
	if err != nil {
		return err
	}
	if err := a.pins.Set(pin); err != nil {
		return err
	}
	if err := a.limiter.Reset(); err != nil {
		return err
	}
	printPINBox("Your Drop PIN", pin, "Senders need this PIN to send files to this device.\nIt is shown only once. Change it with `drop security set-pin`.")
	return nil
}

func printPINBox(title, pin, note string) {
	line := strings.Repeat("─", len(pin)+4)
	fmt.Fprintf(os.Stderr, "\n%s\n\n┌%s┐\n│  %s  │\n└%s┘\n\n%s\n\n", title, line, pin, line, note)
}
