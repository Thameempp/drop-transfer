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

	"github.com/thameem/drop/internal/config"
	"github.com/thameem/drop/internal/discovery"
	"github.com/thameem/drop/internal/power"
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
	cmd.Flags().StringVar(&dir, "dir", "", "destination directory (default: current directory)")
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

	fmt.Fprintf(os.Stderr, "%s is ready to receive on port %d → %s\n", a.identity.Name, p, dir)
	if _, running := serviceState(); running {
		fmt.Fprintln(os.Stderr, "Note: the background active-sharing receiver is running too. If a sender reaches it instead of this window, the transfer is declined. Pause it with `drop active service stop`.")
	}
	if b := a.activeBanner(); b != "" {
		fmt.Fprintln(os.Stderr, b)
	}
	fmt.Fprintln(os.Stderr, "Ctrl+C to stop.")

	in := bufio.NewReader(os.Stdin)
	var pbMu sync.Mutex
	var pb *progressBar
	r := &transfer.Receiver{
		KeepAwake: func() func() { return power.KeepAwake("receiving with drop") },
		Self:      a.self(),
		Dir:       dir,
		Policy:    a.policy(),
		Trust:     a.trust,
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
			if d, why := a.activeAccept(ctx, inc); d.Accept {
				fmt.Fprintf(os.Stderr, "✓ Active sharing: accepting %s from %s → %s\n", activeWhat(inc), a.label(inc.KeyID, inc.From.Name), d.Dir)
				return d
			} else if why != "" {
				fmt.Fprintf(os.Stderr, "Active sharing is not applied (%s); asking instead.\n", why)
			}
			return approve(in, dir, yes, inc, a.labelAt(ctx, inc.KeyID, inc.From.Name, hostPart(inc.Addr)))
		}),
		OnProgress: func(inc transfer.Incoming, done, total int64) {
			pbMu.Lock()
			if pb == nil {
				pb = newProgress(os.Stderr, isTTY(os.Stderr), "Receiving")
				if inc.Type != security.TransferFolder {
					pb.SetFile("Receiving", "", sanitizeLabel(inc.Name))
				}
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
			p.SetFile("Receiving", fmt.Sprintf("[%d/%d]", i, n), sanitizeLabel(path))
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
func approve(in *bufio.Reader, dir string, yes bool, inc transfer.Incoming, from string) transfer.Decision {
	origDir := dir
	// Text is shown live, with no prompt: it is never written to disk, and on a
	// terminal control characters are stripped before it is printed.
	if yes || inc.Type == security.TransferText {
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
	case security.TransferFolder:
		what = fmt.Sprintf("Folder: %s (%s in %s)", inc.Name, plural(inc.Files, "file", "files"), plural(inc.Dirs, "subfolder", "subfolders"))
	}
	// [d] changes the destination for this transfer only.
	chosen := dir
	for {
		fmt.Fprintf(os.Stderr, "\nIncoming transfer\n\n  From: %s (%s)\n  %s\n", from, inc.Addr, what)
		fmt.Fprintf(os.Stderr, "  Save to: %s\n", chosen)
		fmt.Fprintf(os.Stderr, "  Size: %s\n  Authentication: %s\n\n", humanBytes(inc.Size), authLine)
		fmt.Fprint(os.Stderr, "Accept? [Y/n], or d to choose another folder: ")
		ans := strings.ToLower(readLine(in))
		if ans == "d" || ans == "dir" {
			chosen = askDir(in, chosen)
			continue
		}
		if ans != "" && !strings.HasPrefix(ans, "y") {
			return transfer.Decision{Reason: "declined by user"}
		}
		break
	}
	dir = chosen
	d := transfer.Decision{Accept: true, Conflict: transfer.ConflictRename}
	if dir != origDir {
		d.Dir = dir
	}
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
		fmt.Fprintln(os.Stderr, "\nSenders need your Drop PIN. Forgot it? Run `drop security show-pin` (or `drop receive --new-pin`).")
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
	printPINBox("Your Drop PIN", pin, "Senders need this PIN to send files to this device.\nShow it again with `drop security show-pin`; change it with `set-pin`.")
	return nil
}

func printPINBox(title, pin, note string) {
	line := strings.Repeat("─", len(pin)+4)
	fmt.Fprintf(os.Stderr, "\n%s\n\n┌%s┐\n│  %s  │\n└%s┘\n\n%s\n\n", title, line, pin, line, note)
}

// askDir asks for a destination folder and returns it, or current if the
// answer is empty or unusable.
func askDir(in *bufio.Reader, current string) string {
	fmt.Fprintf(os.Stderr, "Save to folder (Enter to keep %s): ", current)
	ans := readLine(in)
	if strings.TrimSpace(ans) == "" {
		return current
	}
	p, err := config.ExpandDir(ans)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		return current
	}
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		fmt.Fprintf(os.Stderr, "✗ %s is not a folder\n", p)
		return current
	}
	return p
}

func newReceiveDirCmd(verbose *bool) *cobra.Command {
	var reset bool
	cmd := &cobra.Command{
		Use:   "receive-dir [folder]",
		Short: "Show or set the default folder for received files",
		Long: `Without arguments, shows where received files are saved.
With a folder, makes it the default for every "drop receive". Use --reset to
go back to saving in the folder where "drop receive" is run.
While accepting a transfer you can still choose another folder with "d".`,
		Example: "  drop receive-dir ~/inbox\n  drop receive-dir --reset",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := loadApp(*verbose)
			if err != nil {
				return err
			}
			switch {
			case reset && len(args) > 0:
				return usageErr("use either a folder or --reset")
			case reset:
				a.cfg.Transfer.ReceiveDir = ""
			case len(args) == 1:
				p, err := config.ExpandDir(args[0])
				if err != nil {
					return usageErr("%v", err)
				}
				if st, err := os.Stat(p); err == nil && !st.IsDir() {
					return usageErr("%s is not a folder", p)
				}
				if err := os.MkdirAll(p, 0o755); err != nil {
					return withCode(ExitGeneral, err)
				}
				a.cfg.Transfer.ReceiveDir = p
			default:
				if d := a.cfg.Transfer.ReceiveDir; d != "" {
					fmt.Printf("Received files are saved to %s\n(change: drop receive-dir <folder>, reset: drop receive-dir --reset)\n", d)
				} else {
					fmt.Println("No default folder set: received files are saved to the folder where `drop receive` is run.\n(set one: drop receive-dir <folder>)")
				}
				return nil
			}
			if err := config.Save(a.cfgDir, a.cfg); err != nil {
				return withCode(ExitGeneral, err)
			}
			if reset {
				fmt.Println("✓ Default folder cleared. Received files go to the folder where `drop receive` is run.")
			} else {
				fmt.Printf("✓ Received files will be saved to %s\n", a.cfg.Transfer.ReceiveDir)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&reset, "reset", false, "clear the default folder")
	return cmd
}

func activeWhat(inc transfer.Incoming) string {
	if inc.Type == security.TransferFolder {
		return "folder " + sanitizeLabel(inc.Name)
	}
	return sanitizeLabel(inc.Name)
}

func hostPart(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return h
}
