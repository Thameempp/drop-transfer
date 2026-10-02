package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/thameem/drop/internal/discovery"
	"github.com/thameem/drop/internal/power"
	"github.com/thameem/drop/internal/protocol"
	"github.com/thameem/drop/internal/security"
	"github.com/thameem/drop/internal/transfer"
	"github.com/thameem/drop/internal/transport"
)

const (
	serviceLabel   = "com.thameem.drop.active" // macOS LaunchAgent
	serviceUnit    = "drop-active.service"     // Linux systemd user unit
	serviceTask    = "Drop Active Sharing"     // Windows scheduled task
	maxServiceLog  = 1 << 20
	serviceLogName = "service.log"
)

func newActiveServeCmd(verbose *bool) *cobra.Command {
	var logPath string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the active-sharing receiver in the foreground (what the background service runs)",
		Long: `Listens for transfers like "drop receive" but never asks anything: it accepts
only what active sharing allows (an allowed trusted device on a saved network)
and declines everything else. Normally you do not run this yourself; use
"drop active service install" so it starts at login.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if logPath != "" {
				if f, err := openServiceLog(logPath); err == nil {
					os.Stderr, os.Stdout = f, f
				}
			}
			a, err := loadApp(*verbose)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return a.runActiveService(ctx)
		},
	}
	cmd.Flags().StringVar(&logPath, "log", "", "append output to this file")
	return cmd
}

// openServiceLog opens the log for appending, starting afresh if it grew large.
func openServiceLog(path string) (*os.File, error) {
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if st, err := os.Stat(path); err == nil && st.Size() > maxServiceLog {
		flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	return os.OpenFile(path, flags, 0o600)
}

func (a *app) runActiveService(ctx context.Context) error {
	st, err := a.active.Load()
	if err != nil {
		return err
	}
	if m := activeMissing(st); m != "" {
		return usageErr("active sharing is not set up yet: %s", m)
	}
	l, err := a.tr.Listen(":0")
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
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	} else {
		defer stop()
	}
	fmt.Fprintf(os.Stderr, "Active sharing service ready on port %d.\n%s\n", p, a.activeBanner())

	r := &transfer.Receiver{
		KeepAwake: func() func() { return power.KeepAwake("receiving with drop") },
		Self:      a.self(),
		Dir:       st.Dir,
		Policy:    a.policy(),
		Trust:     a.trust,
		Upgrade: func(c transport.Conn) (transport.Conn, error) {
			return security.Server(c, a.identity, security.Any())
		},
		// No Auth: the service never takes a PIN, so it offers nothing to guess.
		Logf: a.debugf,
		OnError: func(addr string, err error) {
			a.debugf("connection from %s failed: %v", addr, err)
		},
		Approver: transfer.ApproverFunc(func(ctx context.Context, inc transfer.Incoming) transfer.Decision {
			from := a.label(inc.KeyID, inc.From.Name)
			if d, _ := a.activeAccept(ctx, inc); d.Accept {
				fmt.Fprintf(os.Stderr, "✓ accepting %s from %s → %s\n", activeWhat(inc), from, d.Dir)
				return d
			}
			fmt.Fprintf(os.Stderr, "✗ declined %s from %s (not allowed by active sharing)\n", activeWhat(inc), from)
			return transfer.Decision{Reason: "this device only receives from allowed devices on its saved network while nobody is at it; ask its owner to run `drop receive`"}
		}),
		OnResult: func(rec *transfer.Received, inc *transfer.Incoming, err error) {
			if err != nil {
				if inc != nil {
					fmt.Fprintf(os.Stderr, "✗ %s from %s: %v\n", inc.Name, sanitizeLabel(inc.From.Name), err)
				}
				return
			}
			if rec != nil && inc != nil && inc.Type != security.TransferText {
				fmt.Fprintf(os.Stderr, "✓ %s (%s) from %s verified, saved to %s\n", inc.Name, humanBytes(inc.Size), sanitizeLabel(inc.From.Name), rec.Path)
			}
		},
	}
	if err := r.Serve(ctx, l); err != nil && ctx.Err() == nil {
		return withCode(ExitGeneral, err)
	}
	return nil
}

// ---- install / control

func newActiveServiceCmd(verbose *bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Receive active-sharing transfers in the background, without running `drop receive`",
		Long: `Installs a small background receiver that starts when you log in. While it runs,
allowed trusted devices on your saved network can send you files with nothing
for you to do. It never prompts and declines everything else.

Set active sharing up first ("drop active setup"), then "drop active service install".
The computer must be awake and logged in; a sleeping or logged-out computer
cannot receive.`,
	}
	cmd.AddCommand(
		&cobra.Command{Use: "install", Short: "Start the receiver at every login (and start it now)", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				a, err := loadApp(*verbose)
				if err != nil {
					return err
				}
				st, err := a.active.Load()
				if err != nil {
					return err
				}
				if m := activeMissing(st); m != "" || !st.Enabled {
					if m == "" {
						m = "turn it on (drop active on)"
					}
					return usageErr("set active sharing up first: %s", m)
				}
				exe, err := os.Executable()
				if err != nil {
					return err
				}
				if r, err := filepath.EvalSymlinks(exe); err == nil {
					exe = r
				}
				if err := installService(exe, filepath.Join(a.cfgDir, serviceLogName)); err != nil {
					return withCode(ExitGeneral, err)
				}
				fmt.Printf("✓ Background receiver installed and started. It now runs at every login.\n  Log: %s\n", filepath.Join(a.cfgDir, serviceLogName))
				fmt.Println("  If you move or reinstall `drop`, run this command again.")
				return nil
			}},
		&cobra.Command{Use: "uninstall", Short: "Stop it and remove it from login", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				if err := uninstallService(); err != nil {
					return withCode(ExitGeneral, err)
				}
				fmt.Println("✓ Background receiver removed.")
				return nil
			}},
		&cobra.Command{Use: "start", Short: "Start it now", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error { return serviceControl("start") }},
		&cobra.Command{Use: "stop", Short: "Stop it until the next login (or start)", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error { return serviceControl("stop") }},
		&cobra.Command{Use: "status", Short: "Show whether it is installed and running", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				installed, running := serviceState()
				switch {
				case !installed:
					fmt.Println("Background receiver: not installed (drop active service install)")
				case running:
					fmt.Println("Background receiver: installed and running")
				default:
					fmt.Println("Background receiver: installed, not running (drop active service start)")
				}
				return nil
			}},
	)
	return cmd
}

func serviceControl(what string) error {
	if installed, _ := serviceState(); !installed {
		return usageErr("the background receiver is not installed (drop active service install)")
	}
	if err := controlService(what); err != nil {
		return withCode(ExitGeneral, err)
	}
	fmt.Printf("✓ Background receiver %s.\n", map[string]string{"start": "started", "stop": "stopped"}[what])
	return nil
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func homeDir() string { h, _ := os.UserHomeDir(); return h }

func launchAgentPath() string {
	return filepath.Join(homeDir(), "Library", "LaunchAgents", serviceLabel+".plist")
}
func systemdUnitPath() string {
	return filepath.Join(homeDir(), ".config", "systemd", "user", serviceUnit)
}

func domain() string { return "gui/" + strconv.Itoa(os.Getuid()) }

func installService(exe, logPath string) error {
	env := ""
	if h := os.Getenv("DROP_HOME"); h != "" {
		env = h
	}
	switch runtime.GOOS {
	case "darwin":
		path := launchAgentPath()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(launchdPlist(exe, logPath, env)), 0o644); err != nil {
			return err
		}
		run("launchctl", "bootout", domain()+"/"+serviceLabel) // replace an older copy; fine if absent
		_, err := run("launchctl", "bootstrap", domain(), path)
		return err
	case "linux":
		path := systemdUnitPath()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(systemdUnit(exe, logPath, env)), 0o644); err != nil {
			return err
		}
		if _, err := run("systemctl", "--user", "daemon-reload"); err != nil {
			return err
		}
		_, err := run("systemctl", "--user", "enable", "--now", serviceUnit)
		return err
	case "windows":
		if _, err := run("schtasks", "/Create", "/F", "/TN", serviceTask, "/SC", "ONLOGON", "/RL", "LIMITED", "/TR", windowsTaskCommand(exe, logPath)); err != nil {
			return err
		}
		_, err := run("schtasks", "/Run", "/TN", serviceTask)
		return err
	}
	return fmt.Errorf("the background receiver is not supported on %s", runtime.GOOS)
}

func uninstallService() error {
	switch runtime.GOOS {
	case "darwin":
		run("launchctl", "bootout", domain()+"/"+serviceLabel)
		if err := os.Remove(launchAgentPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	case "linux":
		run("systemctl", "--user", "disable", "--now", serviceUnit)
		if err := os.Remove(systemdUnitPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		run("systemctl", "--user", "daemon-reload")
		return nil
	case "windows":
		run("schtasks", "/End", "/TN", serviceTask)
		_, err := run("schtasks", "/Delete", "/F", "/TN", serviceTask)
		return err
	}
	return fmt.Errorf("the background receiver is not supported on %s", runtime.GOOS)
}

func controlService(what string) error {
	var err error
	switch runtime.GOOS {
	case "darwin":
		if what == "stop" {
			_, err = run("launchctl", "bootout", domain()+"/"+serviceLabel)
		} else {
			_, err = run("launchctl", "bootstrap", domain(), launchAgentPath())
		}
	case "linux":
		_, err = run("systemctl", "--user", what, serviceUnit)
	case "windows":
		if what == "stop" {
			_, err = run("schtasks", "/End", "/TN", serviceTask)
		} else {
			_, err = run("schtasks", "/Run", "/TN", serviceTask)
		}
	default:
		err = fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	return err
}

// serviceState reports whether the background receiver is installed and running.
func serviceState() (installed, running bool) {
	switch runtime.GOOS {
	case "darwin":
		if _, err := os.Stat(launchAgentPath()); err != nil {
			return false, false
		}
		_, err := run("launchctl", "print", domain()+"/"+serviceLabel)
		return true, err == nil
	case "linux":
		if _, err := os.Stat(systemdUnitPath()); err != nil {
			return false, false
		}
		out, _ := run("systemctl", "--user", "is-active", serviceUnit)
		return true, strings.TrimSpace(out) == "active"
	case "windows":
		out, err := run("schtasks", "/Query", "/TN", serviceTask, "/FO", "LIST")
		return err == nil, err == nil && strings.Contains(out, "Running")
	}
	return false, false
}

// ---- service definitions (pure, so they can be tested)

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

func launchdPlist(exe, logPath, dropHome string) string {
	envBlock := ""
	if dropHome != "" {
		envBlock = "\n\t<key>EnvironmentVariables</key>\n\t<dict><key>DROP_HOME</key><string>" + xmlEscape(dropHome) + "</string></dict>"
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>` + serviceLabel + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + xmlEscape(exe) + `</string>
		<string>active</string>
		<string>serve</string>
		<string>--log</string>
		<string>` + xmlEscape(logPath) + `</string>
	</array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>ProcessType</key><string>Background</string>` + envBlock + `
</dict>
</plist>
`
}

func systemdQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`).Replace(s) + `"`
}

func systemdUnit(exe, logPath, dropHome string) string {
	env := ""
	if dropHome != "" {
		env = "Environment=" + systemdQuote("DROP_HOME="+dropHome) + "\n"
	}
	return "[Unit]\nDescription=Drop active sharing receiver\nAfter=network-online.target\n\n[Service]\nExecStart=" +
		systemdQuote(exe) + " active serve --log " + systemdQuote(logPath) + "\n" + env +
		"Restart=on-failure\nRestartSec=10\n\n[Install]\nWantedBy=default.target\n"
}

func windowsTaskCommand(exe, logPath string) string {
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	return `powershell.exe -NoProfile -WindowStyle Hidden -Command "& ` + q(exe) + ` active serve --log ` + q(logPath) + `"`
}
