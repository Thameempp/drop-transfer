package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/thameem/drop/internal/security"
)

func newSecurityCmd(verbose *bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "security",
		Short: "Manage the Drop PIN that authorizes transfers to this device",
		Long: `The Drop PIN authorizes senders to send protected content (files, folders,
projects, ...) to this device. It is verified without ever being sent over the
network and is stored only as an Argon2id hash. It is not an encryption key:
connections are encrypted with TLS 1.3 regardless.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { return showSecurity(*verbose) },
	}
	cmd.AddCommand(
		&cobra.Command{Use: "status", Short: "Show PIN and policy status", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error { return showSecurity(*verbose) }},
		&cobra.Command{Use: "set-pin", Short: "Choose a new Drop PIN", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				a, err := loadApp(*verbose)
				if err != nil {
					return err
				}
				if !hasTTY() {
					return usageErr("setting a PIN needs a terminal")
				}
				var pin string
				for {
					if pin, err = readSecret("New Drop PIN (6-12 digits):\n> "); err != nil {
						return err
					}
					if verr := security.ValidatePIN(pin); verr != nil {
						fmt.Fprintf(os.Stderr, "✗ %v\n", verr)
						continue
					}
					again, err := readSecret("Repeat it:\n> ")
					if err != nil {
						return err
					}
					if again != pin {
						fmt.Fprintln(os.Stderr, "✗ The PINs do not match")
						continue
					}
					break
				}
				return a.storePIN(pin, false)
			}},
		&cobra.Command{Use: "trusted", Short: "List trusted devices (they can send without the PIN)", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				a, err := loadApp(*verbose)
				if err != nil {
					return err
				}
				return a.listTrusted()
			}},
		newUntrustCmd(verbose),
		&cobra.Command{Use: "show-pin", Short: "Show the current Drop PIN", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				a, err := loadApp(*verbose)
				if err != nil {
					return err
				}
				pin, err := a.pins.Reveal()
				switch {
				case errors.Is(err, security.ErrNoPIN):
					return usageErr("no Drop PIN yet: run `drop receive` (creates one) or `drop security generate-pin`")
				case errors.Is(err, security.ErrPINNotRecoverable):
					return usageErr("this PIN was set before it could be shown again: run `drop security generate-pin` (or set-pin) to create one you can show")
				case err != nil:
					return err
				}
				printPINBox("Your Drop PIN", pin, "Anyone with this PIN can send files to this device.")
				return nil
			}},
		&cobra.Command{Use: "generate-pin", Short: "Generate a random Drop PIN", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				a, err := loadApp(*verbose)
				if err != nil {
					return err
				}
				pin, err := security.GeneratePIN(a.cfg.Security.PINLength)
				if err != nil {
					return err
				}
				return a.storePIN(pin, true)
			}},
	)
	return cmd
}

func (a *app) storePIN(pin string, show bool) error {
	if err := a.pins.Set(pin); err != nil {
		return err
	}
	// A new PIN starts with a clean slate: old attempt counters and lockouts no longer apply.
	if err := a.limiter.Reset(); err != nil {
		return err
	}
	if show {
		printPINBox("New Drop PIN", pin, "Show it again with `drop security show-pin`. The old PIN no longer works.")
	} else {
		fmt.Println("✓ Drop PIN changed. The old PIN no longer works.")
	}
	if n := len(a.trust.List()); n > 0 {
		fmt.Printf("Note: %s stay trusted: trust is bound to each device's key, not to the PIN.\n"+
			"      If the old PIN was exposed, review them with `drop security trusted`, or revoke all with `drop security untrust --all`.\n",
			plural(n, "trusted device", "trusted devices"))
	}
	return nil
}

func showSecurity(verbose bool) error {
	a, err := loadApp(verbose)
	if err != nil {
		return err
	}
	fmt.Println("Security")
	fmt.Println()
	if _, err := a.pins.Load(); err == nil {
		fmt.Println("  Drop PIN:       configured")
	} else if errors.Is(err, security.ErrNoPIN) {
		fmt.Println("  Drop PIN:       not set (created on first `drop receive`)")
	} else {
		return err
	}
	c := a.cfg.Security
	fmt.Printf("  Plain text:     PIN %s\n", map[bool]string{true: "required", false: "not required"}[c.TextRequiresPIN])
	fmt.Printf("  Everything else: PIN required\n")
	if n := len(a.trust.List()); n > 0 {
		exp := "never expires"
		if c.TrustExpiryDays > 0 {
			exp = fmt.Sprintf("expires after %d days unused", c.TrustExpiryDays)
		}
		fmt.Printf("  Trusted devices: %d (%s)\n", n, exp)
	} else {
		fmt.Println("  Trusted devices: none")
	}
	fmt.Printf("  Lockout:        after %d failed attempts, %ds doubling up to %ds\n", c.MaxAttempts, c.LockoutSeconds, c.LockoutMaxSeconds)
	fmt.Println()
	fmt.Println("  drop security set-pin       choose a PIN")
	fmt.Println("  drop security show-pin      show the current PIN")
	fmt.Println("  drop security generate-pin  generate a random PIN")
	fmt.Println("  drop security trusted       list devices that may send without the PIN")
	fmt.Println("  drop security untrust       revoke a trusted device")
	return nil
}

func newUntrustCmd(verbose *bool) *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "untrust <name|id>",
		Short: "Revoke a trusted device; it needs the PIN again",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := loadApp(*verbose)
			if err != nil {
				return err
			}
			if all {
				n, err := a.trust.RemoveAll()
				if err != nil {
					return err
				}
				fmt.Printf("✓ %s revoked. Everyone needs the PIN again.\n", plural(n, "trusted device", "trusted devices"))
				return nil
			}
			if len(args) != 1 {
				return usageErr("name a device (see `drop security trusted`) or pass --all")
			}
			var match []security.TrustedDevice
			for _, d := range a.trust.List() {
				if strings.EqualFold(d.Name, args[0]) || d.ID == args[0] || (len(args[0]) >= 6 && strings.HasPrefix(d.ID, strings.ToLower(args[0]))) {
					match = append(match, d)
				}
			}
			switch len(match) {
			case 0:
				return usageErr("no trusted device matches %q", args[0])
			case 1:
				if _, err := a.trust.Remove(match[0].ID); err != nil {
					return err
				}
				fmt.Printf("✓ %s is no longer trusted. It needs the PIN again.\n", match[0].Name)
				return nil
			}
			return usageErr("%q matches %d trusted devices; use the ID from `drop security trusted`", args[0], len(match))
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "revoke every trusted device")
	return cmd
}

func (a *app) listTrusted() error {
	devs := a.trust.List()
	if len(devs) == 0 {
		fmt.Fprintln(os.Stderr, "No trusted devices. A device becomes trusted when you answer yes to the offer after a PIN-authorized transfer.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tOS\tID\tTRUSTED SINCE\tLAST USED\tSTATUS")
	for _, d := range devs {
		status := "active"
		if a.trust.Expired(d) {
			status = "expired (needs the PIN)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", a.label(d.ID, d.Name), sanitizeLabel(d.OS), d.ID[:8],
			d.AddedAt.Local().Format("2006-01-02"), d.LastUsed.Local().Format("2006-01-02"), status)
	}
	return tw.Flush()
}
