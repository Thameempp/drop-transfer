package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/thameem/drop/internal/active"
	"github.com/thameem/drop/internal/config"
	"github.com/thameem/drop/internal/discovery"
	"github.com/thameem/drop/internal/security"
	"github.com/thameem/drop/internal/transfer"
)

// devRef is a device the user might mean.
type devRef struct{ ID, Name string }

// matchDevice picks the one device that q names: a nickname, a device name, or
// the start of a device ID. Exact matches win; anything ambiguous is an error.
func (a *app) matchDevice(q string, cands []devRef) (devRef, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return devRef{}, usageErr("name a device")
	}
	if id, ok := a.names.Resolve(q); ok {
		for _, c := range cands {
			if c.ID == id {
				return c, nil
			}
		}
	}
	var exact, loose []devRef
	for _, c := range cands {
		n := strings.ToLower(c.Name)
		lq := strings.ToLower(q)
		switch {
		case n == lq || c.ID == q:
			exact = append(exact, c)
		case (len(q) >= 4 && strings.HasPrefix(c.ID, lq)) || strings.HasPrefix(n, lq) || strings.Contains(n, lq):
			loose = append(loose, c)
		case strings.Contains(strings.ToLower(a.names.Get(c.ID)), lq):
			loose = append(loose, c)
		}
	}
	m := exact
	if len(m) == 0 {
		m = loose
	}
	switch len(m) {
	case 0:
		return devRef{}, usageErr("no device matches %q", q)
	case 1:
		return m[0], nil
	}
	var b strings.Builder
	for _, c := range m {
		fmt.Fprintf(&b, "\n  • %s (%s)", a.label(c.ID, c.Name), c.ID[:8])
	}
	return devRef{}, usageErr("%q matches several devices:%s\nBe more specific (a longer name or the ID).", q, b.String())
}

// label shows a device as "nickname (real name)" when the user named it.
func (a *app) label(id, name string) string {
	return active.Display(a.names.Get(id), sanitizeLabel(name))
}

func (a *app) trustedRefs() []devRef {
	var out []devRef
	for _, d := range a.trust.List() {
		out = append(out, devRef{d.ID, d.Name})
	}
	return out
}

func newActiveCmd(verbose *bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "active",
		Short: "Auto-accept files from chosen trusted devices on your own network",
		Long: `Active sharing lets chosen trusted devices send you files and folders
without you answering "Accept?" each time. Everything arrives in one dedicated
folder. It only works when ALL of these hold:

  • "drop receive" is running (or the background service is installed:
    "drop active service install", so the other person never has to run it)
  • the sender is a trusted device that you explicitly allowed
  • you are on a network you saved (identified by the router, not the Wi-Fi name)
  • the sender is on that same local network
  • active sharing is on

Anything else still asks as usual.`,
		Example: "  drop active setup --dir ~/Shared --device \"Work PC\" --network Home\n  drop active status\n  drop active off",
	}
	cmd.AddCommand(
		newActiveSetupCmd(verbose),
		&cobra.Command{Use: "status", Short: "Show the active-sharing settings", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				a, err := loadApp(*verbose)
				if err != nil {
					return err
				}
				return a.showActive(cmd.Context())
			}},
		&cobra.Command{Use: "on", Short: "Turn active sharing on", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				return withActive(*verbose, func(a *app, st *active.Settings) error {
					if missing := activeMissing(*st); missing != "" {
						return usageErr("cannot turn on yet: %s", missing)
					}
					st.Enabled = true
					fmt.Println("✓ Active sharing is on.")
					return nil
				})
			}},
		&cobra.Command{Use: "off", Short: "Turn active sharing off (settings are kept)", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				return withActive(*verbose, func(a *app, st *active.Settings) error {
					st.Enabled = false
					fmt.Println("✓ Active sharing is off. Every transfer asks again.")
					return nil
				})
			}},
		&cobra.Command{Use: "dir <folder>", Short: "Set the dedicated folder active sharing saves into", Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return withActive(*verbose, func(a *app, st *active.Settings) error {
					p, err := prepareDir(args[0])
					if err != nil {
						return err
					}
					st.Dir = p
					fmt.Printf("✓ Active sharing saves into %s\n", p)
					return nil
				})
			}},
		&cobra.Command{Use: "allow <device>", Short: "Let a trusted device send without asking", Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return withActive(*verbose, func(a *app, st *active.Settings) error {
					d, err := a.matchTrusted(args[0])
					if err != nil {
						return err
					}
					st.Allow(d.ID)
					fmt.Printf("✓ %s may now send without asking.\n", a.label(d.ID, d.Name))
					return nil
				})
			}},
		newActiveDenyCmd(verbose),
		newActiveServeCmd(verbose),
		newActiveServiceCmd(verbose),
		newActiveNetworkCmd(verbose),
	)
	return cmd
}

// withActive loads the settings, lets fn change them and saves.
func withActive(verbose bool, fn func(*app, *active.Settings) error) error {
	a, err := loadApp(verbose)
	if err != nil {
		return err
	}
	return a.active.Update(func(st *active.Settings) error { return fn(a, st) })
}

func (a *app) matchTrusted(q string) (devRef, error) {
	cands := a.trustedRefs()
	if len(cands) == 0 {
		return devRef{}, usageErr("no trusted devices yet. A device becomes trusted when you answer yes to the offer after a PIN-authorized transfer (see `drop security trusted`)")
	}
	return a.matchDevice(q, cands)
}

func prepareDir(arg string) (string, error) {
	p, err := config.ExpandDir(arg)
	if err != nil {
		return "", usageErr("%v", err)
	}
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		return "", usageErr("%s is not a folder", p)
	}
	if err := os.MkdirAll(p, 0o755); err != nil {
		return "", withCode(ExitGeneral, err)
	}
	return p, nil
}

// activeMissing says what is still needed before active sharing can be on.
func activeMissing(st active.Settings) string {
	var m []string
	if st.Dir == "" {
		m = append(m, "set a folder (drop active dir <folder>)")
	}
	if len(st.Devices) == 0 {
		m = append(m, "allow a trusted device (drop active allow <device>)")
	}
	if len(st.Networks) == 0 {
		m = append(m, "save this network (drop active network add <name>)")
	}
	return strings.Join(m, "; ")
}

func newActiveSetupCmd(verbose *bool) *cobra.Command {
	var (
		dir     string
		devices []string
		network string
	)
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Set everything up in one go and turn active sharing on",
		Long: `Sets the folder, allows the trusted devices you name, saves the network you are
on right now under the given name, and turns active sharing on. Run it while
connected to the network you want to allow.`,
		Example: `  drop active setup --dir ~/Shared --device "Work PC" --device Phone --network Home`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if dir == "" || len(devices) == 0 || network == "" {
				return usageErr("setup needs --dir <folder>, at least one --device <trusted device> and --network <name for this network>")
			}
			return withActive(*verbose, func(a *app, st *active.Settings) error {
				p, err := prepareDir(dir)
				if err != nil {
					return err
				}
				var picked []devRef
				for _, q := range devices {
					d, err := a.matchTrusted(q)
					if err != nil {
						return err
					}
					picked = append(picked, d)
				}
				net, err := a.currentNetwork(cmd.Context(), network)
				if err != nil {
					return err
				}
				st.Dir = p
				for _, d := range picked {
					st.Allow(d.ID)
				}
				st.AddNetwork(net)
				st.Enabled = true
				fmt.Printf("✓ Active sharing is on.\n  Folder:  %s\n  Network: %s\n  Devices:", p, net.Name)
				for _, d := range picked {
					fmt.Printf(" %s", a.label(d.ID, d.Name))
				}
				fmt.Println("\nKeep `drop receive` running to receive.")
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "folder to save into")
	cmd.Flags().StringArrayVar(&devices, "device", nil, "trusted device to allow (repeatable)")
	cmd.Flags().StringVar(&network, "network", "", "name to save the current network under")
	return cmd
}

func newActiveDenyCmd(verbose *bool) *cobra.Command {
	var all bool
	cmd := &cobra.Command{Use: "deny [device]", Short: "Stop auto-accepting from a device (it stays trusted)", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withActive(*verbose, func(a *app, st *active.Settings) error {
				if all {
					st.Devices = nil
					fmt.Println("✓ No device is auto-accepted any more.")
					return nil
				}
				if len(args) != 1 {
					return usageErr("name a device or pass --all")
				}
				var cands []devRef
				for _, id := range st.Devices {
					name := id[:8]
					for _, t := range a.trustedRefs() {
						if t.ID == id {
							name = t.Name
						}
					}
					cands = append(cands, devRef{id, name})
				}
				d, err := a.matchDevice(args[0], cands)
				if err != nil {
					return err
				}
				st.Deny(d.ID)
				fmt.Printf("✓ %s now asks before sending, like any other device.\n", a.label(d.ID, d.Name))
				return nil
			})
		}}
	cmd.Flags().BoolVar(&all, "all", false, "stop auto-accepting from every device")
	return cmd
}

func newActiveNetworkCmd(verbose *bool) *cobra.Command {
	cmd := &cobra.Command{Use: "network", Short: "Choose the networks active sharing works on",
		Long: `Active sharing only works while you are connected to a saved network, and you can
save as many as you like (home, office...). A network is recognised by its
router, so run "add" while connected to the one you want to allow.`}
	cmd.AddCommand(
		&cobra.Command{Use: "add [name]", Short: "Save the network you are connected to now", Args: cobra.MaximumNArgs(1),
			Long: "Saves the network you are connected to right now. Without a name it uses the Wi-Fi name when the system shares it.",
			RunE: func(cmd *cobra.Command, args []string) error {
				return withActive(*verbose, func(a *app, st *active.Settings) error {
					name := ""
					if len(args) == 1 {
						name = args[0]
					} else if name = discovery.WiFiName(cmd.Context()); name == "" {
						name = fmt.Sprintf("Network %d", len(st.Networks)+1)
					}
					n, err := a.currentNetwork(cmd.Context(), name)
					if err != nil {
						return err
					}
					for _, o := range st.Networks {
						if strings.EqualFold(o.GatewayMAC, n.GatewayMAC) && !strings.EqualFold(o.Name, n.Name) {
							fmt.Printf("(You were already on this network as %q; it is now called %q.)\n", o.Name, n.Name)
						}
					}
					st.AddNetwork(n)
					fmt.Printf("✓ Saved this network as %q. Active sharing works here now.\n", n.Name)
					return nil
				})
			}},
		&cobra.Command{Use: "list", Short: "Show the saved networks", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				a, err := loadApp(*verbose)
				if err != nil {
					return err
				}
				st, err := a.active.Load()
				if err != nil {
					return err
				}
				if len(st.Networks) == 0 {
					fmt.Fprintln(os.Stderr, "No saved networks. Connect to one and run: drop active network add [name]")
					return nil
				}
				here, _ := a.currentRouter(cmd.Context())
				tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "NAME\tWI-FI NAME\tROUTER\t")
				for _, n := range st.SortedNetworks() {
					mark := ""
					if here != "" && strings.EqualFold(here, n.GatewayMAC) {
						mark = "← connected now"
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", n.Name, n.SSID, n.GatewayMAC, mark)
				}
				return tw.Flush()
			}},
		&cobra.Command{Use: "remove <name>", Short: "Forget a saved network", Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return withActive(*verbose, func(a *app, st *active.Settings) error {
					if !st.RemoveNetwork(args[0]) {
						return usageErr("no saved network named %q (see: drop active network list)", args[0])
					}
					fmt.Printf("✓ Forgot network %q. Active sharing no longer works there.\n", args[0])
					return nil
				})
			}},
	)
	return cmd
}

// currentNetwork identifies the network this machine is on right now.
func (a *app) currentNetwork(ctx context.Context, name string) (active.Network, error) {
	name = active.Clean(name)
	if name == "" {
		return active.Network{}, usageErr("give the network a name")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	mac, err := discovery.CurrentRouterMAC(ctx)
	if err != nil || mac == "" {
		return active.Network{}, withCode(ExitUnavailable, fmt.Errorf("could not identify this network (%v). Are you connected to a router?", err))
	}
	return active.Network{Name: name, GatewayMAC: mac, SSID: discovery.WiFiName(ctx)}, nil
}

// currentRouter is the hardware address of the router we are connected through, or "".
func (a *app) currentRouter(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	return discovery.CurrentRouterMAC(ctx)
}

func (a *app) showActive(ctx context.Context) error {
	st, err := a.active.Load()
	if err != nil {
		return err
	}
	here, _ := a.currentRouter(ctx)
	var hereNet *active.Network
	for i, n := range st.Networks {
		if here != "" && strings.EqualFold(n.GatewayMAC, here) {
			hereNet = &st.Networks[i]
		}
	}
	switch {
	case !st.Enabled:
		fmt.Println("Active sharing: OFF (turn on: drop active on)")
	case len(st.Networks) == 0:
		fmt.Println("Active sharing: ON, but no network is saved yet (drop active network add)")
	case hereNet != nil:
		fmt.Printf("Active sharing: ON and working now (connected to %q)\n", hereNet.Name)
	default:
		fmt.Println("Active sharing: ON, waiting: you are not on a saved network, so every transfer still asks")
	}
	dir := st.Dir
	if dir == "" {
		dir = "(not set: drop active dir <folder>)"
	}
	fmt.Printf("  Folder:   %s\n", dir)
	if len(st.Devices) == 0 {
		fmt.Println("  Devices:  none (drop active allow <device>)")
	} else {
		fmt.Println("  Devices:")
		trusted := map[string]string{}
		for _, t := range a.trustedRefs() {
			trusted[t.ID] = t.Name
		}
		for _, id := range st.Devices {
			note := ""
			name, ok := trusted[id]
			if !ok {
				name, note = id[:8], "  (no longer trusted: it will ask)"
			}
			fmt.Printf("    • %s%s\n", a.label(id, name), note)
		}
	}
	if len(st.Networks) == 0 {
		fmt.Println("  Networks: none (drop active network add [name])")
	} else {
		fmt.Println("  Networks (works only on these):")
		for _, n := range st.SortedNetworks() {
			extra := ""
			if n.SSID != "" && n.SSID != n.Name {
				extra = " (Wi-Fi " + n.SSID + ")"
			}
			mark := ""
			if hereNet != nil && hereNet.GatewayMAC == n.GatewayMAC {
				mark = "  ← connected now"
			}
			fmt.Printf("    • %s%s%s\n", n.Name, extra, mark)
		}
	}
	return nil
}

// activeAccept decides whether inc may be accepted without asking. The second
// result is a short note explaining why active sharing did not apply (for the
// device owner), empty when it is simply not in use.
func (a *app) activeAccept(ctx context.Context, inc transfer.Incoming) (transfer.Decision, string) {
	st, err := a.active.Load()
	if err != nil || !st.Enabled {
		return transfer.Decision{}, ""
	}
	if inc.Type == security.TransferText || inc.AuthMethod != "trusted" || !st.HasDevice(inc.KeyID) {
		return transfer.Decision{}, ""
	}
	mac := ""
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if m, err := discovery.CurrentRouterMAC(cctx); err == nil {
		mac = m
	}
	host, _, _ := net.SplitHostPort(inc.Addr)
	d := st.Check(inc.KeyID, inc.AuthMethod == "trusted", mac, discovery.OnLink(net.ParseIP(host)))
	if !d.OK {
		return transfer.Decision{}, d.Reason
	}
	return transfer.Decision{Accept: true, Conflict: transfer.ConflictRename, Dir: d.Dir}, ""
}

// activeBanner is the line `drop receive` prints about active sharing, or "".
func (a *app) activeBanner() string {
	st, err := a.active.Load()
	if err != nil || !st.Enabled {
		return ""
	}
	var names []string
	for _, id := range st.Devices {
		n := id[:8]
		for _, t := range a.trustedRefs() {
			if t.ID == id {
				n = t.Name
			}
		}
		names = append(names, a.label(id, n))
	}
	var nets []string
	for _, n := range st.SortedNetworks() {
		nets = append(nets, n.Name)
	}
	return fmt.Sprintf("Active sharing ON: %s can send without asking → %s\n  (only on: %s)", strings.Join(names, ", "), st.Dir, strings.Join(nets, ", "))
}

// ---- nicknames

func newNameCmd(verbose *bool) *cobra.Command {
	var clear bool
	cmd := &cobra.Command{
		Use:   "name [device] [nickname]",
		Short: "Give a device a nickname that only you see",
		Long: `Names a device for yourself. The nickname is stored only on this machine; the
other device is never told. It shows up wherever that device is listed, and
you can send to it with --to <nickname>.

The device can be given by name, or by its address (as shown by "drop devices"),
which also works for a device that is not running drop right now:
  drop name 192.168.1.8 Moms-phone

Without arguments it lists your nicknames.`,
		Example: "  drop name \"Work PC\" Office\n  drop name 192.168.1.8 Mom\n  drop --to Mom report.pdf\n  drop name Office --clear\n  drop name",
		Args:    cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := loadApp(*verbose)
			if err != nil {
				return err
			}
			if len(args) == 0 {
				return a.listNames()
			}
			if !clear && len(args) != 2 {
				return usageErr("usage: drop name <device> <nickname>   (or --clear to remove one)")
			}
			var d devRef
			if ip, ok := parseIPArg(args[0]); ok {
				d, err = a.resolveAddress(cmd.Context(), ip) // a device named by its address
			} else {
				d, err = a.matchDevice(args[0], a.knownDevices(cmd.Context()))
			}
			if err != nil {
				return err
			}
			nick := ""
			if !clear {
				if nick = active.Clean(args[1]); nick == "" {
					return usageErr("the nickname is empty")
				}
			}
			if err := a.names.Set(d.ID, nick); err != nil {
				if errors.Is(err, active.ErrNameTaken) {
					return usageErr("another device is already called %q", nick)
				}
				return withCode(ExitGeneral, err)
			}
			if clear {
				fmt.Printf("✓ Removed the nickname of %s.\n", sanitizeLabel(d.Name))
			} else {
				fmt.Printf("✓ %s is now called %q on this machine only.\n", sanitizeLabel(d.Name), nick)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&clear, "clear", false, "remove the device's nickname")
	return cmd
}

// knownDevices lists devices a nickname can be given to: trusted devices, ones
// already nicknamed, and anything currently visible running drop.
func (a *app) knownDevices(ctx context.Context) []devRef {
	seen := map[string]bool{}
	var out []devRef
	add := func(id, name string) {
		if id != "" && !seen[id] && id != a.identity.ID {
			seen[id] = true
			out = append(out, devRef{id, name})
		}
	}
	for _, t := range a.trustedRefs() {
		add(t.ID, t.Name)
	}
	for id := range a.names.List() {
		add(id, describeKey(id))
	}
	if peers, err := a.disc.Browse(ctx, 2*time.Second); err == nil {
		for _, p := range peers {
			add(p.ID, p.Name)
		}
	}
	return out
}

func (a *app) listNames() error {
	names := a.names.List()
	if len(names) == 0 {
		fmt.Fprintln(os.Stderr, "No nicknames yet. Give one with: drop name <device or address> <nickname>")
		return nil
	}
	real := map[string]string{}
	for _, t := range a.trustedRefs() {
		real[t.ID] = t.Name
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NICKNAME\tDEVICE")
	for id, nick := range names {
		dev := describeKey(id)
		if n := real[id]; n != "" {
			dev = sanitizeLabel(n) + " (" + id[:8] + ")"
		}
		fmt.Fprintf(tw, "%s\t%s\n", nick, dev)
	}
	return tw.Flush()
}
