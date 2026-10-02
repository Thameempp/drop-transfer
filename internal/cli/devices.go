package cli

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/thameem/drop/internal/discovery"
)

func newDevicesCmd(verbose *bool) *cobra.Command {
	var (
		timeout time.Duration
		ready   bool
		passive bool
	)
	cmd := &cobra.Command{
		Use:   "devices",
		Short: "List devices on your network (and which of them can receive with drop)",
		Long: `Lists the devices nearby on your local network, whether or not they run drop.
Devices that are ready to receive (running "drop receive") are listed first.

Sources: mDNS/Bonjour (every service type a device advertises), the operating
system's neighbor table, and reverse DNS for names. To make the neighbor table
complete, drop first sends one tiny UDP packet to each address of your local
subnet (never more than a /24); use --passive to skip that. Devices that
advertise nothing, and phones that use a random MAC address, may appear only
by IP address, and some devices (those that ignore the network) cannot be seen
at all. To send to a device it must run "drop receive".`,
		Example: "  drop devices\n  drop devices --ready       only devices that can receive now\n  drop devices --passive     do not probe the subnet",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := loadApp(*verbose)
			if err != nil {
				return err
			}
			if isTTY(os.Stderr) {
				fmt.Fprint(os.Stderr, "Scanning your network…\r")
			}
			hosts, err := discovery.ScanLAN(cmd.Context(), discovery.ScanOptions{Timeout: timeout, Probe: !passive})
			if isTTY(os.Stderr) {
				fmt.Fprint(os.Stderr, "\033[K")
			}
			if err != nil {
				return withCode(ExitUnavailable, err)
			}
			// Never list this device itself as a peer.
			var shown []discovery.Host
			readyCount := 0
			for _, h := range hosts {
				if h.Drop != nil && h.Drop.ID == a.identity.ID {
					continue
				}
				if h.Drop != nil {
					readyCount++
				} else if ready {
					continue
				}
				shown = append(shown, h)
			}
			if len(shown) == 0 {
				if ready {
					fmt.Fprintln(os.Stderr, "No device is ready to receive. Run `drop receive` on the other device (without --ready, `drop devices` lists everything on your network).")
				} else {
					fmt.Fprintln(os.Stderr, "No devices found. Check that you are on the same Wi-Fi/LAN as the other devices and that no VPN or guest-network isolation is active.")
				}
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tADDRESS\tDROP\tDETAILS")
			for _, h := range shown {
				state, details := "not running", h.Describe()
				id := ""
				if h.Drop != nil {
					id = h.Drop.ID
				}
				name := a.labelAt(cmd.Context(), id, h.Name, h.IP)
				if h.Drop != nil {
					state = "ready"
					details = sanitizeLabel(h.Drop.OS)
					if a.trustedBy.Has(h.Drop.ID) {
						details += ", trusts you"
					}
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", shorten(name, 40), h.IP, state, details)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			notReady := len(shown) - readyCount
			fmt.Fprintf(os.Stderr, "\n%s ready to receive, %s without drop running.", plural(readyCount, "device", "devices"), plural(notReady, "device", "devices"))
			if notReady > 0 && !ready {
				fmt.Fprint(os.Stderr, " Run `drop receive` on a device to send to it.")
			}
			fmt.Fprintln(os.Stderr)
			return nil
		},
	}
	cmd.Flags().DurationVar(&timeout, "timeout", 2*time.Second, "how long each discovery phase waits")
	cmd.Flags().BoolVar(&ready, "ready", false, "only devices that are ready to receive (running `drop receive`)")
	cmd.Flags().BoolVar(&passive, "passive", false, "do not send the probe packets that fill the neighbor table")
	return cmd
}
