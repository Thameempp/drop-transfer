package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/thameem/drop/internal/device"
	"github.com/thameem/drop/internal/security"
)

func newStatusCmd(verbose *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show this device's identity and configuration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := loadApp(*verbose)
			if err != nil {
				return err
			}
			recv, _ := a.cfg.ResolveReceiveDir()
			fmt.Printf("Device:      %s (%s)\n", a.identity.Name, a.identity.OS)
			fmt.Printf("Drop:        %s\n", Version)
			fmt.Printf("Fingerprint: %s\n", device.Fingerprint(a.identity.PublicKey))
			fmt.Printf("Transport:   %s + TLS 1.3\n", a.tr.Name())
			pin := "configured"
			if _, err := a.pins.Load(); err != nil {
				pin = "not set (created on first `drop receive`)"
			}
			fmt.Printf("Drop PIN:    %s\n", pin)
			fmt.Printf("Text policy: PIN %s\n", map[bool]string{true: "required", false: "not required"}[a.policy().RequiresAuthorization(security.TransferText)])
			fmt.Printf("Receives to: %s\n", recv)
			fmt.Printf("Config dir:  %s\n", a.cfgDir)
			return nil
		},
	}
}
