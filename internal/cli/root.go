// Package cli wires the command line to the application packages. It owns all
// terminal interaction; networking and transfer logic live elsewhere.
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"
)

const rootLong = `drop — developer-first local transfer

Send files to nearby devices without accounts, cloud storage or IP addresses.`

const rootExample = `  drop main.py              pick a nearby device, then send
  drop --to windows main.py send without prompts (scripts, IDEs)
  echo hi | drop --text     send plain text (no PIN)
  drop security             manage your Drop PIN
  drop diff                 send your Git changes (patch or files)
  drop receive              wait for incoming files
  drop devices              list nearby devices`

// Execute runs the CLI and returns the process exit code.
func Execute(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	root := newRoot()
	root.SetArgs(args)
	if err := root.ExecuteContext(ctx); err != nil {
		if errors.Is(err, errPickCancelled) || errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "Cancelled.")
			return ExitCancelled
		}
		fmt.Fprintf(os.Stderr, "drop: %v\n", err)
		if v, _ := root.PersistentFlags().GetBool("verbose"); !v && codeFor(err) != ExitUsage {
			fmt.Fprintln(os.Stderr, "Run with --verbose for details.")
		}
		return codeFor(err)
	}
	return ExitOK
}

func newRoot() *cobra.Command {
	var verbose bool
	var send sendOptions

	root := &cobra.Command{
		Use:     "drop [path]",
		Short:   "Developer-first local file transfer",
		Long:    rootLong,
		Example: rootExample,
		// ArbitraryArgs lets `drop main.py` fall through to the send flow;
		// real subcommand names are still matched first by cobra.
		Args:          cobra.ArbitraryArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && !send.text {
				return cmd.Help()
			}
			return runSend(cmd, verbose, send, args)
		},
	}
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "print diagnostic detail to stderr")
	root.Version = Version
	addSendFlags(root, &send)

	root.AddCommand(newSendCmd(&verbose), newReceiveCmd(&verbose), newDevicesCmd(&verbose), newDiffCmd(&verbose), newGitCmd(&verbose), newSecurityCmd(&verbose), newStatusCmd(&verbose))
	return root
}

func usageErr(format string, args ...any) error {
	return withCode(ExitUsage, fmt.Errorf(format, args...))
}
