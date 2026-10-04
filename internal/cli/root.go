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

Send files, folders, text, Git changes and your clipboard to nearby devices
without accounts, cloud storage or IP addresses.

EASIEST START
  drop setup               one arrow-key menu for everything below: turn Active
                           sharing / Active clipboard on or off, add or remove
                           trusted devices, allow devices, save networks, folders, PIN.

FIRST TRANSFER
  Receiving device:  drop receive          (shows your Drop PIN; keep it open)
  Sending device:    drop report.pdf       (pick the device, enter the PIN)
  Answer "y" when the receiver offers to trust the sender: needed for the
  automatic modes below.

SET UP ACTIVE SHARING  (files and folders arrive with no "Accept?" prompt)
  Do this once on the RECEIVING computer, while connected to the network to allow:
    drop active setup --dir ~/Shared --device "Work PC" --network Home
  It saves the folder, allows that trusted device, remembers this network (by its
  router) and starts a small background receiver, so nobody has to run
  "drop receive". Works only on saved networks, from allowed devices.
    drop active status                  what is on, and whether it is working now
    drop active off / on                pause / resume
    drop active network add Office      allow another network (list, remove too)
    drop active allow Phone / deny Phone

SET UP ACTIVE CLIPBOARD  (a copy sent to you lands on your clipboard, just paste)
  Once on the RECEIVING computer (uses the same allowed devices and networks):
    drop clipboard live on --device "Work PC" --network Home
  Then on the SENDING device: copy something, run "drop clipboard", choose the
  device. The receiver gets a notification and pastes with Cmd+V / Ctrl+V.
    drop clipboard live status / off`

const rootExample = `  SETUP
  drop setup                         guided menu: active sharing, clipboard, devices, networks

  SEND
  drop main.py                       pick a nearby device, then send
  drop src/                          send a folder (smart exclusions, secrets skipped)
  drop --to Office main.py           send without prompts (name, nickname, ID or host:port)
  echo hi | drop --text              send plain text (no PIN)
  drop clipboard                     pick what you copied (arrow keys, Space, a, Enter) and send
  drop diff / drop git               send your uncommitted Git changes / the repository

  RECEIVE
  drop receive                       wait for incoming files, text and clipboards
  drop receive --dir ~/inbox         save somewhere else (press d at the prompt for one transfer)
  drop receive-dir ~/inbox           make that the default folder (--reset to undo)

  DEVICES AND NAMES
  drop devices                       list devices on your network
  drop name 192.168.1.8 Mom          give a device (or address) a nickname only you see
  drop --to Mom main.py              send using the nickname

  ACTIVE SHARING AND CLIPBOARD
  drop active setup --dir ~/Shared --device "Work PC" --network Home
  drop active status | on | off | network list
  drop active service status | stop | start | uninstall
  drop clipboard live on --device "Work PC" --network Home
  drop clipboard history on          remember earlier copies for the picker (off by default)

  SECURITY
  drop security show-pin             show your Drop PIN again
  drop security trusted              devices that may send without the PIN
  drop security untrust <name>       revoke one (or --all)
  drop security generate-pin         new PIN (the old one stops working)`

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

	root.AddCommand(newSendCmd(&verbose), newReceiveCmd(&verbose), newReceiveDirCmd(&verbose), newSetupCmd(&verbose), newActiveCmd(&verbose), newClipboardCmd(&verbose), newNameCmd(&verbose), newDevicesCmd(&verbose), newDiffCmd(&verbose), newGitCmd(&verbose), newSecurityCmd(&verbose), newStatusCmd(&verbose))
	return root
}

func usageErr(format string, args ...any) error {
	return withCode(ExitUsage, fmt.Errorf(format, args...))
}
