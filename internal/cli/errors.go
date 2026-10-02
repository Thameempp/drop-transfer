package cli

import (
	"context"
	"errors"
	"net"

	"github.com/thameem/drop/internal/protocol"
	"github.com/thameem/drop/internal/transfer"
)

// Exit codes. Stable: scripts and IDE integrations may rely on them.
const (
	ExitOK           = 0
	ExitGeneral      = 1
	ExitUsage        = 2
	ExitUnavailable  = 3 // device not found / unreachable
	ExitAuth         = 4 // reserved for the authentication phase
	ExitTransfer     = 5
	ExitVerification = 6
	ExitCancelled    = 130
)

// exitError carries an exit code and a user-facing message.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func withCode(code int, err error) error {
	if err == nil {
		return nil
	}
	return &exitError{code: code, err: err}
}

// codeFor maps an error to an exit code.
func codeFor(err error) int {
	var ee *exitError
	switch {
	case errors.As(err, &ee):
		return ee.code
	case errors.Is(err, context.Canceled):
		return ExitCancelled
	case errors.Is(err, transfer.ErrVerification):
		return ExitVerification
	case errors.Is(err, transfer.ErrDeclined), protocol.IsRemote(err):
		return ExitTransfer
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return ExitUnavailable
	}
	return ExitGeneral
}
