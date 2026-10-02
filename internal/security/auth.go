package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"filippo.io/cpace"
	"golang.org/x/crypto/hkdf"

	"github.com/thameem/drop/internal/protocol"
	"github.com/thameem/drop/internal/transport"
)

const authAD = "drop-pin-auth-v1"

var authTimeout = 30 * time.Second

// Failure kinds a sender can see. Deliberately coarse: a wrong PIN reveals
// nothing about how close the guess was.
var (
	ErrWrongPIN = errors.New("incorrect Drop PIN")
	ErrLocked   = errors.New("receiver is temporarily locked after too many failed attempts")
)

// AuthError carries the user-facing detail of a failed authorization.
type AuthError struct {
	Err               error
	AttemptsRemaining int
	RetryAfter        time.Duration
}

func (e *AuthError) Error() string { return e.Err.Error() }
func (e *AuthError) Unwrap() error { return e.Err }

// Authenticator is the receiver side of PIN authorization.
type Authenticator struct {
	SelfID  string
	PINs    *PINStore
	Limiter *Limiter
	// Logf receives safe, secret-free diagnostics. Optional.
	Logf func(format string, args ...any)
}

func (a *Authenticator) logf(f string, args ...any) {
	if a.Logf != nil {
		a.Logf(f, args...)
	}
}

// Serve runs the receiver half after an AuthInit has been read. It returns nil
// only if the sender proved knowledge of the PIN. Nothing here depends on, or
// reveals, how close a wrong PIN was.
func (a *Authenticator) Serve(conn transport.Conn) error {
	peerID, binding, err := channel(conn)
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(authTimeout))
	defer conn.SetDeadline(time.Time{})
	a.logf("[auth] authentication requested")

	verifier, err := a.PINs.Load()
	if err != nil {
		_ = protocol.WriteMsg(conn, &protocol.Error{Message: "authorization is not available on this device"})
		return err
	}
	lockedFor, remaining, err := a.Limiter.Begin()
	if err != nil {
		return fmt.Errorf("record attempt: %w", err)
	}
	if lockedFor > 0 {
		a.logf("[auth] rejected: locked")
		_ = protocol.WriteMsg(conn, &protocol.AuthParams{Locked: true, RetryAfter: ceilSecs(lockedFor)})
		return &AuthError{Err: ErrLocked, RetryAfter: lockedFor}
	}
	p := verifier.params()
	if err := protocol.WriteMsg(conn, &protocol.AuthParams{Salt: p.Salt, Time: p.Time, MemoryKiB: p.MemoryKiB, Threads: p.Threads}); err != nil {
		return err
	}
	start, err := protocol.Expect[*protocol.AuthStart](conn)
	if err != nil {
		return fmt.Errorf("authentication: %w", err)
	}
	ctxInfo := cpace.NewContextInfo(peerID, a.SelfID, append(append([]byte(nil), binding...), authAD...))
	msgB, key, err := cpace.Exchange(verifier.password(), ctxInfo, start.Msg)
	if err != nil {
		return a.failAuth(conn, remaining, fmt.Errorf("authentication: %w", err))
	}
	if err := protocol.WriteMsg(conn, &protocol.AuthChallenge{Msg: msgB}); err != nil {
		return err
	}
	proof, err := protocol.Expect[*protocol.AuthProof](conn)
	if err != nil {
		return fmt.Errorf("authentication: %w", err)
	}
	want := tag(key, "initiator", start.Msg, msgB)
	if !hmac.Equal(proof.Tag, want) {
		return a.failAuth(conn, remaining, nil)
	}
	if err := a.Limiter.Succeed(); err != nil {
		return fmt.Errorf("record success: %w", err)
	}
	a.logf("[auth] authentication succeeded")
	return protocol.WriteMsg(conn, &protocol.AuthResult{OK: true, Tag: tag(key, "responder", start.Msg, msgB)})
}

func (a *Authenticator) failAuth(conn transport.Conn, remaining int, cause error) error {
	lockedFor, err := a.Limiter.Fail()
	if err != nil {
		return fmt.Errorf("record failure: %w", err)
	}
	a.logf("[auth] authentication failed")
	_ = protocol.WriteMsg(conn, &protocol.AuthResult{OK: false, AttemptsRemaining: remaining, RetryAfter: ceilSecs(lockedFor)})
	if cause != nil {
		a.logf("[auth] detail: %v", cause)
	}
	return &AuthError{Err: ErrWrongPIN, AttemptsRemaining: remaining, RetryAfter: lockedFor}
}

// Authenticate runs the sender half: it proves knowledge of pin to the
// receiver (and verifies the receiver knew it too) without sending the PIN.
func Authenticate(conn transport.Conn, selfID, pin string) error {
	peerID, binding, err := channel(conn)
	if err != nil {
		return err
	}
	if err := ValidatePIN(pin); err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(authTimeout))
	defer conn.SetDeadline(time.Time{})

	if err := protocol.WriteMsg(conn, &protocol.AuthInit{}); err != nil {
		return err
	}
	params, err := protocol.Expect[*protocol.AuthParams](conn)
	if err != nil {
		return fmt.Errorf("authentication: %w", err)
	}
	if params.Locked {
		return &AuthError{Err: ErrLocked, RetryAfter: time.Duration(params.RetryAfter) * time.Second}
	}
	password, err := passwordFromPIN(pin, paramsView{params.Salt, params.Time, params.MemoryKiB, params.Threads})
	if err != nil {
		return err
	}
	ctxInfo := cpace.NewContextInfo(selfID, peerID, append(append([]byte(nil), binding...), authAD...))
	msgA, state, err := cpace.Start(password, ctxInfo)
	if err != nil {
		return fmt.Errorf("authentication: %w", err)
	}
	if err := protocol.WriteMsg(conn, &protocol.AuthStart{Msg: msgA}); err != nil {
		return err
	}
	ch, err := protocol.Expect[*protocol.AuthChallenge](conn)
	if err != nil {
		return fmt.Errorf("authentication: %w", err)
	}
	key, err := state.Finish(ch.Msg)
	if err != nil {
		return fmt.Errorf("authentication: %w", err)
	}
	if err := protocol.WriteMsg(conn, &protocol.AuthProof{Tag: tag(key, "initiator", msgA, ch.Msg)}); err != nil {
		return err
	}
	res, err := protocol.Expect[*protocol.AuthResult](conn)
	if err != nil {
		return fmt.Errorf("authentication: %w", err)
	}
	if !res.OK {
		return &AuthError{Err: ErrWrongPIN, AttemptsRemaining: res.AttemptsRemaining, RetryAfter: time.Duration(res.RetryAfter) * time.Second}
	}
	if !hmac.Equal(res.Tag, tag(key, "responder", msgA, ch.Msg)) {
		return errors.New("authentication: receiver failed to prove it knows the PIN; refusing to continue")
	}
	return nil
}

func channel(conn transport.Conn) (peerID string, binding []byte, err error) {
	p, ok := conn.(transport.Peered)
	if !ok {
		return "", nil, errors.New("PIN authorization requires a secured connection")
	}
	b, err := ChannelBinding(conn)
	if err != nil {
		return "", nil, fmt.Errorf("bind to secure channel: %w", err)
	}
	return p.PeerID(), b, nil
}

// tag is explicit key confirmation: HMAC-SHA-256 under a key expanded from the
// PAKE output with HKDF, over the PAKE transcript, labelled per role so a tag
// cannot be reflected back.
func tag(key []byte, role string, msgA, msgB []byte) []byte {
	k := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, key, []byte("drop confirm "+role)), k); err != nil {
		panic(err) // HKDF-SHA256 can always produce 32 bytes
	}
	m := hmac.New(sha256.New, k)
	m.Write(msgA)
	m.Write(msgB)
	return m.Sum(nil)
}

func ceilSecs(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int((d + time.Second - 1) / time.Second)
}
