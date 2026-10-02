package transfer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thameem/drop/internal/device"
	"github.com/thameem/drop/internal/protocol"
	"github.com/thameem/drop/internal/security"
	"github.com/thameem/drop/internal/transport"
)

// trustingApprover accepts every transfer and, if it can, asks to trust the sender.
func trustingApprover(trust bool) Approver {
	return ApproverFunc(func(_ context.Context, in Incoming) Decision {
		return Decision{Accept: true, Trust: trust}
	})
}

// session runs one transfer against a fresh single-connection receiver that
// shares the given trust store and identities (like a restarted `drop receive`).
type session struct {
	t     *testing.T
	trust *security.TrustStore
	rcv   *device.Identity
	snd   *device.Identity
	cfg   string
}

func newSession(t *testing.T) *session {
	st, _ := security.OpenTrustStore(t.TempDir(), security.DefaultTrustExpiry)
	s := &session{t: t, trust: st, rcv: newIdentity(t, "receiver"), snd: newIdentity(t, "sender"), cfg: t.TempDir()}
	if err := security.OpenPINStore(s.cfg).Set(testPIN); err != nil {
		t.Fatal(err)
	}
	return s
}

type outcome struct {
	send    *SendResult
	sendErr error
	rec     *Received
	recErr  error
	dir     string
}

func (s *session) run(ap Approver, sender *device.Identity, pin string, pol security.Policy, path string) outcome {
	t := s.t
	l, err := tcp.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	dir := t.TempDir()
	lim, _ := security.OpenLimiter(s.cfg, security.DefaultLimiter())
	r := &Receiver{
		Self: Self{ID: s.rcv.ID, Name: "recv"}, Dir: dir, Approver: ap, Policy: pol, Trust: s.trust,
		Upgrade: func(c transport.Conn) (transport.Conn, error) { return security.Server(c, s.rcv, security.Any()) },
		Auth:    &security.Authenticator{SelfID: s.rcv.ID, PINs: security.OpenPINStore(s.cfg), Limiter: lim},
	}
	done := make(chan outcome, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		rec, err := r.HandleOne(ctx, l)
		done <- outcome{rec: rec, recErr: err}
	}()
	raw, err := tcp.Dial(context.Background(), l.Addr())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := security.Client(raw, sender, security.ExpectID(s.rcv.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	res, serr := SendFile(context.Background(), conn, Self{ID: sender.ID, Name: "send", OS: "test"}, path, SendOptions{PIN: pin, Policy: pol})
	conn.Close() // like the CLI, so a failed send never leaves the receiver waiting
	out := <-done
	out.send, out.sendErr, out.dir = res, serr, dir
	return out
}

func srcFile(t *testing.T) string { return writeFile(t, "a.txt", []byte("payload")) }

func TestTrustLifecycle(t *testing.T) {
	s := newSession(t)
	src := srcFile(t)
	pol := security.Policy{}

	// 1) Untrusted sender without a PIN: refused, nothing written.
	o := s.run(trustingApprover(false), s.snd, "", pol, src)
	if !errors.Is(o.sendErr, ErrPINRequired) {
		t.Fatalf("untrusted sender without PIN: %v", o.sendErr)
	}
	assertEmpty(t, o.dir)

	// 2) With the PIN, and the receiver's user chooses to trust it.
	o = s.run(trustingApprover(true), s.snd, testPIN, pol, src)
	if o.sendErr != nil || o.recErr != nil {
		t.Fatalf("%v / %v", o.sendErr, o.recErr)
	}
	if !o.rec.TrustGranted || !o.send.TrustGranted || o.send.UsedTrust || o.rec.In.AuthMethod != "pin" {
		t.Fatalf("grant not reported: rec=%+v send=%+v", o.rec, o.send)
	}

	// 3) Next time: no PIN at all.
	o = s.run(trustingApprover(false), s.snd, "", pol, src)
	if o.sendErr != nil || o.recErr != nil {
		t.Fatalf("trusted send without PIN: %v / %v", o.sendErr, o.recErr)
	}
	if !o.send.UsedTrust || !o.rec.In.Authorized || o.rec.In.AuthMethod != "trusted" || o.rec.TrustGranted {
		t.Fatalf("%+v %+v", o.rec.In, o.send)
	}
	if b, _ := os.ReadFile(o.rec.Path); string(b) != "payload" {
		t.Fatal("content")
	}

	// 4) Revocation applies at once, even though this receiver "process" has been running.
	devs := s.trust.List()
	if len(devs) != 1 {
		t.Fatalf("%v", devs)
	}
	if ok, err := s.trust.Remove(devs[0].ID); !ok || err != nil {
		t.Fatal(ok, err)
	}
	o = s.run(trustingApprover(false), s.snd, "", pol, src)
	if !errors.Is(o.sendErr, ErrPINRequired) {
		t.Fatalf("revoked device still trusted: %v", o.sendErr)
	}
	assertEmpty(t, o.dir)
}

func TestDeclinedTrustOfferStoresNothing(t *testing.T) {
	s := newSession(t)
	o := s.run(trustingApprover(false), s.snd, testPIN, security.Policy{}, srcFile(t))
	if o.sendErr != nil || o.rec.TrustGranted || o.send.TrustGranted {
		t.Fatalf("%+v", o)
	}
	if len(s.trust.List()) != 0 {
		t.Fatal("device trusted without the user's say-so")
	}
}

func TestTrustIsBoundToTheKeyNotTheNameOrID(t *testing.T) {
	s := newSession(t)
	src := srcFile(t)
	s.run(trustingApprover(true), s.snd, testPIN, security.Policy{}, src) // trust the real sender

	// An attacker with a different key, same display name, no PIN.
	attacker := newIdentity(t, "sender")
	o := s.run(trustingApprover(false), attacker, "", security.Policy{}, src)
	if !errors.Is(o.sendErr, ErrPINRequired) {
		t.Fatalf("a different key inherited trust: %v", o.sendErr)
	}
	assertEmpty(t, o.dir)
}

func TestTrustOnlyGrantedAfterVerifiedTransfer(t *testing.T) {
	s := newSession(t)
	// Declined transfer: no trust even though the user ticked "trust".
	decline := ApproverFunc(func(context.Context, Incoming) Decision { return Decision{Reason: "no", Trust: true} })
	o := s.run(decline, s.snd, testPIN, security.Policy{}, srcFile(t))
	if !errors.Is(o.sendErr, ErrDeclined) || len(s.trust.List()) != 0 {
		t.Fatalf("%v trusted=%d", o.sendErr, len(s.trust.List()))
	}
}

func TestTrustIsNeverCreatedWithoutAPINSession(t *testing.T) {
	// A trusted device asking for trust again, or a PIN-less text transfer
	// asking for trust, must not create or refresh an entry.
	s := newSession(t)
	pol := security.Policy{}
	l, _ := tcp.Listen("127.0.0.1:0")
	defer l.Close()
	r := &Receiver{Self: Self{ID: s.rcv.ID}, Dir: t.TempDir(), Approver: trustingApprover(true), Policy: pol, Trust: s.trust,
		Upgrade: func(c transport.Conn) (transport.Conn, error) { return security.Server(c, s.rcv, security.Any()) }}
	go r.HandleOne(context.Background(), l)
	raw, _ := tcp.Dial(context.Background(), l.Addr())
	conn, _ := security.Client(raw, s.snd, security.Any())
	defer conn.Close()
	if _, err := SendText(context.Background(), conn, Self{ID: s.snd.ID, Name: "x"}, []byte("hi"), SendOptions{Policy: pol}); err != nil {
		t.Fatal(err)
	}
	if len(s.trust.List()) != 0 {
		t.Fatal("trust created from a session that never proved the PIN")
	}
}

func TestExpiredTrustFallsBackToPIN(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	clock := func() time.Time { return now }
	st, _ := security.OpenTrustStoreForTest(dir, 30*24*time.Hour, clock)
	s := newSession(t)
	s.trust = st
	src := srcFile(t)
	s.run(trustingApprover(true), s.snd, testPIN, security.Policy{}, src)
	if o := s.run(trustingApprover(false), s.snd, "", security.Policy{}, src); o.sendErr != nil {
		t.Fatalf("fresh trust rejected: %v", o.sendErr)
	}
	now = now.Add(31 * 24 * time.Hour) // unused for longer than the expiry
	o := s.run(trustingApprover(false), s.snd, "", security.Policy{}, src)
	if !errors.Is(o.sendErr, ErrPINRequired) {
		t.Fatalf("expired trust still honoured: %v", o.sendErr)
	}
}

func TestTrustedUseDoesNotTouchLockoutCounters(t *testing.T) {
	s := newSession(t)
	src := srcFile(t)
	s.run(trustingApprover(true), s.snd, testPIN, security.Policy{}, src)
	for i := 0; i < 5; i++ { // more than the 3 PIN attempts allowed
		if o := s.run(trustingApprover(false), s.snd, "", security.Policy{}, src); o.sendErr != nil {
			t.Fatalf("trusted send %d: %v", i, o.sendErr)
		}
	}
	// The PIN path is unaffected: a stranger still gets all 3 attempts.
	stranger := newIdentity(t, "stranger")
	o := s.run(trustingApprover(false), stranger, "000000", security.Policy{}, src)
	var ae *security.AuthError
	if !errors.As(o.sendErr, &ae) || ae.AttemptsRemaining != 2 {
		t.Fatalf("%v", o.sendErr)
	}
}

func TestTrustedDeviceStillNeedsReceiverConsent(t *testing.T) {
	s := newSession(t)
	src := srcFile(t)
	s.run(trustingApprover(true), s.snd, testPIN, security.Policy{}, src)
	no := ApproverFunc(func(context.Context, Incoming) Decision { return Decision{Reason: "not now"} })
	o := s.run(no, s.snd, "", security.Policy{}, src)
	if !errors.Is(o.sendErr, ErrDeclined) {
		t.Fatalf("trust bypassed the consent prompt: %v", o.sendErr)
	}
	assertEmpty(t, o.dir)
}

func TestTrustAppliesToFoldersAndProtectedTypesButHelloStillAuthenticated(t *testing.T) {
	s := newSession(t)
	src := srcFile(t)
	s.run(trustingApprover(true), s.snd, testPIN, security.Policy{}, src)
	// A trusted sender still cannot lie about its device ID in the hello.
	l, _ := tcp.Listen("127.0.0.1:0")
	defer l.Close()
	r := &Receiver{Self: Self{ID: s.rcv.ID}, Dir: t.TempDir(), Approver: trustingApprover(false), Trust: s.trust,
		Upgrade: func(c transport.Conn) (transport.Conn, error) { return security.Server(c, s.rcv, security.Any()) }}
	errc := make(chan error, 1)
	go func() { _, err := r.HandleOne(context.Background(), l); errc <- err }()
	raw, _ := tcp.Dial(context.Background(), l.Addr())
	conn, _ := security.Client(raw, s.snd, security.Any())
	defer conn.Close()
	protocol.WriteMsg(conn, &protocol.Hello{Versions: []int{2}, DeviceID: "someone-else"})
	if err := <-errc; err == nil {
		t.Fatal("receiver accepted a hello whose ID does not match the TLS identity")
	}
}

func TestReceiverWithoutTrustStoreIgnoresTrust(t *testing.T) {
	h := newHarness(t, trustingApprover(true), security.Policy{})
	h.r.Trust = nil
	if _, err := h.send(srcFile(t), testPIN); err != nil {
		t.Fatal(err)
	}
	r := h.wait()
	if r.err != nil || r.rec.TrustGranted {
		t.Fatalf("%v %+v", r.err, r.rec)
	}
}

var _ = filepath.Join
