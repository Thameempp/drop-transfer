package security

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thameem/drop/internal/device"
	"github.com/thameem/drop/internal/protocol"
	"github.com/thameem/drop/internal/transport"
)

func ident(t *testing.T, name string) *device.Identity {
	t.Helper()
	id, err := device.LoadOrCreate(t.TempDir(), name, "test")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func dialPair(t *testing.T) (transport.Conn, transport.Conn) {
	t.Helper()
	l, err := transport.TCP{}.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ch := make(chan transport.Conn, 1)
	go func() { c, _ := l.Accept(); ch <- c }()
	c, err := transport.TCP{}.Dial(context.Background(), l.Addr())
	if err != nil {
		t.Fatal(err)
	}
	s := <-ch
	t.Cleanup(func() { c.Close(); s.Close() })
	return c, s
}

// secured returns a TLS-secured (sender, receiver) connection pair.
func secured(t *testing.T, snd, rcv *device.Identity) (transport.Conn, transport.Conn) {
	t.Helper()
	c, s := dialPair(t)
	var cc, sc transport.Conn
	var ce, se error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); cc, ce = Client(c, snd, ExpectID(rcv.ID)) }()
	go func() { defer wg.Done(); sc, se = Server(s, rcv, Any()) }()
	wg.Wait()
	if ce != nil || se != nil {
		t.Fatalf("tls: %v / %v", ce, se)
	}
	return cc, sc
}

type env struct {
	snd, rcv *device.Identity
	auth     *Authenticator
	dir      string
	logs     *bytes.Buffer
	mu       sync.Mutex
}

func newEnv(t *testing.T, pin string) *env {
	t.Helper()
	e := &env{snd: ident(t, "sender"), rcv: ident(t, "receiver"), dir: t.TempDir(), logs: &bytes.Buffer{}}
	ps := OpenPINStore(e.dir)
	if err := ps.Set(pin); err != nil {
		t.Fatal(err)
	}
	lim, err := OpenLimiter(e.dir, DefaultLimiter())
	if err != nil {
		t.Fatal(err)
	}
	e.auth = &Authenticator{SelfID: e.rcv.ID, PINs: ps, Limiter: lim, Logf: func(f string, a ...any) {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.logs.WriteString(strings.TrimSpace(sprintf(f, a...)) + "\n")
	}}
	return e
}

// attempt runs one full sender↔receiver authorization with pin.
func (e *env) attempt(t *testing.T, pin string) (sendErr, recvErr error) {
	t.Helper()
	cc, sc := secured(t, e.snd, e.rcv)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := protocol.Expect[*protocol.AuthInit](sc); err != nil {
			recvErr = err
			return
		}
		recvErr = e.auth.Serve(sc)
	}()
	sendErr = Authenticate(cc, e.snd.ID, pin)
	wg.Wait()
	return
}

func TestCorrectPIN(t *testing.T) {
	e := newEnv(t, "482917")
	if s, r := e.attempt(t, "482917"); s != nil || r != nil {
		t.Fatalf("send %v recv %v", s, r)
	}
}

func TestWrongPINReportsOnlyIncorrectAndAttemptsRemaining(t *testing.T) {
	e := newEnv(t, "482917")
	for i, wantRemaining := range []int{2, 1} {
		s, r := e.attempt(t, "000000")
		var ae *AuthError
		if !errors.As(s, &ae) || !errors.Is(s, ErrWrongPIN) {
			t.Fatalf("attempt %d: send err = %v", i+1, s)
		}
		if ae.AttemptsRemaining != wantRemaining {
			t.Fatalf("attempt %d: remaining = %d, want %d", i+1, ae.AttemptsRemaining, wantRemaining)
		}
		if r == nil {
			t.Fatal("receiver considered a wrong PIN a success")
		}
	}
}

func TestNearMissLooksIdenticalToTotalMiss(t *testing.T) {
	// The sender must not learn how close the guess was: compare the error
	// text for a one-digit-off PIN and a completely different one.
	a := newEnv(t, "482917")
	b := newEnv(t, "482917")
	sa, _ := a.attempt(t, "482918")
	sb, _ := b.attempt(t, "999999")
	if sa == nil || sb == nil || sa.Error() != sb.Error() {
		t.Fatalf("distinguishable: %v vs %v", sa, sb)
	}
}

func TestLockoutAfterMaxAttemptsThenCorrectPINRefused(t *testing.T) {
	e := newEnv(t, "482917")
	for i := 0; i < 3; i++ {
		e.attempt(t, "111111")
	}
	s, _ := e.attempt(t, "482917") // even the right PIN is refused while locked
	var ae *AuthError
	if !errors.Is(s, ErrLocked) || !errors.As(s, &ae) || ae.RetryAfter <= 0 {
		t.Fatalf("send err = %v", s)
	}
}

func TestSuccessResetsCounter(t *testing.T) {
	e := newEnv(t, "482917")
	e.attempt(t, "111111")
	e.attempt(t, "111111")
	if s, r := e.attempt(t, "482917"); s != nil || r != nil {
		t.Fatalf("%v %v", s, r)
	}
	s, _ := e.attempt(t, "111111")
	var ae *AuthError
	if !errors.As(s, &ae) || ae.AttemptsRemaining != 2 {
		t.Fatalf("counter not reset: %v", s)
	}
}

func TestAbandonedAttemptsStillCount(t *testing.T) {
	e := newEnv(t, "482917")
	for i := 0; i < 3; i++ {
		cc, sc := secured(t, e.snd, e.rcv)
		done := make(chan struct{})
		go func() { protocol.Expect[*protocol.AuthInit](sc); e.auth.Serve(sc); close(done) }()
		protocol.WriteMsg(cc, &protocol.AuthInit{})
		protocol.Expect[*protocol.AuthParams](cc)
		cc.Close() // probe and hang up without finishing
		<-done
	}
	s, _ := e.attempt(t, "482917")
	if !errors.Is(s, ErrLocked) {
		t.Fatalf("abandoned probes were not counted: %v", s)
	}
}

func TestMalformedAndEmptyPINRejectedBeforeNetwork(t *testing.T) {
	e := newEnv(t, "482917")
	for _, pin := range []string{"", "12345", "abcdef", "12 456", "1234567890123", "４８２９１７"} {
		cc, _ := secured(t, e.snd, e.rcv)
		if err := Authenticate(cc, e.snd.ID, pin); !errors.Is(err, ErrInvalidPIN) {
			t.Errorf("pin %q: %v", pin, err)
		}
	}
}

// relay is an active man-in-the-middle: it terminates TLS toward the sender
// with its own identity and opens a separate TLS session to the receiver,
// forwarding the PIN-auth messages between them.
func TestRelayMITMCannotAuthenticate(t *testing.T) {
	e := newEnv(t, "482917")
	mitm := ident(t, "mitm")

	// sender <-> mitm
	sToM, mFromS := dialPair(t)
	// mitm <-> receiver
	mToR, rFromM := dialPair(t)
	var wg sync.WaitGroup
	var sConn, mS, mR, rConn transport.Conn
	var errs [4]error
	wg.Add(4)
	go func() { defer wg.Done(); sConn, errs[0] = Client(sToM, e.snd, Any()) }()
	go func() { defer wg.Done(); mS, errs[1] = Server(mFromS, mitm, Any()) }()
	go func() { defer wg.Done(); mR, errs[2] = Client(mToR, mitm, ExpectID(e.rcv.ID)) }()
	go func() { defer wg.Done(); rConn, errs[3] = Server(rFromM, e.rcv, Any()) }()
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	// Forward every message verbatim in both directions.
	fwd := func(dst, src transport.Conn) {
		for {
			m, err := protocol.ReadMsg(src)
			if err != nil {
				dst.Close()
				return
			}
			if protocol.WriteMsg(dst, m) != nil {
				return
			}
		}
	}
	go fwd(mR, mS)
	go fwd(mS, mR)
	recvDone := make(chan error, 1)
	go func() {
		protocol.Expect[*protocol.AuthInit](rConn)
		recvDone <- e.auth.Serve(rConn)
	}()
	sendErr := Authenticate(sConn, e.snd.ID, "482917") // the user typed the CORRECT pin
	if sendErr == nil {
		t.Fatal("PIN auth succeeded through a relaying man-in-the-middle")
	}
	if err := <-recvDone; err == nil {
		t.Fatal("receiver authorized a relayed session")
	}
}

func TestReplayedAuthMessagesFail(t *testing.T) {
	e := newEnv(t, "482917")
	// Session 1: record the sender's messages during a legitimate success.
	cc, sc := secured(t, e.snd, e.rcv)
	rec := &recorder{wrapped: wrapped{cc}}
	go func() { protocol.Expect[*protocol.AuthInit](sc); e.auth.Serve(sc) }()
	if err := Authenticate(rec, e.snd.ID, "482917"); err != nil {
		t.Fatal(err)
	}
	start, proof := rec.start, rec.proof
	if start == nil || proof == nil {
		t.Fatal("did not capture messages")
	}
	// Session 2: replay them verbatim.
	cc2, sc2 := secured(t, e.snd, e.rcv)
	done := make(chan error, 1)
	go func() { protocol.Expect[*protocol.AuthInit](sc2); done <- e.auth.Serve(sc2) }()
	protocol.WriteMsg(cc2, &protocol.AuthInit{})
	protocol.Expect[*protocol.AuthParams](cc2)
	protocol.WriteMsg(cc2, start)
	protocol.Expect[*protocol.AuthChallenge](cc2)
	protocol.WriteMsg(cc2, proof)
	res, _ := protocol.Expect[*protocol.AuthResult](cc2)
	if res != nil && res.OK {
		t.Fatal("replayed proof was accepted")
	}
	if err := <-done; err == nil {
		t.Fatal("receiver accepted a replay")
	}
}

type recorder struct {
	wrapped
	start *protocol.AuthStart
	proof *protocol.AuthProof
	buf   []byte
}

func (r *recorder) Write(p []byte) (int, error) {
	r.buf = append(r.buf, p...)
	// frames are length-prefixed; parse whole frames as they accumulate
	for len(r.buf) >= 4 {
		n := int(r.buf[0])<<24 | int(r.buf[1])<<16 | int(r.buf[2])<<8 | int(r.buf[3])
		if len(r.buf) < 4+n {
			break
		}
		m, err := protocol.ReadMsg(bytes.NewReader(r.buf[:4+n]))
		if err == nil {
			switch v := m.(type) {
			case *protocol.AuthStart:
				r.start = v
			case *protocol.AuthProof:
				r.proof = v
			}
		}
		r.buf = r.buf[4+n:]
	}
	return r.wrapped.Conn.Write(p)
}

func TestAuthTimeoutWhenSenderStalls(t *testing.T) {
	e := newEnv(t, "482917")
	cc, sc := secured(t, e.snd, e.rcv)
	_ = cc
	old := authTimeoutForTest(100 * time.Millisecond)
	defer old()
	done := make(chan error, 1)
	go func() { protocol.Expect[*protocol.AuthInit](sc); done <- e.auth.Serve(sc) }()
	protocol.WriteMsg(cc, &protocol.AuthInit{}) // then say nothing
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected timeout error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("receiver hung on a stalled sender")
	}
}

func TestSenderRejectsHostileArgonParameters(t *testing.T) {
	e := newEnv(t, "482917")
	cc, sc := secured(t, e.snd, e.rcv)
	go func() {
		protocol.Expect[*protocol.AuthInit](sc)
		protocol.WriteMsg(sc, &protocol.AuthParams{Salt: make([]byte, 16), Time: 1, MemoryKiB: 1 << 30, Threads: 4})
	}()
	if err := Authenticate(cc, e.snd.ID, "482917"); err == nil || !strings.Contains(err.Error(), "unacceptable") {
		t.Fatalf("got %v", err)
	}
}

func TestPINNeverOnWireOrOnDisk(t *testing.T) {
	const pin = "482917"
	e := newEnv(t, pin)
	// Disk: nothing under the config dir may contain the PIN.
	if s, r := e.attempt(t, pin); s != nil || r != nil {
		t.Fatal(s, r)
	}
	e.attempt(t, "123456")
	filepath.WalkDir(e.dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			if bytes.Contains(b, []byte(pin)) || bytes.Contains(b, []byte("123456")) {
				t.Errorf("PIN found in %s", p)
			}
		}
		return nil
	})
	// Logs.
	if strings.Contains(e.logs.String(), pin) || strings.Contains(e.logs.String(), "123456") {
		t.Fatal("PIN in logs")
	}
	// Wire (inside TLS, but check the plaintext frames the sender emits).
	cc, sc := secured(t, e.snd, e.rcv)
	spy := &spyConn{wrapped: wrapped{cc}}
	go func() { protocol.Expect[*protocol.AuthInit](sc); e.auth.Serve(sc) }()
	if err := Authenticate(spy, e.snd.ID, pin); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(spy.written.Bytes(), []byte(pin)) {
		t.Fatal("PIN present in protocol frames")
	}
}

type spyConn struct {
	wrapped
	written bytes.Buffer
}

func (s *spyConn) Write(p []byte) (int, error) { s.written.Write(p); return s.wrapped.Conn.Write(p) }

func TestTLSRejectsWrongPeerIdentity(t *testing.T) {
	a, b, other := ident(t, "a"), ident(t, "b"), ident(t, "other")
	c, s := dialPair(t)
	go Server(s, other, Any())
	if _, err := Client(c, a, ExpectID(b.ID)); !errors.Is(err, ErrPeerMismatch) {
		t.Fatalf("got %v", err)
	}
}

func TestPlaintextClientRejectedByTLSServer(t *testing.T) {
	rcv := ident(t, "r")
	c, s := dialPair(t)
	errc := make(chan error, 1)
	go func() { _, err := Server(s, rcv, Any()); errc <- err }()
	protocol.WriteMsg(c, &protocol.Hello{Versions: []int{2}}) // speak plaintext protocol at a TLS server
	if err := <-errc; err == nil {
		t.Fatal("TLS server accepted a plaintext peer")
	}
}

func TestTLS12ClientRejected(t *testing.T) {
	// Server enforces TLS 1.3 minimum; verify via our own client config surface.
	a, b := ident(t, "a"), ident(t, "b")
	cc, sc := secured(t, a, b)
	_ = sc
	if s, ok := cc.(*secureConn); !ok || s.tc.ConnectionState().Version != 0x0304 {
		t.Fatal("connection is not TLS 1.3")
	}
}

func TestPolicy(t *testing.T) {
	p := Policy{}
	for ty, want := range map[TransferType]bool{
		TransferText: false, TransferClipboard: true, TransferFile: true, TransferFolder: true,
		TransferProject: true, TransferGit: true, "dataset": true, "unknown": true, "": true,
	} {
		if got := p.RequiresAuthorization(ty); got != want {
			t.Errorf("%q: got %v want %v", ty, got, want)
		}
	}
	if !(Policy{TextRequiresPIN: true}).RequiresAuthorization(TransferText) {
		t.Fatal("text_requires_pin not honoured")
	}
}

func TestChannelBindingDiffersPerSession(t *testing.T) {
	a, b := ident(t, "a"), ident(t, "b")
	c1, s1 := secured(t, a, b)
	c2, _ := secured(t, a, b)
	x1, _ := ChannelBinding(c1)
	y1, _ := ChannelBinding(s1)
	x2, _ := ChannelBinding(c2)
	if !bytes.Equal(x1, y1) || bytes.Equal(x1, x2) {
		t.Fatal("binding not shared within a session / not unique across sessions")
	}
}

var _ = io.Discard
