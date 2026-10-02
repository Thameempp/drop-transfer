package transfer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thameem/drop/internal/device"
	"github.com/thameem/drop/internal/protocol"
	"github.com/thameem/drop/internal/security"
	"github.com/thameem/drop/internal/transport"
)

const testPIN = "482917"

func init() { security.ReduceKDFCostForTests() }

var tcp = transport.TCP{}

func acceptAll(c Conflict) Approver {
	return ApproverFunc(func(context.Context, Incoming) Decision { return Decision{Accept: true, Conflict: c} })
}

func newIdentity(t testing.TB, name string) *device.Identity {
	t.Helper()
	id, err := device.LoadOrCreate(t.TempDir(), name, "test")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// harness is a real receiver (TLS + PIN auth) handling exactly one connection.
type harness struct {
	t     testing.TB
	l     transport.Listener
	r     *Receiver
	dir   string
	rcv   *device.Identity
	snd   *device.Identity
	done  chan result
	logs  *syncBuf
	texts chan []byte
	trust *security.TrustStore
}

type result struct {
	rec *Received
	err error
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) add(l string) { s.mu.Lock(); s.b.WriteString(l + "\n"); s.mu.Unlock() }
func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newHarness(t *testing.T, ap Approver, policy security.Policy) *harness {
	return newHarnessTB(t, ap, policy)
}

func newHarnessB(b *testing.B) *harness {
	return newHarnessTB(b, acceptAll(ConflictRename), security.Policy{})
}

func (h *harness) dialB(b *testing.B) transport.Conn { return h.dial() }

func newHarnessTB(t testing.TB, ap Approver, policy security.Policy) *harness {
	t.Helper()
	l, err := tcp.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	h := &harness{t: t, l: l, dir: t.TempDir(), rcv: newIdentity(t, "receiver"), snd: newIdentity(t, "sender"),
		done: make(chan result, 1), logs: &syncBuf{}, texts: make(chan []byte, 1)}
	cfgDir := t.TempDir()
	pins := security.OpenPINStore(cfgDir)
	if err := pins.Set(testPIN); err != nil {
		t.Fatal(err)
	}
	lim, _ := security.OpenLimiter(cfgDir, security.DefaultLimiter())
	logf := func(f string, a ...any) { h.logs.add(strings.TrimSpace(sprintf(f, a...))) }
	h.trust, _ = security.OpenTrustStore(t.TempDir(), security.DefaultTrustExpiry)
	h.r = &Receiver{
		Self: Self{ID: h.rcv.ID, Name: "recv", OS: "test"}, Dir: h.dir, Approver: ap, Policy: policy, Logf: logf, Trust: h.trust,
		Upgrade: func(c transport.Conn) (transport.Conn, error) { return security.Server(c, h.rcv, security.Any()) },
		Auth:    &security.Authenticator{SelfID: h.rcv.ID, PINs: pins, Limiter: lim, Logf: logf},
		OnText:  func(_ Incoming, d []byte) { h.texts <- d },
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		rec, err := h.r.HandleOne(ctx, l)
		h.done <- result{rec, err}
	}()
	return h
}

func (h *harness) dial() transport.Conn {
	h.t.Helper()
	raw, err := tcp.Dial(context.Background(), h.l.Addr())
	if err != nil {
		h.t.Fatal(err)
	}
	conn, err := security.Client(raw, h.snd, security.ExpectID(h.rcv.ID))
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { conn.Close() })
	return conn
}

func (h *harness) opts(pin string) SendOptions {
	return SendOptions{PIN: pin, Logf: func(f string, a ...any) { h.logs.add(strings.TrimSpace(sprintf(f, a...))) }}
}

func (h *harness) selfS() Self { return Self{ID: h.snd.ID, Name: "send", OS: "test"} }

func (h *harness) send(path, pin string) (*SendResult, error) {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	o := h.opts(pin)
	o.Policy = h.r.Policy
	return SendFile(ctx, h.dial(), h.selfS(), path, o)
}

func (h *harness) wait() result {
	h.t.Helper()
	select {
	case r := <-h.done:
		return r
	case <-time.After(60 * time.Second):
		h.t.Fatal("receiver timed out")
		return result{}
	}
}

// authedRaw returns a TLS connection that has completed hello and PIN auth, for
// tests that then misbehave at the request layer like a hostile (but
// authorized) peer.
func (h *harness) authedRaw() transport.Conn {
	h.t.Helper()
	conn := h.dial()
	rawHello(h.t, conn, h.snd)
	if err := security.Authenticate(conn, h.snd.ID, testPIN); err != nil {
		h.t.Fatal(err)
	}
	return conn
}

func rawHello(t testing.TB, conn transport.Conn, id *device.Identity) {
	t.Helper()
	protocol.WriteMsg(conn, &protocol.Hello{Versions: protocol.SupportedVersions, DeviceID: id.ID, DeviceName: "evil"})
	if _, err := protocol.Expect[*protocol.HelloAck](conn); err != nil {
		t.Fatal(err)
	}
}

func sprintf(f string, a ...any) string {
	return strings.TrimSpace(strings.ReplaceAll(fmtSprintf(f, a...), "\n", " "))
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func assertEmpty(t *testing.T, dir string) {
	t.Helper()
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("destination not empty: %v", ents)
	}
}

func TestAuthenticatedTransferRoundTrip(t *testing.T) {
	big := make([]byte, 24<<20+13)
	rand.Read(big)
	cases := map[string][]byte{
		"main.py":          []byte("print('hi')\n"),
		"empty.txt":        {},
		"my file (v2).txt": []byte("spaces and parens"),
		"données-日本語.txt":  []byte("unicode"),
		"big.bin":          big,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
			res, err := h.send(writeFile(t, name, data), testPIN)
			if err != nil {
				t.Fatalf("send: %v", err)
			}
			r := h.wait()
			if r.err != nil {
				t.Fatalf("receive: %v", r.err)
			}
			if got, _ := os.ReadFile(r.rec.Path); !bytes.Equal(got, data) {
				t.Fatal("content mismatch")
			}
			if res.SHA256 != sum(data) || r.rec.SHA256 != res.SHA256 {
				t.Fatal("hash mismatch")
			}
			if !r.rec.In.Authorized || r.rec.In.From.ID != h.snd.ID || res.Peer.ID != h.rcv.ID {
				t.Fatalf("identities/authorization not recorded: %+v", r.rec.In)
			}
			ents, _ := os.ReadDir(h.dir)
			for _, e := range ents {
				if strings.HasPrefix(e.Name(), ".drop-partial") {
					t.Errorf("leftover %s", e.Name())
				}
			}
		})
	}
}

func TestWrongPINWritesNothing(t *testing.T) {
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	_, err := h.send(writeFile(t, "a.txt", []byte("x")), "000000")
	var ae *security.AuthError
	if !errors.As(err, &ae) || !errors.Is(err, security.ErrWrongPIN) || ae.AttemptsRemaining != 2 {
		t.Fatalf("err = %v", err)
	}
	h.wait()
	assertEmpty(t, h.dir)
}

func TestFileWithoutAuthorizationIsRefused(t *testing.T) {
	h := newHarness(t, acceptAll(ConflictReplace), security.Policy{})
	conn := h.dial()
	rawHello(t, conn, h.snd)
	data := []byte("evil payload")
	protocol.WriteMsg(conn, &protocol.TransferRequest{TransferID: "1", Mode: protocol.ModeFile, Name: "pwn.sh", Size: int64(len(data)), SHA256: sum(data)})
	resp, err := protocol.Expect[*protocol.TransferResponse](conn)
	if err != nil || resp.Accept {
		t.Fatalf("unauthorized file was accepted: %+v %v", resp, err)
	}
	if r := h.wait(); !errors.Is(r.err, ErrUnauthorized) {
		t.Fatalf("receiver err = %v", r.err)
	}
	assertEmpty(t, h.dir)
}

func TestSenderWithoutPINCannotSendProtectedFile(t *testing.T) {
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	if _, err := h.send(writeFile(t, "a.txt", []byte("x")), ""); !errors.Is(err, ErrPINRequired) {
		t.Fatalf("err = %v", err)
	}
}

func sendText(t *testing.T, h *harness, text, pin string) error {
	t.Helper()
	o := h.opts(pin)
	o.Policy = h.r.Policy
	_, err := SendText(context.Background(), h.dial(), h.selfS(), []byte(text), o)
	return err
}

func TestTextWithoutPINByDefault(t *testing.T) {
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	if err := sendText(t, h, "hello from drop\n", ""); err != nil {
		t.Fatal(err)
	}
	if got := <-h.texts; string(got) != "hello from drop\n" {
		t.Fatalf("%q", got)
	}
	if r := h.wait(); r.err != nil || r.rec.In.Authorized {
		t.Fatalf("%v", r.err)
	}
	assertEmpty(t, h.dir) // text never touches disk
}

func TestTextRequiresPINWhenConfigured(t *testing.T) {
	pol := security.Policy{TextRequiresPIN: true}
	h := newHarness(t, acceptAll(ConflictRename), pol)
	if err := sendText(t, h, "secret", ""); !errors.Is(err, ErrPINRequired) {
		t.Fatalf("err = %v", err)
	}
	// And a hostile client that skips auth is refused by the receiver itself.
	h2 := newHarness(t, acceptAll(ConflictRename), pol)
	conn := h2.dial()
	rawHello(t, conn, h2.snd)
	protocol.WriteMsg(conn, &protocol.TransferRequest{Mode: protocol.ModeText, Size: 3, SHA256: sum([]byte("abc"))})
	if resp, _ := protocol.Expect[*protocol.TransferResponse](conn); resp == nil || resp.Accept {
		t.Fatal("receiver accepted unauthenticated text despite text_requires_pin")
	}
	// With the PIN it works.
	h3 := newHarness(t, acceptAll(ConflictRename), pol)
	if err := sendText(t, h3, "ok", testPIN); err != nil {
		t.Fatal(err)
	}
}

func TestTextTooLargeRejected(t *testing.T) {
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	conn := h.dial()
	rawHello(t, conn, h.snd)
	protocol.WriteMsg(conn, &protocol.TransferRequest{Mode: protocol.ModeText, Size: MaxTextSize + 1, SHA256: sum(nil)})
	if r := h.wait(); r.err == nil {
		t.Fatal("oversized text accepted")
	}
}

func TestCorruptedTextDetected(t *testing.T) {
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	conn := h.dial()
	rawHello(t, conn, h.snd)
	protocol.WriteMsg(conn, &protocol.TransferRequest{Mode: protocol.ModeText, Size: 5, SHA256: sum([]byte("hello"))})
	protocol.Expect[*protocol.TransferResponse](conn)
	conn.Write([]byte("jello"))
	res, _ := protocol.Expect[*protocol.TransferResult](conn)
	if res == nil || res.OK {
		t.Fatal("corrupted text accepted")
	}
	select {
	case <-h.texts:
		t.Fatal("corrupted text was delivered")
	default:
	}
}

func TestDuplicateNameIsRenamedNotOverwritten(t *testing.T) {
	src := writeFile(t, "a.txt", []byte("new"))
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	existing := filepath.Join(h.dir, "a.txt")
	os.WriteFile(existing, []byte("old"), 0o644)
	if _, err := h.send(src, testPIN); err != nil {
		t.Fatal(err)
	}
	r := h.wait()
	if b, _ := os.ReadFile(existing); string(b) != "old" || filepath.Base(r.rec.Path) != "a (1).txt" {
		t.Fatalf("existing modified or wrong name: %s", r.rec.Path)
	}
}

func TestReplaceConflict(t *testing.T) {
	src := writeFile(t, "a.txt", []byte("new"))
	h := newHarness(t, acceptAll(ConflictReplace), security.Policy{})
	existing := filepath.Join(h.dir, "a.txt")
	os.WriteFile(existing, []byte("old"), 0o644)
	if _, err := h.send(src, testPIN); err != nil {
		t.Fatal(err)
	}
	h.wait()
	if b, _ := os.ReadFile(existing); string(b) != "new" {
		t.Fatal("not replaced")
	}
}

func TestDeclined(t *testing.T) {
	h := newHarness(t, ApproverFunc(func(context.Context, Incoming) Decision { return Decision{Reason: "not now"} }), security.Policy{})
	if _, err := h.send(writeFile(t, "a.txt", []byte("x")), testPIN); !errors.Is(err, ErrDeclined) {
		t.Fatalf("got %v", err)
	}
	h.wait()
	assertEmpty(t, h.dir)
}

func TestSendDirectoryAndMissingFileRejected(t *testing.T) {
	for name, path := range map[string]string{"directory": t.TempDir(), "missing": "/no/such/file"} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
			if _, err := SendFile(context.Background(), h.dial(), h.selfS(), path, h.opts(testPIN)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestPathTraversalNamesRejectedEvenWhenAuthorized(t *testing.T) {
	for _, name := range []string{"../evil", "..\\evil", "/etc/passwd", "a/../../b", "C:\\x", ".."} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, acceptAll(ConflictReplace), security.Policy{})
			conn := h.authedRaw()
			protocol.WriteMsg(conn, &protocol.TransferRequest{Mode: protocol.ModeFile, Name: name, Size: 1, SHA256: sum([]byte("x"))})
			if r := h.wait(); r.err == nil {
				t.Fatal("unsafe name accepted")
			}
			assertEmpty(t, h.dir)
			if _, err := os.Stat(filepath.Join(filepath.Dir(h.dir), "evil")); err == nil {
				t.Fatal("file escaped destination")
			}
		})
	}
}

func TestCorruptedFileDataFailsVerification(t *testing.T) {
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	conn := h.authedRaw()
	good := []byte("hello world")
	protocol.WriteMsg(conn, &protocol.TransferRequest{Mode: protocol.ModeFile, Name: "a.txt", Size: int64(len(good)), SHA256: sum(good)})
	if resp, err := protocol.Expect[*protocol.TransferResponse](conn); err != nil || !resp.Accept {
		t.Fatalf("%v %v", resp, err)
	}
	conn.Write([]byte("hello_world"))
	res, err := protocol.Expect[*protocol.TransferResult](conn)
	if err != nil || res.OK {
		t.Fatalf("success reported on corrupted data: %+v %v", res, err)
	}
	if r := h.wait(); !errors.Is(r.err, ErrVerification) {
		t.Fatalf("%v", r.err)
	}
	assertEmpty(t, h.dir)
}

func TestTruncatedStreamCleansUp(t *testing.T) {
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	conn := h.authedRaw()
	protocol.WriteMsg(conn, &protocol.TransferRequest{Mode: protocol.ModeFile, Name: "a.txt", Size: 100, SHA256: sum([]byte("x"))})
	protocol.Expect[*protocol.TransferResponse](conn)
	conn.Write([]byte("only a few bytes"))
	conn.Close()
	if r := h.wait(); r.err == nil {
		t.Fatal("expected error")
	}
	assertEmpty(t, h.dir)
}

func TestInvalidRequests(t *testing.T) {
	cases := map[string]*protocol.TransferRequest{
		"negative size": {Mode: protocol.ModeFile, Name: "a", Size: -1, SHA256: sum(nil)},
		"bad hash":      {Mode: protocol.ModeFile, Name: "a", Size: 1, SHA256: "zz"},
		"bad mode":      {Mode: "dir", Name: "a", Size: 1, SHA256: sum(nil)},
		"clipboard":     {Mode: "clipboard", Size: 1, SHA256: sum(nil)}, // not implemented: must not be accepted as anything weaker
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
			protocol.WriteMsg(h.authedRaw(), req)
			if r := h.wait(); r.err == nil {
				t.Fatal("expected error")
			}
			assertEmpty(t, h.dir)
		})
	}
}

func TestPlaintextClientIsRejected(t *testing.T) {
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	raw, _ := tcp.Dial(context.Background(), h.l.Addr())
	defer raw.Close()
	protocol.WriteMsg(raw, &protocol.Hello{Versions: []int{2}, DeviceID: "x"})
	if r := h.wait(); r.err == nil {
		t.Fatal("receiver talked to a plaintext peer")
	}
	assertEmpty(t, h.dir)
}

func TestReceiverRefusesToRunWithoutTLS(t *testing.T) {
	l, _ := tcp.Listen("127.0.0.1:0")
	defer l.Close()
	r := &Receiver{Dir: t.TempDir(), Approver: acceptAll(ConflictRename)}
	if err := r.Serve(context.Background(), l); err == nil {
		t.Fatal("Serve ran without an Upgrade")
	}
	if _, err := r.HandleOne(context.Background(), l); err == nil {
		t.Fatal("HandleOne ran without an Upgrade")
	}
}

func TestSenderRefusesPlaintextConnection(t *testing.T) {
	l, _ := tcp.Listen("127.0.0.1:0")
	defer l.Close()
	raw, _ := tcp.Dial(context.Background(), l.Addr())
	defer raw.Close()
	_, err := SendFile(context.Background(), raw, Self{}, writeFile(t, "a", []byte("x")), SendOptions{PIN: testPIN})
	if err == nil || !strings.Contains(err.Error(), "not authenticated and encrypted") {
		t.Fatalf("err = %v", err)
	}
}

func TestIncompatibleProtocolVersion(t *testing.T) {
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	conn := h.dial()
	protocol.WriteMsg(conn, &protocol.Hello{Versions: []int{1}, DeviceID: h.snd.ID})
	if _, err := protocol.Expect[*protocol.HelloAck](conn); err == nil {
		t.Fatal("v1 peer accepted")
	}
	h.wait()
}

func TestSpoofedDeviceIDInHelloRejected(t *testing.T) {
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	conn := h.dial()
	protocol.WriteMsg(conn, &protocol.Hello{Versions: []int{2}, DeviceID: "someone-else"})
	if r := h.wait(); r.err == nil {
		t.Fatal("claimed ID not checked against the TLS identity")
	}
}

func TestSenderCancelUnblocks(t *testing.T) {
	h := newHarness(t, ApproverFunc(func(ctx context.Context, _ Incoming) Decision { <-ctx.Done(); return Decision{} }), security.Policy{})
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	_, err := SendFile(ctx, h.dial(), h.selfS(), writeFile(t, "a", []byte("x")), h.opts(testPIN))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

func TestProgressReported(t *testing.T) {
	data := make([]byte, 1<<20)
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	var last, total int64
	o := h.opts(testPIN)
	o.Progress = func(d, t int64) { last, total = d, t }
	if _, err := SendFile(context.Background(), h.dial(), h.selfS(), writeFile(t, "p.bin", data), o); err != nil {
		t.Fatal(err)
	}
	h.wait()
	if last != int64(len(data)) || total != last {
		t.Fatalf("progress ended at %d/%d", last, total)
	}
}

func TestLogsNeverContainPINOrFileContents(t *testing.T) {
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	if _, err := h.send(writeFile(t, "a.txt", []byte("SENSITIVE-FILE-CONTENT")), testPIN); err != nil {
		t.Fatal(err)
	}
	h.wait()
	logs := h.logs.String()
	if strings.Contains(logs, testPIN) || strings.Contains(logs, "SENSITIVE-FILE-CONTENT") {
		t.Fatalf("secret in logs:\n%s", logs)
	}
	for _, want := range []string{"[auth] authentication succeeded", "[transfer] secure channel established"} {
		if !strings.Contains(logs, want) {
			t.Errorf("missing log %q in:\n%s", want, logs)
		}
	}
}

func TestApproverCanRedirectOneTransfer(t *testing.T) {
	other := t.TempDir()
	ap := ApproverFunc(func(context.Context, Incoming) Decision {
		return Decision{Accept: true, Conflict: ConflictRename, Dir: other}
	})
	h := newHarness(t, ap, security.Policy{})
	if _, err := h.send(writeFile(t, "a.txt", []byte("hello")), testPIN); err != nil {
		t.Fatalf("send: %v", err)
	}
	r := h.wait()
	if r.err != nil {
		t.Fatal(r.err)
	}
	if filepath.Dir(r.rec.Path) != other {
		t.Fatalf("saved to %s, want %s", r.rec.Path, other)
	}
	assertEmpty(t, h.dir)
}
