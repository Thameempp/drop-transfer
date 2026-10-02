package transfer

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/thameem/drop/internal/device"
	"github.com/thameem/drop/internal/filesystem"
	"github.com/thameem/drop/internal/protocol"
	"github.com/thameem/drop/internal/security"
	"github.com/thameem/drop/internal/transport"
)

// Incoming describes a request awaiting the user's decision.
type Incoming struct {
	From Peer
	Addr string
	Name string // already validated by filesystem.SafeName (empty for text)
	Size int64
	Type security.TransferType
	// Files and Dirs summarise a folder transfer (zero otherwise).
	Files, Dirs int
	// Authorized is true when the sender is allowed to send protected content:
	// it proved knowledge of the Drop PIN on this connection, or it is a
	// trusted device. Text may be accepted without it (see security.Policy).
	Authorized bool
	// AuthMethod is "pin", "trusted", or "" when not authorized.
	AuthMethod string
	// Fingerprint identifies the sender's key, for display when offering trust.
	Fingerprint string
	// KeyID is the device ID derived from the sender's TLS-verified key (not the
	// name it claims). Empty if the connection carried no key.
	KeyID string
}

// Conflict says what to do when the destination name already exists.
type Conflict int

const (
	// ConflictRename keeps the existing file and saves as "name (1).ext". Zero value, so it is the safe default.
	ConflictRename Conflict = iota
	ConflictReplace
)

// Decision is an Approver's answer.
type Decision struct {
	Accept   bool
	Reason   string // shown to the sender on decline
	Conflict Conflict
	// Trust asks the receiver to remember the sender as a trusted device after
	// this transfer verifies. Only honoured for PIN-authorized senders.
	Trust bool
	// Dir overrides Receiver.Dir for this transfer only. Empty means Receiver.Dir.
	Dir string
}

// Approver decides whether to accept an incoming transfer. It may block on user input.
type Approver interface {
	Approve(ctx context.Context, in Incoming) Decision
}

// ApproverFunc adapts a function to Approver.
type ApproverFunc func(ctx context.Context, in Incoming) Decision

func (f ApproverFunc) Approve(ctx context.Context, in Incoming) Decision { return f(ctx, in) }

// Received describes a finished, verified file.
type Received struct {
	In     Incoming
	Path   string
	SHA256 string
	// TrustGranted is true if the sender was added to the trusted devices.
	TrustGranted bool
}

// Receiver accepts transfers into Dir.
type Receiver struct {
	Self     Self
	Dir      string
	Approver Approver
	// KeepAwake, if set, is called when a connection arrives and its release when
	// the connection is done, so the machine does not sleep mid-transfer.
	KeepAwake func() (release func())
	// OnProgress is optional. It is only called for accepted transfers.
	OnProgress func(in Incoming, done, total int64)
	// Upgrade secures a freshly accepted connection (TLS) before any protocol
	// message is read. REQUIRED: there is no plaintext mode. The returned
	// connection must be transport.Peered.
	Upgrade func(transport.Conn) (transport.Conn, error)
	// Auth verifies the Drop PIN. REQUIRED when Policy requires authorization
	// for any transfer type that can arrive.
	Auth *security.Authenticator
	// Policy decides which transfer types need the PIN.
	Policy security.Policy
	// Trust lets previously trusted devices skip the PIN. Optional: nil
	// disables trusted devices entirely.
	Trust *security.TrustStore
	// OnFile is called as each file of an accepted folder transfer starts.
	OnFile func(in Incoming, index, count int, path string)
	// OnText receives accepted, verified plain text. Text is never written to disk.
	OnText func(in Incoming, data []byte)
	// Logf receives safe, secret-free diagnostics. Optional.
	Logf func(format string, args ...any)
	// OnError is called for connections that failed before a transfer request
	// was read (failed secure handshake, bad hello, ...). Optional.
	OnError func(addr string, err error)
	// OnResult is called once per connection that reached the request stage
	// (err == nil means a verified file was stored). Optional.
	OnResult func(r *Received, in *Incoming, err error)

	mu sync.Mutex // serialises prompts and writes: one transfer at a time
}

// MaxTextSize bounds a plain-text transfer; it is buffered in memory.
const MaxTextSize = 1 << 20

var errNoUpgrade = errors.New("receiver misconfigured: a secure Upgrade is required, plaintext is not supported")

// Serve accepts connections until ctx is cancelled or the listener fails.
func (r *Receiver) Serve(ctx context.Context, l transport.Listener) error {
	if r.Upgrade == nil {
		return errNoUpgrade
	}
	stop := closeOnCancel(ctx, l)
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return fmt.Errorf("accept: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn.Close()
			r.handle(ctx, conn)
		}()
	}
}

// HandleOne accepts a single connection and returns its outcome.
func (r *Receiver) HandleOne(ctx context.Context, l transport.Listener) (*Received, error) {
	if r.Upgrade == nil {
		return nil, errNoUpgrade
	}
	stop := closeOnCancel(ctx, l)
	defer stop()
	conn, err := l.Accept()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("accept: %w", err)
	}
	defer conn.Close()
	return r.handle(ctx, conn)
}

func (r *Receiver) handle(ctx context.Context, conn transport.Conn) (rec *Received, err error) {
	defer closeOnCancel(ctx, conn)()
	if r.KeepAwake != nil {
		defer r.KeepAwake()()
	}
	addr := conn.RemoteAddr()
	var in *Incoming
	secured := false
	defer func() {
		if in == nil && err != nil && r.OnError != nil {
			r.OnError(addr, err)
		}
		if err != nil && secured && !protocol.IsRemote(err) {
			// Best effort: tell the peer why, unless it was the one who failed.
			_ = protocol.WriteMsg(conn, &protocol.Error{Message: publicMessage(err)})
		}
		if r.OnResult != nil && in != nil {
			r.OnResult(rec, in, err)
		}
	}()

	up, uerr := r.Upgrade(conn)
	if uerr != nil {
		return nil, uerr
	}
	conn, secured = up, true
	defer closeOnCancel(ctx, conn)()
	defer conn.Close()
	peered, ok := conn.(transport.Peered)
	if !ok {
		return nil, errNoUpgrade
	}
	r.logf("[transfer] secure channel established")

	hello, err := protocol.Expect[*protocol.Hello](conn)
	if err != nil {
		return nil, fmt.Errorf("handshake with %s: %w", conn.RemoteAddr(), err)
	}
	if hello.DeviceID != peered.PeerID() {
		return nil, fmt.Errorf("peer claimed device ID %q but authenticated as %q", hello.DeviceID, peered.PeerID())
	}
	ver, err := protocol.Negotiate(protocol.SupportedVersions, hello.Versions)
	if err != nil {
		return nil, err
	}
	peerKey, _ := security.PeerKey(conn)
	trusted := r.Trust != nil && len(peerKey) > 0 && r.Trust.IsTrusted(peerKey)
	if err := protocol.WriteMsg(conn, &protocol.HelloAck{Version: ver, DeviceID: r.Self.ID, DeviceName: r.Self.Name, OS: r.Self.OS, Trusted: trusted}); err != nil {
		return nil, err
	}
	peer := Peer{ID: peered.PeerID(), Name: hello.DeviceName}

	// The sender may authorize with the PIN first. Nothing is written to disk
	// until a request arrives, and protected requests are refused below unless
	// authorized.
	// Unauthenticated peers get a bounded window to finish this phase.
	conn.SetDeadline(time.Now().Add(preRequestTimeout))
	authorized, method := false, ""
	if trusted {
		authorized, method = true, "trusted"
		r.logf("[auth] trusted device recognized")
	}
	var req *protocol.TransferRequest
	for req == nil {
		m, err := protocol.ReadMsg(conn)
		if err != nil {
			return nil, fmt.Errorf("read from %s: %w", peer.Name, err)
		}
		switch v := m.(type) {
		case *protocol.AuthInit:
			if authorized {
				return nil, errors.New("authorization already completed")
			}
			if r.Auth == nil {
				_ = protocol.WriteMsg(conn, &protocol.Error{Message: "this device does not take a Drop PIN; it only receives from devices it already trusts. Ask its owner to run `drop receive`"})
				return nil, errors.New("this receiver cannot authorize senders")
			}
			if err := r.Auth.Serve(conn); err != nil {
				return nil, err
			}
			authorized, method = true, "pin"
		case *protocol.TransferRequest:
			req = v
		case *protocol.Error:
			return nil, &protocol.RemoteError{Message: v.Message}
		default:
			return nil, fmt.Errorf("unexpected %s message", m.MsgType())
		}
	}

	conn.SetDeadline(time.Time{})
	ttype, name, err := r.validateRequest(req)
	if err != nil {
		return nil, err
	}
	incoming := Incoming{From: peer, Addr: conn.RemoteAddr(), Name: name, Size: req.Size, Type: ttype, Authorized: authorized,
		AuthMethod: method, Files: req.Files, Dirs: req.Dirs}
	if len(peerKey) > 0 {
		incoming.Fingerprint = device.Fingerprint(peerKey)
		incoming.KeyID = device.IDFromPublicKey(peerKey)
	}
	in = &incoming
	if r.Policy.RequiresAuthorization(ttype) && !authorized {
		r.logf("[auth] refused unauthorized %s transfer", ttype)
		_ = protocol.WriteMsg(conn, &protocol.TransferResponse{Accept: false, Reason: "authorization required"})
		return nil, ErrUnauthorized
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	dec := r.Approver.Approve(ctx, incoming)
	if !dec.Accept {
		_ = protocol.WriteMsg(conn, &protocol.TransferResponse{Accept: false, Reason: dec.Reason})
		return nil, ErrDeclined
	}
	if err := protocol.WriteMsg(conn, &protocol.TransferResponse{Accept: true}); err != nil {
		return nil, err
	}

	if ttype == security.TransferText {
		data, err := r.receiveText(conn, incoming, req.SHA256)
		if err != nil {
			_ = protocol.WriteMsg(conn, &protocol.TransferResult{OK: false, Error: publicMessage(err)})
			return nil, wrapCtx(ctx, err)
		}
		granted := r.grantTrust(dec, incoming, peerKey, hello)
		if err := protocol.WriteMsg(conn, &protocol.TransferResult{OK: true, SHA256: req.SHA256, Trusted: granted}); err != nil {
			return nil, err
		}
		if r.OnText != nil {
			r.OnText(incoming, data)
		}
		return &Received{In: incoming, SHA256: req.SHA256, TrustGranted: granted}, nil
	}

	if ttype == security.TransferFolder {
		rec, tree, err := r.receiveFolder(conn, incoming, req, destDir(r.Dir, dec))
		if err != nil {
			_ = protocol.WriteMsg(conn, &protocol.TransferResult{OK: false, Error: publicMessage(err)})
			if errors.Is(err, ErrVerification) || errors.Is(err, errManifest) {
				return nil, err
			}
			return nil, wrapCtx(ctx, err)
		}
		rec.TrustGranted = r.grantTrust(dec, incoming, peerKey, hello)
		if err := protocol.WriteMsg(conn, &protocol.TransferResult{OK: true, SHA256: tree, Trusted: rec.TrustGranted}); err != nil {
			return rec, fmt.Errorf("folder stored at %s but confirmation failed: %w", rec.Path, err)
		}
		return rec, nil
	}

	rec, err = r.receiveFile(conn, incoming, req.SHA256, dec.Conflict, destDir(r.Dir, dec))
	if err != nil {
		_ = protocol.WriteMsg(conn, &protocol.TransferResult{OK: false, Error: publicMessage(err)})
		if errors.Is(err, ErrVerification) {
			return nil, err
		}
		return nil, wrapCtx(ctx, err)
	}
	rec.TrustGranted = r.grantTrust(dec, incoming, peerKey, hello)
	if err := protocol.WriteMsg(conn, &protocol.TransferResult{OK: true, SHA256: rec.SHA256, Trusted: rec.TrustGranted}); err != nil {
		return rec, fmt.Errorf("file stored at %s but confirmation failed: %w", rec.Path, err)
	}
	return rec, nil
}

// grantTrust remembers the sender as a trusted device, but only when the user
// asked for it AND the sender just proved the PIN (trust is never created from
// an unauthenticated or already-trusted session) AND the transfer verified.
func (r *Receiver) grantTrust(dec Decision, in Incoming, key []byte, hello *protocol.Hello) bool {
	if !dec.Trust || r.Trust == nil || in.AuthMethod != "pin" || len(key) == 0 {
		return false
	}
	if _, err := r.Trust.Add(key, hello.DeviceName, hello.OS); err != nil {
		r.logf("[auth] could not save trusted device: %v", err)
		return false
	}
	r.logf("[auth] device added to trusted devices")
	return true
}

// validateRequest checks a request before anything is decided or written.
func (r *Receiver) validateRequest(req *protocol.TransferRequest) (security.TransferType, string, error) {
	if len(req.SHA256) != sha256.Size*2 {
		return "", "", errors.New("invalid sha256 in request")
	}
	if _, err := hex.DecodeString(req.SHA256); err != nil {
		return "", "", errors.New("invalid sha256 in request")
	}
	if req.Size < 0 {
		return "", "", fmt.Errorf("invalid size %d", req.Size)
	}
	switch req.Mode {
	case protocol.ModeFile:
		name, err := filesystem.SafeName(req.Name)
		return security.TransferFile, name, err
	case protocol.ModeFolder:
		if req.Files < 0 || req.Dirs < 0 || req.Files+req.Dirs > filesystem.MaxEntries {
			return "", "", errors.New("invalid folder summary")
		}
		name, err := filesystem.SafeName(req.Name)
		return security.TransferFolder, name, err
	case protocol.ModeText:
		if req.Size > MaxTextSize {
			return "", "", fmt.Errorf("text of %d bytes exceeds the %d byte limit", req.Size, MaxTextSize)
		}
		return security.TransferText, "", nil
	}
	return "", "", fmt.Errorf("unsupported transfer mode %q", req.Mode)
}

func (r *Receiver) receiveText(conn transport.Conn, in Incoming, wantHash string) ([]byte, error) {
	buf := make([]byte, in.Size)
	if _, err := io.ReadFull(idleReader{conn}, buf); err != nil {
		return nil, fmt.Errorf("receive text: connection failed: %w", err)
	}
	sum := sha256.Sum256(buf)
	if hex.EncodeToString(sum[:]) != wantHash {
		return nil, fmt.Errorf("%w: text hash mismatch", ErrVerification)
	}
	return buf, nil
}

// dataIdleTimeout bounds how long a sender may stay silent mid-transfer. Without
// it a stalled (but authenticated) peer would hold the receiver forever.
var dataIdleTimeout = 2 * time.Minute

// idleReader refreshes the connection deadline before every read.
type idleReader struct{ c transport.Conn }

func (r idleReader) Read(p []byte) (int, error) {
	r.c.SetDeadline(time.Now().Add(dataIdleTimeout))
	return r.c.Read(p)
}

// errManifest marks a manifest the receiver refused.
var errManifest = errors.New("manifest rejected")

// receiveFolder reads and fully validates the manifest BEFORE creating
// anything, then writes into a private staging directory and renames it into
// place only after every file and the whole-tree hash verified.
func (r *Receiver) receiveFolder(conn transport.Conn, in Incoming, req *protocol.TransferRequest, dir string) (*Received, string, error) {
	reject := func(msg string) (*Received, string, error) {
		_ = protocol.WriteMsg(conn, &protocol.ManifestAck{OK: false, Error: msg})
		return nil, "", fmt.Errorf("%w: %s", errManifest, msg)
	}
	blob, err := protocol.ReadBlob(idleReader{conn}, MaxManifestBytes)
	if err != nil {
		return nil, "", fmt.Errorf("receive manifest: %w", err)
	}
	if sum := sha256.Sum256(blob); hex.EncodeToString(sum[:]) != req.SHA256 {
		return reject("manifest hash does not match the request")
	}
	_, plan, err := ParseManifest(blob)
	if err != nil {
		return reject(err.Error())
	}
	if plan.Files != req.Files || plan.Dirs != req.Dirs || plan.Total != req.Size {
		return reject("manifest does not match the announced file count, folder count or size")
	}
	if err := protocol.WriteMsg(conn, &protocol.ManifestAck{OK: true}); err != nil {
		return nil, "", err
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, "", fmt.Errorf("create destination %s: %w", dir, err)
	}
	staging, err := os.MkdirTemp(dir, ".drop-partial-dir-*")
	if err != nil {
		return nil, "", fmt.Errorf("create staging folder in %s: %w", dir, err)
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(staging)
		}
	}()

	tree := newTreeHash()
	var done int64
	idx := 0
	for _, e := range plan.Entries {
		local := filepath.Join(append([]string{staging}, e.Local...)...)
		if e.Dir {
			if err := os.Mkdir(local, 0o755); err != nil {
				return nil, "", fmt.Errorf("create folder %s: %w", e.Path, err)
			}
			tree.dir(e.Path)
			continue
		}
		idx++
		if r.OnFile != nil {
			r.OnFile(in, idx, plan.Files, e.Path)
		}
		sum, err := r.receiveOneFile(conn, local, e, &done, plan.Total, in)
		if err != nil {
			return nil, "", err
		}
		tree.file(e.Path, e.Size, sum)
	}

	final, err := filesystem.RenameUnique(staging, dir, in.Name)
	if err != nil {
		return nil, "", err
	}
	ok = true
	os.Chmod(final, 0o755)
	t := tree.sum()
	return &Received{In: in, Path: final, SHA256: t}, t, nil
}

// receiveOneFile writes one file (exclusive create, never overwriting) and
// verifies the SHA-256 trailer the sender appends.
func (r *Receiver) receiveOneFile(conn transport.Conn, path string, e Planned, done *int64, total int64, in Incoming) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", e.Path, err)
	}
	h := sha256.New()
	pw := &tally{done: done, total: total}
	if r.OnProgress != nil {
		pw.fn = func(d, t int64) { r.OnProgress(in, d, t) }
	}
	n, err := copyBulk(io.MultiWriter(f, h, pw), io.LimitReader(idleReader{conn}, e.Size))
	if err != nil || n != e.Size {
		f.Close()
		return nil, fmt.Errorf("receive %s: connection failed after %d of %d bytes: %w", e.Path, n, e.Size, orEOF(err))
	}
	var trailer [sha256.Size]byte
	if _, err := io.ReadFull(idleReader{conn}, trailer[:]); err != nil {
		f.Close()
		return nil, fmt.Errorf("receive hash of %s: %w", e.Path, err)
	}
	sum := h.Sum(nil)
	if !hmacEqual(trailer[:], sum) {
		f.Close()
		return nil, fmt.Errorf("%w: %s arrived corrupted", ErrVerification, e.Path)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("write %s: %w", e.Path, err)
	}
	mode := os.FileMode(0o644)
	if e.Exec {
		mode = 0o755
	}
	if err := os.Chmod(path, mode); err != nil {
		return nil, fmt.Errorf("set permissions on %s: %w", e.Path, err)
	}
	return sum, nil
}

func orEOF(err error) error {
	if err == nil {
		return io.ErrUnexpectedEOF
	}
	return err
}

func hmacEqual(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

func (r *Receiver) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

func (r *Receiver) receiveFile(conn transport.Conn, in Incoming, wantHash string, conflict Conflict, dir string) (*Received, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create destination %s: %w", dir, err)
	}
	// Data goes to a hidden temp file in the destination dir (same filesystem,
	// so the final rename is atomic) and is only given its real name once verified.
	tmp, err := os.CreateTemp(dir, ".drop-partial-*")
	if err != nil {
		return nil, fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { tmp.Close(); os.Remove(tmpPath) }

	ch := &countingHasher{h: sha256.New(), total: in.Size}
	if r.OnProgress != nil {
		ch.fn = func(d, t int64) { r.OnProgress(in, d, t) }
	}
	n, err := copyBulk(io.MultiWriter(tmp, ch), io.LimitReader(idleReader{conn}, in.Size))
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("receive %q: connection failed after %d of %d bytes: %w", in.Name, n, in.Size, err)
	}
	if n != in.Size {
		cleanup()
		return nil, fmt.Errorf("receive %q: connection closed after %d of %d bytes", in.Name, n, in.Size)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("write %s: %w", tmpPath, err)
	}
	got := hex.EncodeToString(ch.h.Sum(nil))
	if got != wantHash {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("%w: expected %s, computed %s", ErrVerification, wantHash, got)
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("set permissions on %s: %w", tmpPath, err)
	}

	var final string
	switch conflict {
	case ConflictReplace:
		final = filepath.Join(dir, in.Name)
	default:
		final, err = filesystem.ReserveUnique(dir, in.Name)
		if err != nil {
			os.Remove(tmpPath)
			return nil, err
		}
	}
	if err := os.Rename(tmpPath, final); err != nil {
		os.Remove(tmpPath)
		if conflict == ConflictRename {
			os.Remove(final) // our own zero-byte reservation
		}
		return nil, fmt.Errorf("move received file into place at %s: %w", final, err)
	}
	return &Received{In: in, Path: final, SHA256: got}, nil
}

const preRequestTimeout = 60 * time.Second

// publicMessage is what we are willing to tell a remote peer about a local
// failure: the wrapped chain minus local filesystem detail where practical.
func publicMessage(err error) string {
	switch {
	case errors.Is(err, ErrVerification):
		return "integrity verification failed"
	case errors.Is(err, ErrDeclined):
		return "declined"
	case errors.Is(err, errManifest):
		return "manifest rejected"
	case errors.Is(err, ErrUnauthorized):
		return "authorization required"
	case errors.Is(err, filesystem.ErrUnsafeName):
		return "unsafe file name"
	}
	return "receiver error"
}

// destDir is the directory a transfer is written to: the approver's choice, if any.
func destDir(def string, dec Decision) string {
	if dec.Dir != "" {
		return dec.Dir
	}
	return def
}
