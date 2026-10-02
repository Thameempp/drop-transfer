package transfer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/thameem/drop/internal/filesystem"
	"io"
	"os"
	"path/filepath"

	"github.com/thameem/drop/internal/protocol"
	"github.com/thameem/drop/internal/security"
	"github.com/thameem/drop/internal/transport"
)

// SendOptions configures a send.
type SendOptions struct {
	Progress ProgressFunc
	// PIN is the receiver's Drop PIN. It is used locally to run the PAKE and is
	// never transmitted. Required when Policy demands authorization.
	PIN    string
	Policy security.Policy
	// OnFile is called as each file of a folder transfer starts (1-based index).
	OnFile func(index, count int, path string)
	// OnAuthenticated is called once PIN authorization has succeeded. Optional.
	OnAuthenticated func()
	// Logf receives safe, secret-free diagnostics. Optional.
	Logf func(format string, args ...any)
}

// SendResult describes a completed, verified send.
type SendResult struct {
	Name   string
	Size   int64
	SHA256 string // for folders: the tree hash both sides agreed on
	Peer   Peer
	Files  int // number of files (folders only)
	// UsedTrust is true when the receiver recognized us as a trusted device and
	// no PIN exchange took place.
	UsedTrust bool
	// TrustGranted is true when the receiver's user chose to trust us during
	// this transfer.
	TrustGranted bool
}

// SendFile sends the regular file at path over conn and returns only after the
// receiver has confirmed a matching SHA-256. conn must be a secured connection
// (see security.Client); the caller owns it.
func SendFile(ctx context.Context, conn transport.Conn, self Self, path string, o SendOptions) (*SendResult, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%s is a directory; folder transfer is not supported yet", path)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	want, size, err := HashFile(path)
	if err != nil {
		return nil, err
	}
	name := filepath.Base(path)
	req := &protocol.TransferRequest{TransferID: newID(), Mode: protocol.ModeFile, Name: name, Size: size, SHA256: want}
	return send(ctx, conn, self, o, security.TransferFile, req, func(c transport.Conn) (string, error) {
		src, err := os.Open(path)
		if err != nil {
			return "", fmt.Errorf("open %s: %w", path, err)
		}
		defer src.Close()
		return streamBytes(c, src, req, o.Progress)
	})
}

// SendText sends plain text. Whether a PIN is needed is decided by o.Policy.
func SendText(ctx context.Context, conn transport.Conn, self Self, text []byte, o SendOptions) (*SendResult, error) {
	if len(text) > MaxTextSize {
		return nil, fmt.Errorf("text is %d bytes; the limit is %d (send it as a file instead)", len(text), MaxTextSize)
	}
	sum := sha256.Sum256(text)
	req := &protocol.TransferRequest{TransferID: newID(), Mode: protocol.ModeText, Size: int64(len(text)), SHA256: hex.EncodeToString(sum[:])}
	return send(ctx, conn, self, o, security.TransferText, req, func(c transport.Conn) (string, error) {
		return streamBytes(c, bytes.NewReader(text), req, o.Progress)
	})
}

// streamBytes sends req.Size bytes from src and notices if the source changed
// while sending. The receiver's confirmation must equal req.SHA256.
func streamBytes(c transport.Conn, src io.Reader, req *protocol.TransferRequest, progress ProgressFunc) (string, error) {
	ch := &countingHasher{h: sha256.New(), total: req.Size, fn: progress}
	n, err := io.Copy(c, io.TeeReader(io.LimitReader(src, req.Size), ch))
	if err != nil {
		return "", fmt.Errorf("send: connection failed after %d of %d bytes: %w", n, req.Size, err)
	}
	if n != req.Size {
		return "", fmt.Errorf("source shrank while sending (%d of %d bytes)", n, req.Size)
	}
	if got := hex.EncodeToString(ch.h.Sum(nil)); got != req.SHA256 {
		return "", errors.New("source changed while sending")
	}
	return req.SHA256, nil
}

// SendFolder sends a scanned directory tree. The manifest goes first (and is
// validated by the receiver before anything is written); then each file's bytes
// followed by its SHA-256, read in a single pass. The receiver's tree hash must
// equal ours for the transfer to count as verified.
func SendFolder(ctx context.Context, conn transport.Conn, self Self, scan *filesystem.ScanResult, o SendOptions) (*SendResult, error) {
	mf := NewManifest(scan)
	blob, err := mf.Marshal()
	if err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	if len(blob) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest of %d bytes is too large; send a smaller tree", len(blob))
	}
	sum := sha256.Sum256(blob)
	req := &protocol.TransferRequest{
		TransferID: newID(), Mode: protocol.ModeFolder, Name: scan.Name, Size: scan.TotalSize,
		SHA256: hex.EncodeToString(sum[:]), Files: scan.Files, Dirs: scan.Dirs,
	}
	return send(ctx, conn, self, o, security.TransferFolder, req, func(c transport.Conn) (string, error) {
		if err := protocol.WriteBlob(c, blob); err != nil {
			return "", err
		}
		ack, err := protocol.Expect[*protocol.ManifestAck](c)
		if err != nil {
			return "", fmt.Errorf("await manifest approval: %w", err)
		}
		if !ack.OK {
			return "", fmt.Errorf("receiver rejected the manifest: %s", orDefault(ack.Error, "no reason given"))
		}
		tree := newTreeHash()
		var done int64
		idx := 0
		for _, e := range mf.Entries {
			if e.Dir {
				tree.dir(e.Path)
				continue
			}
			idx++
			if o.OnFile != nil {
				o.OnFile(idx, scan.Files, e.Path)
			}
			fh, err := sendOneFile(c, scan.Root, e, &done, scan.TotalSize, o.Progress)
			if err != nil {
				return "", err
			}
			tree.file(e.Path, e.Size, fh)
		}
		return tree.sum(), nil
	})
}

// sendOneFile streams one file followed by its 32-byte SHA-256 trailer. It
// refuses to follow a symlink swapped in after the scan.
func sendOneFile(c transport.Conn, root string, e ManifestEntry, done *int64, total int64, progress ProgressFunc) ([]byte, error) {
	p := filepath.Join(root, filepath.FromSlash(e.Path))
	lst, err := os.Lstat(p)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", e.Path, err)
	}
	if !lst.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is no longer a regular file; refusing to send it", e.Path)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", e.Path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !os.SameFile(lst, fi) {
		return nil, fmt.Errorf("%s changed while sending; refusing to continue", e.Path)
	}
	if fi.Size() != e.Size {
		return nil, fmt.Errorf("%s changed since it was scanned (%d bytes, expected %d); send again", e.Path, fi.Size(), e.Size)
	}
	h := sha256.New()
	pw := &tally{done: done, total: total, fn: progress}
	n, err := io.Copy(io.MultiWriter(c, h, pw), io.LimitReader(f, e.Size))
	if err != nil {
		return nil, fmt.Errorf("send %s: connection failed after %d of %d bytes: %w", e.Path, n, e.Size, err)
	}
	if n != e.Size {
		return nil, fmt.Errorf("%s shrank while sending (%d of %d bytes); send again", e.Path, n, e.Size)
	}
	// Detect a file that was modified while we were reading it: a consistent
	// prefix of a changed file would otherwise pass every hash check.
	if after, err := f.Stat(); err != nil || after.Size() != e.Size || !after.ModTime().Equal(fi.ModTime()) {
		return nil, fmt.Errorf("%s changed while sending; send again once it is stable", e.Path)
	}
	sum := h.Sum(nil)
	if _, err := c.Write(sum); err != nil {
		return nil, fmt.Errorf("send hash of %s: %w", e.Path, err)
	}
	return sum, nil
}

func send(ctx context.Context, conn transport.Conn, self Self, o SendOptions, ttype security.TransferType,
	req *protocol.TransferRequest, stream func(transport.Conn) (string, error)) (*SendResult, error) {
	defer closeOnCancel(ctx, conn)()
	logf := func(f string, a ...any) {
		if o.Logf != nil {
			o.Logf(f, a...)
		}
	}
	peered, ok := conn.(transport.Peered)
	if !ok {
		return nil, errors.New("refusing to send over a connection that is not authenticated and encrypted")
	}

	peer, trusted, err := clientHandshake(conn, self, peered)
	if err != nil {
		return nil, wrapCtx(ctx, fmt.Errorf("handshake with %s: %w", conn.RemoteAddr(), err))
	}
	needAuth := o.Policy.RequiresAuthorization(ttype)
	usedTrust := needAuth && trusted
	if needAuth && !trusted {
		if o.PIN == "" {
			return nil, ErrPINRequired
		}
		logf("[auth] authentication requested")
		if err := security.Authenticate(conn, self.ID, o.PIN); err != nil {
			logf("[auth] authentication failed")
			return nil, wrapCtx(ctx, err)
		}
		logf("[auth] authentication succeeded")
		if o.OnAuthenticated != nil {
			o.OnAuthenticated()
		}
	}

	if err := protocol.WriteMsg(conn, req); err != nil {
		return nil, wrapCtx(ctx, fmt.Errorf("send request: %w", err))
	}
	resp, err := protocol.Expect[*protocol.TransferResponse](conn)
	if err != nil {
		return nil, wrapCtx(ctx, fmt.Errorf("await decision: %w", err))
	}
	if !resp.Accept {
		return nil, fmt.Errorf("%w: %s", ErrDeclined, orDefault(resp.Reason, "no reason given"))
	}

	want, err := stream(conn)
	if err != nil {
		return nil, wrapCtx(ctx, err)
	}

	res, err := protocol.Expect[*protocol.TransferResult](conn)
	if err != nil {
		return nil, wrapCtx(ctx, fmt.Errorf("await verification: %w", err))
	}
	if !res.OK {
		return nil, fmt.Errorf("%w: receiver reported: %s", ErrVerification, orDefault(res.Error, "unknown error"))
	}
	if res.SHA256 != want {
		return nil, fmt.Errorf("%w: sender %s, receiver %s", ErrVerification, want, res.SHA256)
	}
	return &SendResult{Name: req.Name, Size: req.Size, SHA256: want, Peer: peer, Files: req.Files,
		UsedTrust: usedTrust, TrustGranted: res.Trusted}, nil
}

func clientHandshake(conn transport.Conn, self Self, peered transport.Peered) (Peer, bool, error) {
	hello := &protocol.Hello{Versions: protocol.SupportedVersions, DeviceID: self.ID, DeviceName: self.Name, OS: self.OS}
	if err := protocol.WriteMsg(conn, hello); err != nil {
		return Peer{}, false, err
	}
	ack, err := protocol.Expect[*protocol.HelloAck](conn)
	if err != nil {
		return Peer{}, false, err
	}
	if _, err := protocol.Negotiate(protocol.SupportedVersions, []int{ack.Version}); err != nil {
		return Peer{}, false, err
	}
	if ack.DeviceID != peered.PeerID() {
		return Peer{}, false, fmt.Errorf("peer claimed device ID %q but authenticated as %q", ack.DeviceID, peered.PeerID())
	}
	return Peer{ID: peered.PeerID(), Name: ack.DeviceName}, ack.Trusted, nil
}

func newID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// wrapCtx prefers the context error when the failure was caused by cancellation.
func wrapCtx(ctx context.Context, err error) error {
	if ce := ctx.Err(); ce != nil {
		return fmt.Errorf("%w (%v)", ce, err)
	}
	return err
}
