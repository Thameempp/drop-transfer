// Package transfer implements the sender and receiver sides of a drop transfer.
// It is independent of both the transport implementation and terminal rendering.
package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sync"
	"time"
)

// Self identifies the local device in handshakes.
type Self struct {
	ID   string
	Name string
	OS   string
}

// Peer identifies the remote device as reported in its handshake.
// Until authentication lands (security phase) these values are self-asserted.
type Peer struct {
	ID   string
	Name string
}

// ProgressFunc reports bytes moved so far out of total. It is called from the
// transfer goroutine and must return quickly; rate-limit in the renderer.
type ProgressFunc func(done, total int64)

// Error kinds let callers map failures to exit codes.
var (
	ErrDeclined     = errors.New("transfer declined by receiver")
	ErrVerification = errors.New("integrity verification failed")
	ErrUnauthorized = errors.New("authorization required")
	// ErrPINRequired is returned by a sender that has no PIN when the receiver
	// does not recognize it as a trusted device.
	ErrPINRequired = errors.New("the receiver does not trust this device: the Drop PIN is required")
)

// HashFile streams path through SHA-256 without loading it into memory.
func HashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := copyBulk(h, f)
	if err != nil {
		return "", 0, fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// progressReader/Writer wrap a stream, feeding a hash and a progress callback.
type countingHasher struct {
	h     hash.Hash
	done  int64
	total int64
	fn    ProgressFunc
	last  time.Time
}

func (c *countingHasher) Write(p []byte) (int, error) {
	c.h.Write(p)
	c.done += int64(len(p))
	if c.fn != nil && (c.done == c.total || time.Since(c.last) > 50*time.Millisecond) {
		c.last = time.Now()
		c.fn(c.done, c.total)
	}
	return len(p), nil
}

// closeOnCancel closes c when ctx is cancelled so blocked I/O unblocks.
// The returned func stops the watcher.
func closeOnCancel(ctx context.Context, c io.Closer) func() {
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-stop:
		}
	}()
	return func() { close(stop) }
}

// tally accumulates bytes across many files and reports overall progress.
type tally struct {
	done  *int64
	total int64
	fn    ProgressFunc
	last  time.Time
}

func (t *tally) Write(p []byte) (int, error) {
	*t.done += int64(len(p))
	if t.fn != nil && (*t.done == t.total || time.Since(t.last) > 50*time.Millisecond) {
		t.last = time.Now()
		t.fn(*t.done, t.total)
	}
	return len(p), nil
}

// treeHash is the end-to-end digest of a folder: every entry in manifest order
// with each file's size and SHA-256. Sender and receiver compute it
// independently; equality proves the whole tree arrived intact.
type treeHash struct{ h hash.Hash }

func newTreeHash() *treeHash { return &treeHash{h: sha256.New()} }

func (t *treeHash) dir(path string) { fmt.Fprintf(t.h, "D\x00%s\n", path) }
func (t *treeHash) file(path string, size int64, sum []byte) {
	fmt.Fprintf(t.h, "F\x00%s\x00%d\x00%x\n", path, size, sum)
}
func (t *treeHash) sum() string { return hex.EncodeToString(t.h.Sum(nil)) }

// copyBufSize is the I/O buffer for bulk data. The 32 KiB io.Copy default means
// many small reads, writes and system calls, which dominates on fast links.
const copyBufSize = 1 << 20

var copyBufs = sync.Pool{New: func() any { b := make([]byte, copyBufSize); return &b }}

// copyBulk is io.Copy with a large pooled buffer.
func copyBulk(dst io.Writer, src io.Reader) (int64, error) {
	bp := copyBufs.Get().(*[]byte)
	defer copyBufs.Put(bp)
	return io.CopyBuffer(dst, src, *bp)
}
