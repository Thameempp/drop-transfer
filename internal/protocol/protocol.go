// Package protocol defines drop's wire messages and framing.
//
// Control messages are length-prefixed JSON frames (4-byte big-endian length,
// then the JSON body). Bulk file data is NOT framed or JSON-encoded: after a
// transfer is accepted the sender writes exactly Size raw bytes on the stream.
package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Version is the highest protocol version this build speaks.
//
// Version 2 requires TLS 1.3 and adds PIN authorization. Version 1 (an early
// unauthenticated prototype) is intentionally not supported.
const Version = 2

// SupportedVersions lists every protocol version this build can speak.
var SupportedVersions = []int{2}

// MaxFrame bounds a control frame so a peer cannot force huge allocations.
const MaxFrame = 1 << 20

// Negotiate returns the highest version present in both lists.
func Negotiate(local, remote []int) (int, error) {
	best := 0
	for _, l := range local {
		for _, r := range remote {
			if l == r && l > best {
				best = l
			}
		}
	}
	if best == 0 {
		return 0, fmt.Errorf("no common protocol version (local %v, remote %v)", local, remote)
	}
	return best, nil
}

// WriteMsg encodes m as one control frame.
func WriteMsg(w io.Writer, m Message) error {
	body, err := json.Marshal(envelope{Type: m.MsgType(), Body: mustMarshal(m)})
	if err != nil {
		return fmt.Errorf("encode %s: %w", m.MsgType(), err)
	}
	if len(body) > MaxFrame {
		return fmt.Errorf("encode %s: frame of %d bytes exceeds limit", m.MsgType(), len(body))
	}
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf, uint32(len(body)))
	copy(buf[4:], body)
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("write %s: %w", m.MsgType(), err)
	}
	return nil
}

// ReadMsg decodes the next control frame.
func ReadMsg(r io.Reader) (Message, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read frame header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxFrame {
		return nil, fmt.Errorf("invalid frame length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read frame body: %w", err)
	}
	var env envelope
	if err := json.Unmarshal(buf, &env); err != nil {
		return nil, fmt.Errorf("decode frame: %w", err)
	}
	m := newMessage(env.Type)
	if m == nil {
		return nil, fmt.Errorf("unknown message type %q", env.Type)
	}
	if err := json.Unmarshal(env.Body, m); err != nil {
		return nil, fmt.Errorf("decode %s: %w", env.Type, err)
	}
	return m, nil
}

// Expect reads one message and requires it to be of type T. A peer-sent Error
// message is surfaced as an error.
func Expect[T Message](r io.Reader) (T, error) {
	var zero T
	m, err := ReadMsg(r)
	if err != nil {
		return zero, err
	}
	if e, ok := m.(*Error); ok {
		return zero, &RemoteError{Message: e.Message}
	}
	t, ok := m.(T)
	if !ok {
		return zero, fmt.Errorf("unexpected %s message, wanted %T", m.MsgType(), zero)
	}
	return t, nil
}

// RemoteError is an error reported by the peer.
type RemoteError struct{ Message string }

func (e *RemoteError) Error() string { return "peer reported: " + e.Message }

// IsRemote reports whether err came from the peer.
func IsRemote(err error) bool {
	var re *RemoteError
	return errors.As(err, &re)
}

type envelope struct {
	Type string          `json:"type"`
	Body json.RawMessage `json:"body"`
}

func mustMarshal(m Message) json.RawMessage {
	b, err := json.Marshal(m)
	if err != nil {
		panic(err) // messages are plain structs; cannot fail
	}
	return b
}

// WriteBlob writes an 8-byte big-endian length followed by b. Blobs carry bulk
// metadata (folder manifests) that may exceed MaxFrame.
func WriteBlob(w io.Writer, b []byte) error {
	var hdr [8]byte
	binary.BigEndian.PutUint64(hdr[:], uint64(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write blob header: %w", err)
	}
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("write blob: %w", err)
	}
	return nil
}

// ReadBlob reads a blob, refusing anything larger than max before allocating.
func ReadBlob(r io.Reader, max int64) ([]byte, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read blob header: %w", err)
	}
	n := binary.BigEndian.Uint64(hdr[:])
	if n > uint64(max) {
		return nil, fmt.Errorf("blob of %d bytes exceeds the %d byte limit", n, max)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read blob: %w", err)
	}
	return buf, nil
}
