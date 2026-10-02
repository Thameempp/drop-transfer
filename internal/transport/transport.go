// Package transport abstracts the byte-stream connection used by the protocol,
// so TCP, QUIC, or future transports can be swapped without touching transfer logic.
package transport

import (
	"context"
	"io"
	"time"
)

// Conn is a reliable, ordered, bidirectional byte stream.
type Conn interface {
	io.ReadWriteCloser
	RemoteAddr() string
	// SetDeadline bounds all pending and future I/O; the zero time clears it.
	SetDeadline(t time.Time) error
}

// Peered is implemented by connections whose peer has been cryptographically
// authenticated; PeerID is derived from the peer's verified public key.
type Peered interface {
	PeerID() string
}

// Listener accepts inbound connections.
type Listener interface {
	Accept() (Conn, error)
	// Addr returns the bound address as host:port.
	Addr() string
	Close() error
}

// Transport creates listeners and outbound connections.
type Transport interface {
	Name() string
	Listen(addr string) (Listener, error)
	Dial(ctx context.Context, addr string) (Conn, error)
}
