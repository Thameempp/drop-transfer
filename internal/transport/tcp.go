package transport

import (
	"context"
	"fmt"
	"net"
	"time"
)

// TCP is the baseline transport.
type TCP struct{}

func (TCP) Name() string { return "tcp" }

func (TCP) Listen(addr string) (Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %q: %w", addr, err)
	}
	return &tcpListener{l}, nil
}

func (TCP) Dial(ctx context.Context, addr string) (Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}
	return &tcpConn{c}, nil
}

type tcpListener struct{ l net.Listener }

func (t *tcpListener) Accept() (Conn, error) {
	c, err := t.l.Accept()
	if err != nil {
		return nil, err
	}
	return &tcpConn{c}, nil
}
func (t *tcpListener) Addr() string { return t.l.Addr().String() }
func (t *tcpListener) Close() error { return t.l.Close() }

type tcpConn struct{ net.Conn }

func (c *tcpConn) RemoteAddr() string { return c.Conn.RemoteAddr().String() }
