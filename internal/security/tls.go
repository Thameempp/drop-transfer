// Package security provides the encrypted channel, PIN authorization, and the
// transfer authorization policy.
//
// Responsibilities are deliberately separate:
//   - TLS 1.3 (this file) gives confidentiality and a cryptographic device
//     identity. Each device presents a self-signed ed25519 certificate built
//     from its identity key; TLS proves it holds the private key.
//   - The PIN (auth.go) authorizes protected transfers. It is verified with a
//     PAKE run inside the TLS channel and bound to it, so the PIN is never
//     transmitted, not even encrypted, and is not itself a key.
//   - Policy (policy.go) decides which transfer types need the PIN.
//
// No custom cryptography is used: crypto/tls, Argon2id, CPace (ristretto255)
// and HMAC-SHA-256/HKDF from well-known libraries.
package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/thameem/drop/internal/device"
	"github.com/thameem/drop/internal/transport"
)

const handshakeTimeout = 15 * time.Second

// ErrPeerMismatch means the device we reached is not the one we meant to reach.
var ErrPeerMismatch = errors.New("connected device is not the one that was selected")

// PeerCheck inspects the peer key (already proven by TLS).
type PeerCheck func(pub ed25519.PublicKey) error

// Any accepts every key. A device ID is not a secret and a TLS identity alone
// does not authorize anything; authorization comes from the PIN.
func Any() PeerCheck { return func(ed25519.PublicKey) error { return nil } }

// ExpectID requires the peer's key to hash to the device ID seen in discovery,
// so a different device cannot answer for a selected one.
func ExpectID(id string) PeerCheck {
	return func(pub ed25519.PublicKey) error {
		if got := device.IDFromPublicKey(pub); got != id {
			return fmt.Errorf("%w (expected %s, got %s)", ErrPeerMismatch, id, got)
		}
		return nil
	}
}

// Client upgrades conn to an authenticated, encrypted connection as TLS client.
func Client(conn transport.Conn, id *device.Identity, check PeerCheck) (transport.Conn, error) {
	return upgrade(conn, id, check, false)
}

// Server upgrades conn as TLS server, requiring a client certificate.
func Server(conn transport.Conn, id *device.Identity, check PeerCheck) (transport.Conn, error) {
	return upgrade(conn, id, check, true)
}

func upgrade(conn transport.Conn, id *device.Identity, check PeerCheck, server bool) (transport.Conn, error) {
	cert, err := certificate(id)
	if err != nil {
		return nil, err
	}
	var peer ed25519.PublicKey
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		// Chain validation is meaningless for self-signed device certs; the
		// real decision is made in VerifyPeerCertificate against our own trust.
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("peer sent no certificate")
			}
			c, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return fmt.Errorf("parse peer certificate: %w", err)
			}
			pub, ok := c.PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("peer certificate key is not ed25519")
			}
			if err := check(pub); err != nil {
				return err
			}
			peer = pub
			return nil
		},
	}
	nc := &netConn{Conn: conn}
	var tc *tls.Conn
	if server {
		tc = tls.Server(nc, cfg)
	} else {
		tc = tls.Client(nc, cfg)
	}
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := tc.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("secure handshake with %s: %w", conn.RemoteAddr(), err)
	}
	conn.SetDeadline(time.Time{})
	if peer == nil {
		conn.Close()
		return nil, errors.New("secure handshake finished without a verified peer key")
	}
	return &secureConn{tc: tc, remote: conn.RemoteAddr(), peer: peer}, nil
}

func certificate(id *device.Identity) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("certificate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "drop-" + id.ID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, id.PublicKey, id.Signer())
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create device certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: id.Signer()}, nil
}

// netConn adapts a transport.Conn to net.Conn for crypto/tls.
type netConn struct{ transport.Conn }

type addr string

func (a addr) Network() string { return "drop" }
func (a addr) String() string  { return string(a) }

func (c *netConn) LocalAddr() net.Addr                { return addr("local") }
func (c *netConn) RemoteAddr() net.Addr               { return addr(c.Conn.RemoteAddr()) }
func (c *netConn) SetReadDeadline(t time.Time) error  { return c.Conn.SetDeadline(t) }
func (c *netConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetDeadline(t) }

// secureConn is the authenticated connection handed to the protocol layer.
type secureConn struct {
	tc     *tls.Conn
	remote string
	peer   ed25519.PublicKey
}

func (s *secureConn) Read(p []byte) (int, error)    { return s.tc.Read(p) }
func (s *secureConn) Write(p []byte) (int, error)   { return s.tc.Write(p) }
func (s *secureConn) Close() error                  { return s.tc.Close() }
func (s *secureConn) RemoteAddr() string            { return s.remote }
func (s *secureConn) SetDeadline(t time.Time) error { return s.tc.SetDeadline(t) }
func (s *secureConn) PeerID() string                { return device.IDFromPublicKey(s.peer) }

// ChannelBinding returns a value unique to this TLS session (RFC 5705/8446
// exporter). Both ends derive the same value only if no one terminated TLS in
// between, so binding the PIN exchange to it defeats man-in-the-middle relays.
func ChannelBinding(c transport.Conn) ([]byte, error) {
	b, ok := c.(interface{ ChannelBinding() ([]byte, error) })
	if !ok {
		return nil, errors.New("connection is not secured")
	}
	return b.ChannelBinding()
}

func (s *secureConn) ChannelBinding() ([]byte, error) {
	st := s.tc.ConnectionState()
	return st.ExportKeyingMaterial("EXPORTER-drop-pin-auth-v1", nil, 32)
}

// PeerKey returns the peer's TLS-verified public key.
func PeerKey(c transport.Conn) (ed25519.PublicKey, bool) {
	if s, ok := c.(*secureConn); ok {
		return s.peer, true
	}
	return nil, false
}
