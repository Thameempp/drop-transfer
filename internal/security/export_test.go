package security

import (
	"fmt"
	"time"

	"github.com/thameem/drop/internal/transport"
)

// Cheap Argon2 for unit tests; production parameters are exercised in TestVerifierHashingAndChecking's shape checks.
func init() { ReduceKDFCostForTests() }

// delegating wrappers keep the secured-connection capabilities visible.
type wrapped struct{ transport.Conn }

func (w wrapped) PeerID() string                  { return w.Conn.(transport.Peered).PeerID() }
func (w wrapped) ChannelBinding() ([]byte, error) { return ChannelBinding(w.Conn) }

func sprintf(f string, a ...any) string { return fmt.Sprintf(f, a...) }

// authTimeoutForTest shortens the auth deadline and returns a restore func.
func authTimeoutForTest(d time.Duration) func() {
	old := authTimeout
	authTimeout = d
	return func() { authTimeout = old }
}
