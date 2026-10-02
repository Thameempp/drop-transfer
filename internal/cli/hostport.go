package cli

import (
	"net"
	"strconv"
)

// isHostPort reports whether s is a literal host:port, e.g. 192.168.1.5:4000 or localhost:4000.
func isHostPort(s string) bool {
	_, port, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n < 65536
}
