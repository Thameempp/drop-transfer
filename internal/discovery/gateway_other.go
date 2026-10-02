//go:build !linux && !darwin && !freebsd && !windows

package discovery

import (
	"errors"
	"net"
)

func defaultGateway() (net.IP, error) { return nil, errors.New("not supported on this platform") }
