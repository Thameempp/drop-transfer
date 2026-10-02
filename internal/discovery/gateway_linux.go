//go:build linux

package discovery

import (
	"errors"
	"net"
	"os"
)

func defaultGateway() (net.IP, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, err
	}
	if ip, ok := parseProcRoute(string(data)); ok {
		return ip, nil
	}
	return nil, errors.New("no default route")
}
