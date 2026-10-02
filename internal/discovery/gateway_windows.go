//go:build windows

package discovery

import (
	"errors"
	"net"
	"os/exec"
)

func defaultGateway() (net.IP, error) {
	out, err := exec.Command("route", "print", "-4", "0.0.0.0").Output()
	if err != nil {
		return nil, err
	}
	if ip, ok := parseWindowsRoute(string(out)); ok {
		return ip, nil
	}
	return nil, errors.New("no default route")
}
