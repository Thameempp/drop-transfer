//go:build darwin || freebsd

package discovery

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/net/route"
)

func defaultGateway() (net.IP, error) {
	rib, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}
	var fallback net.IP
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&syscall.RTF_GATEWAY == 0 || len(rm.Addrs) <= syscall.RTAX_GATEWAY {
			continue
		}
		dst, ok1 := rm.Addrs[syscall.RTAX_DST].(*route.Inet4Addr)
		gw, ok2 := rm.Addrs[syscall.RTAX_GATEWAY].(*route.Inet4Addr)
		if !ok1 || !ok2 || dst.IP != [4]byte{} {
			continue
		}
		ip := net.IP(gw.IP[:])
		if !ip.IsPrivate() {
			continue // a tunnel or the like, not our LAN router
		}
		if rm.Flags&0x1000000 == 0 { // RTF_IFSCOPE: prefer the unscoped (primary) default
			return ip, nil
		}
		if fallback == nil {
			fallback = ip
		}
	}
	if fallback != nil {
		return fallback, nil
	}
	return nil, errors.New("no default route")
}
