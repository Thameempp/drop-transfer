//go:build darwin || freebsd

package discovery

import (
	"net"
	"syscall"

	"golang.org/x/net/route"
)

// readNeighborsKernel reads the ARP table straight from the kernel routing
// interface (the same source `arp -a` uses), without running a program.
func readNeighborsKernel() ([]Neighbor, bool) {
	rib, err := route.FetchRIB(syscall.AF_INET, route.RIBType(syscall.NET_RT_FLAGS), syscall.RTF_LLINFO)
	if err != nil {
		return nil, false
	}
	msgs, err := route.ParseRIB(route.RIBType(syscall.NET_RT_FLAGS), rib)
	if err != nil {
		return nil, false
	}
	var out []Neighbor
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || len(rm.Addrs) <= syscall.RTAX_GATEWAY {
			continue
		}
		dst, ok1 := rm.Addrs[syscall.RTAX_DST].(*route.Inet4Addr)
		gw, ok2 := rm.Addrs[syscall.RTAX_GATEWAY].(*route.LinkAddr)
		if !ok1 || !ok2 || len(gw.Addr) != 6 { // incomplete entries have no link-layer address
			continue
		}
		ip := net.IP(dst.IP[:]).String()
		mac := net.HardwareAddr(gw.Addr).String()
		if n, ok := makeNeighbor(ip, mac); ok {
			out = append(out, n)
		}
	}
	return out, true
}
