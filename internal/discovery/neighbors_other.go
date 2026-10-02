//go:build !darwin && !freebsd

package discovery

func readNeighborsKernel() ([]Neighbor, bool) { return nil, false }
