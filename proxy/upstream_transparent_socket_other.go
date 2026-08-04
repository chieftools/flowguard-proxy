//go:build !linux

package proxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

func transparentDialContext(netip.Addr, uint32) (func(context.Context, string, string) (net.Conn, error), error) {
	return nil, fmt.Errorf("transparent upstream mode is supported only on Linux")
}
