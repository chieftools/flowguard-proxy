//go:build linux

package proxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

func transparentDialContext(source netip.Addr, fwmark uint32) (func(context.Context, string, string) (net.Conn, error), error) {
	if !source.IsValid() || (!source.Is4() && !source.Is6()) || !source.IsGlobalUnicast() {
		return nil, fmt.Errorf("invalid transparent source address %s", source)
	}
	if fwmark == 0 {
		return nil, fmt.Errorf("transparent upstream fwmark must be non-zero")
	}

	dialer := &net.Dialer{
		Timeout:   upstreamDialTimeout,
		KeepAlive: upstreamKeepAlive,
		LocalAddr: &net.TCPAddr{IP: net.IP(source.AsSlice())},
		Control: func(network, _ string, raw syscall.RawConn) error {
			var socketErr error
			if err := raw.Control(func(fd uintptr) {
				if network == "tcp4" {
					socketErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
				} else if network == "tcp6" {
					socketErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
				} else {
					socketErr = fmt.Errorf("unsupported transparent network %q", network)
				}
				if socketErr == nil {
					socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(fwmark))
				}
			}); err != nil {
				return err
			}
			return socketErr
		},
	}
	return dialer.DialContext, nil
}
