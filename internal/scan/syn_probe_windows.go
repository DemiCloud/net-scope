//go:build windows

package scan

import (
	"context"
	"net"
	"time"
)

// probeSYN is not implemented on Windows: the OS blocks raw TCP sends on
// AF_INET/SOCK_RAW sockets since Vista (even as Administrator), and
// packet injection requires WinPcap/Npcap which we deliberately avoid.
// Returns empty SYNProbeInfo so all callers degrade gracefully.
func probeSYN(_ context.Context, _ net.IP, _ int, _ time.Duration) SYNProbeInfo {
	return SYNProbeInfo{}
}
