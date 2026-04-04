//go:build !windows

package sweep

import "net"

// lookupARPCache is a no-op on non-Windows; batchARP already provides MACs.
func lookupARPCache(_ net.IP) net.HardwareAddr { return nil }
