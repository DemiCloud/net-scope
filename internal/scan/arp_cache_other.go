//go:build !windows

package scan

import "net"

// lookupARPCache is a no-op on non-Windows; batchARP already provides MACs.
func lookupARPCache(_ net.IP) net.HardwareAddr { return nil }

// ReadARPTable returns nil on non-Windows; ARP is provided by batchARP.
func ReadARPTable() map[string]net.HardwareAddr { return nil }

// ReadARPTableFull returns nil on non-Windows.
func ReadARPTableFull() []ARPResult { return nil }
