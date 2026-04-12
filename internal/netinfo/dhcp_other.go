//go:build !windows

package netinfo

import (
	"context"
	"fmt"
)

// DHCPEvent is the minimal stub used on non-Windows platforms.
// Passive DHCP capture (SIO_RCVALL) is Windows-only.
type DHCPEvent struct{}

// ListenDHCP is not implemented on non-Windows platforms.
func ListenDHCP(_ context.Context, _ chan<- DHCPEvent) error {
	return fmt.Errorf("passive DHCP capture is not supported on this platform")
}
