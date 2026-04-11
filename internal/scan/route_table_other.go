//go:build !windows && !linux

package scan

import "errors"

// ReadRouteTable returns nil on platforms other than Windows and Linux.
func ReadRouteTable() []RouteEntry { return nil }

// DeleteRouteEntry is not supported on this platform.
func DeleteRouteEntry(_ string) error {
	return errors.New("route deletion is not supported on this platform")
}
