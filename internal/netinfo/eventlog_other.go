//go:build !windows

package netinfo

// ReadNetworkEventLog is not supported on non-Windows platforms.
func ReadNetworkEventLog(_ int) []EventLogEntry { return nil }
