//go:build !windows

package netinfo

// IsElevated always returns false on non-Windows platforms.
func IsElevated() bool { return false }
