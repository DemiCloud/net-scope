//go:build !windows

package scan

// IsElevated always returns false on non-Windows platforms.
func IsElevated() bool { return false }
