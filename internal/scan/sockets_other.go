//go:build !windows && !linux

package scan

// ReadSockets returns nil on platforms other than Windows and Linux.
func ReadSockets() []SocketEntry { return nil }
