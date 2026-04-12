//go:build !windows && !linux

package netinfo

// ReadSockets returns nil on platforms other than Windows and Linux.
func ReadSockets() []SocketEntry { return nil }
