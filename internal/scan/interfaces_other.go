//go:build !linux && !windows

package scan

// enrichInterfaceEntries is a no-op on platforms other than Linux and Windows.
// FreeBSD and other BSDs expose interface stats via sysctl/ioctl but we do not
// have a dependency-free implementation yet.
func enrichInterfaceEntries(_ []InterfaceEntry) {}
