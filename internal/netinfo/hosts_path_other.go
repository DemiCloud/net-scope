//go:build !windows

package netinfo

// hostsFilePath returns the path to the system hosts file on Unix-like systems.
func hostsFilePath() string {
	return "/etc/hosts"
}
