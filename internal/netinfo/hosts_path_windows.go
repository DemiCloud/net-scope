//go:build windows

package netinfo

// hostsFilePath returns the path to the system hosts file on Windows.
func hostsFilePath() string {
	return `C:\Windows\System32\drivers\etc\hosts`
}
