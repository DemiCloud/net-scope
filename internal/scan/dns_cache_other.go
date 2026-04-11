//go:build !windows

package scan

import "errors"

// ReadDNSCache returns nil on non-Windows platforms.
func ReadDNSCache() []DNSCacheEntry { return nil }

// FlushDNSCache is not supported on non-Windows platforms.
func FlushDNSCache() error { return errors.New("not supported on this platform") }
