//go:build !windows

package netinfo

import "errors"

// ReadDNSCache returns nil on non-Windows platforms.
func ReadDNSCache() []DNSCacheEntry { return nil }

// FlushDNSCache is not supported on non-Windows platforms.
func FlushDNSCache() error { return errors.New("not supported on this platform") }

// DeleteDNSCacheEntry is not supported on non-Windows platforms.
func DeleteDNSCacheEntry(_ string) error { return errors.New("not supported on this platform") }
