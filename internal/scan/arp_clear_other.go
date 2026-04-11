//go:build !windows

package scan

import "errors"

// DeleteARPEntry is not supported on non-Windows platforms.
func DeleteARPEntry(_ string) error { return errors.New("not supported on this platform") }

// FlushARPCache is not supported on non-Windows platforms.
func FlushARPCache(_ uint32) error { return errors.New("not supported on this platform") }
