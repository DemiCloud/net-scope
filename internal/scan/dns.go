package scan

import (
	"context"
	"net"
	"strings"
	"time"
)

// reverseDNS performs a PTR lookup for ip and returns the first hostname,
// or an empty string if none is found. The lookup is bounded by timeout
// and will abort early if ctx is cancelled.
func reverseDNS(ctx context.Context, ip net.IP, timeout time.Duration) string {
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx2, ip.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
