package sweep

import (
	"context"
	"net"
	"strings"
	"time"
)

// reverseDNS performs a PTR lookup for ip and returns the first hostname,
// or an empty string if none is found.
func reverseDNS(ip net.IP, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
