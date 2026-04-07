package sweep

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"
)

// scanPorts dials each port concurrently and returns the open ones, sorted.
func scanPorts(ctx context.Context, ip net.IP, ports []int, timeout time.Duration, dial DialFunc) []int {
	type result struct {
		port int
		open bool
	}

	ch := make(chan result, len(ports))
	for _, port := range ports {
		go func(p int) {
			addr := fmt.Sprintf("%s:%d", ip, p)
			conn, err := dialOrDirect(dial)(ctx, "tcp", addr)
			if err == nil {
				conn.Close()
				ch <- result{p, true}
			} else {
				ch <- result{p, false}
			}
		}(port)
	}

	var open []int
	for range ports {
		if r := <-ch; r.open {
			open = append(open, r.port)
		}
	}
	sort.Ints(open)
	return open
}
