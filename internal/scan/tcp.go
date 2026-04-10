package scan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"
)

// probeTCPOpen returns true if ip:port accepts a TCP connection within timeout.
// Lighter than scanPorts — no goroutine, no sorting, just a single dial.
func probeTCPOpen(ctx context.Context, ip net.IP, port int, timeout time.Duration) bool {
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := (&net.Dialer{}).DialContext(ctx2, "tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// scanPorts dials each port concurrently and returns the open ones, sorted.
func scanPorts(ctx context.Context, ip net.IP, ports []int, timeout time.Duration, dial DialFunc) []int {
	// Apply the caller-supplied timeout so filtered ports (no RST) don't block
	// until the OS TCP retransmit timeout (can be tens of seconds).
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type result struct {
		port int
		open bool
	}

	ch := make(chan result, len(ports))
	for _, port := range ports {
		go func(p int) {
			addr := fmt.Sprintf("%s:%d", ip, p)
			conn, err := dialOrDirect(dial)(ctx2, "tcp", addr)
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
