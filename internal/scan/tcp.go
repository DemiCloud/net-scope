package scan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// allPortsRange returns the full list of TCP ports 1–65535.
func allPortsRange() []int {
	ports := make([]int, 65535)
	for i := range ports {
		ports[i] = i + 1
	}
	return ports
}

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
// maxConcurrency limits how many in-flight connections exist at once; pass 0
// to run all ports concurrently (safe for small lists, dangerous for 65535).
func scanPorts(ctx context.Context, ip net.IP, ports []int, timeout time.Duration, dial DialFunc, maxConcurrency int) []int {
	if len(ports) == 0 {
		return nil
	}
	// Apply the caller-supplied timeout so filtered ports (no RST) don't block
	// until the OS TCP retransmit timeout (can be tens of seconds).
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// When the limit exceeds (or equals) the port count, every port gets its own
	// goroutine immediately — no semaphore overhead, same behaviour as before.
	if maxConcurrency <= 0 || maxConcurrency >= len(ports) {
		maxConcurrency = len(ports)
	}

	type result struct {
		port int
		open bool
	}

	sem := make(chan struct{}, maxConcurrency)
	ch := make(chan result, len(ports))

	for _, port := range ports {
		sem <- struct{}{} // blocks the dispatch loop when limit is reached
		go func(p int) {
			defer func() { <-sem }()
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

// ScanPortsStreaming dials ports concurrently and calls emit(port, open) for
// each port result as soon as it is known. The function returns after all ports
// have been checked or ctx is cancelled.
//
// dialTimeout is the per-dial deadline applied independently to each connection
// attempt. maxConcurrency limits in-flight TCP dials; pass 0 for unlimited
// (dangerous for large port lists — use a reasonable cap for all-ports mode).
func ScanPortsStreaming(ctx context.Context, ip net.IP, ports []int, dialTimeout time.Duration, dial DialFunc, maxConcurrency int, emit func(port int, open bool)) {
	if len(ports) == 0 {
		return
	}
	if maxConcurrency <= 0 || maxConcurrency >= len(ports) {
		maxConcurrency = len(ports)
	}

	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	for _, port := range ports {
		p := port
		sem <- struct{}{} // blocks while maxConcurrency dials are in-flight
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			ctx2, cancel := context.WithTimeout(ctx, dialTimeout)
			defer cancel()
			conn, err := dialOrDirect(dial)(ctx2, "tcp", fmt.Sprintf("%s:%d", ip, p))
			if err == nil {
				conn.Close()
				emit(p, true)
			} else {
				emit(p, false)
			}
		}()
	}
	wg.Wait()
}
