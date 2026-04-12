// Package probes registers deep protocol probes with the scan package's catalog.
// Each probe is protocol-aware, streams human-readable output as it runs,
// and returns Observations that are merged into the session service registry.
//
// Call Register() once at startup (before any service connection is accepted).
package probes

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/demicloud/net-scope/internal/scan"
)

// Register populates the global deep probe registry with all built-in probes.
// Must be called before the service subprocess accepts any connection.
func Register() {
	registerGeneral()
	registerWeb()
	registerRemote()
	registerEmail()
	registerFileShare()
	registerDirectory()
	registerDatabase()
	registerMessaging()
	registerDevOps()
	registerNetwork()
	registerGaming()
	registerIndustrial()
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// obs is a convenience constructor for scan.Observation.
func obs(src, key, val string) scan.Observation {
	return scan.Observation{Source: src, Key: key, Value: val}
}

// dialTCP opens a TCP connection, honouring the optional SOCKS5 dial func.
func dialTCP(ctx context.Context, dial scan.DialFunc, ip string, port int, timeout time.Duration) (net.Conn, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	fn := dial
	if fn == nil {
		fn = func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, network, addr)
		}
	}
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return fn(ctx2, "tcp", addr)
}

// dialUDP opens a UDP connection (SOCKS5 does not support UDP; dial is ignored).
func dialUDP(ip string, port int, timeout time.Duration) (net.Conn, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	return net.DialTimeout("udp", addr, timeout)
}

// readLine reads one CR/LF-terminated line from conn.
func readLine(conn net.Conn) (string, error) {
	sc := bufio.NewReader(conn)
	line, err := sc.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

// readLines reads lines until the predicate returns true for one of them.
func readLines(conn net.Conn, until func(string) bool) ([]string, error) {
	var lines []string
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		l := sc.Text()
		lines = append(lines, l)
		if until(l) {
			return lines, nil
		}
	}
	return lines, sc.Err()
}

// joinHost is fmt.Sprintf("%s:%d", ip, port) without the import.
func joinHost(ip string, port int) string {
	return net.JoinHostPort(ip, fmt.Sprintf("%d", port))
}

// httpGetDirect issues a minimal HTTP/1.0 GET and returns status + select headers.
func httpGetDirect(conn net.Conn, host string) (status, server, contentType string, err error) {
	req := "GET / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: probe/1.0\r\nConnection: close\r\n\r\n"
	if _, err = fmt.Fprint(conn, req); err != nil {
		return
	}
	sc := bufio.NewScanner(conn)
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first {
			status = line
			first = false
			continue
		}
		if line == "" {
			break
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "server:") {
			server = strings.TrimSpace(line[7:])
		} else if strings.HasPrefix(lower, "content-type:") {
			contentType = strings.TrimSpace(line[13:])
		}
	}
	err = sc.Err()
	return
}

// httpGetBody issues a minimal HTTP/1.0 GET to path and returns the status
// line, the full response body as a string, and any error.
func httpGetBody(conn net.Conn, host, path string) (statusLine, body string, err error) {
	req := "GET " + path + " HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: probe/1.0\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
	if _, err = fmt.Fprint(conn, req); err != nil {
		return
	}
	sc := bufio.NewScanner(conn)
	first := true
	inBody := false
	var bodyLines []string
	for sc.Scan() {
		line := sc.Text()
		if first {
			statusLine = line
			first = false
			continue
		}
		if !inBody {
			if line == "" {
				inBody = true
			}
			continue
		}
		bodyLines = append(bodyLines, line)
	}
	body = strings.Join(bodyLines, "\n")
	err = sc.Err()
	return
}
