package sweep

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"
	"time"
)

const (
	ssdpMulticast = "239.255.255.250:1900"
	ssdpMSearch   = "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 3\r\n" +
		"ST: ssdp:all\r\n\r\n"
)

// discoverSSDP sends an SSDP M-SEARCH and collects UPnP device responses
// for the duration of timeout. Returns a map of IPv4 string → []ServiceInfo.
func discoverSSDP(ctx context.Context, timeout time.Duration) map[string][]ServiceInfo {
	results := make(map[string][]ServiceInfo)

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return results
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	dst, err := net.ResolveUDPAddr("udp4", ssdpMulticast)
	if err != nil {
		return results
	}
	if _, err := conn.WriteTo([]byte(ssdpMSearch), dst); err != nil {
		return results
	}

	seen := make(map[string]bool)
	buf := make([]byte, 4096)

	for {
		if ctx.Err() != nil {
			break
		}
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}

		headers := parseSSDPResponse(buf[:n])
		if headers == nil {
			continue
		}

		ip := addrToIP(addr)
		if ip == nil {
			continue
		}

		// Deduplicate by IP + USN
		key := ip.String() + headers["usn"]
		if seen[key] {
			continue
		}
		seen[key] = true

		details := []string{}
		if loc := headers["location"]; loc != "" {
			details = append(details, "location:"+loc)
		}
		if server := headers["server"]; server != "" {
			details = append(details, "server:"+server)
		}

		results[ip.String()] = append(results[ip.String()], ServiceInfo{
			Source:  "ssdp",
			Name:    headers["server"],
			Type:    headers["st"],
			Details: details,
		})
	}

	return results
}

// parseSSDPResponse parses an HTTP-like SSDP response into a header map.
// Returns nil if the first line isn't an HTTP 200 OK.
func parseSSDPResponse(data []byte) map[string]string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	if !scanner.Scan() {
		return nil
	}
	if !strings.HasPrefix(scanner.Text(), "HTTP/") {
		return nil
	}

	headers := make(map[string]string)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			headers[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
		}
	}
	return headers
}

func addrToIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP.To4()
	case *net.TCPAddr:
		return a.IP.To4()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host).To4()
}
