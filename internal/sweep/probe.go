package sweep

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"time"
)

// ProbeSpec describes one on-demand port probe.
type ProbeSpec struct {
	Port int
	Type string // "TCP", "SSH", "HTTP", "HTTPS", "FTP", "SMTP", "Telnet", "RDP", "Steam"
}

// ProbeResult is the outcome of one on-demand probe.
type ProbeResult struct {
	Port   int
	Type   string
	Result string // e.g. banner, "open", "timeout", "refused"
}

// CommonProbes is the set fired by "Run all common probes".
var CommonProbes = []ProbeSpec{
	{21, "FTP"},
	{22, "SSH"},
	{23, "Telnet"},
	{25, "SMTP"},
	{80, "HTTP"},
	{443, "HTTPS"},
	{445, "TCP"},
	{3306, "TCP"},
	{3389, "RDP"},
	{5900, "TCP"},
	{8080, "HTTP"},
	{8443, "HTTPS"},
	{27015, "Steam"},
}

// RunProbe executes spec against ip and returns the result.
// Honours ctx cancellation and clamps wall time to timeout.
func RunProbe(ctx context.Context, ip string, spec ProbeSpec, timeout time.Duration) ProbeResult {
	res := ProbeResult{Port: spec.Port, Type: spec.Type}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		res.Result = "invalid IP"
		return res
	}
	switch spec.Type {
	case "SSH":
		if v := probeSSHBanner(ctx, parsed, spec.Port, timeout); v != "" {
			res.Result = v
		} else {
			res.Result = probeTCPStatus(ctx, ip, spec.Port, timeout)
		}
	case "HTTP":
		if v := grabHTTP(ctx, parsed, spec.Port, false, timeout); v != "" {
			res.Result = v
		} else {
			res.Result = probeTCPStatus(ctx, ip, spec.Port, timeout)
		}
	case "HTTPS":
		if v := grabHTTP(ctx, parsed, spec.Port, true, timeout); v != "" {
			res.Result = v
		} else {
			res.Result = probeTCPStatus(ctx, ip, spec.Port, timeout)
		}
	case "FTP", "SMTP", "Telnet":
		if v := grabLineBanner(ctx, parsed, spec.Port, timeout); v != "" {
			res.Result = v
		} else {
			res.Result = probeTCPStatus(ctx, ip, spec.Port, timeout)
		}
	case "RDP":
		res.Result = probeRDP(ctx, parsed, spec.Port, timeout)
	case "Steam":
		if v := probeSteam(ctx, ip, spec.Port, timeout); v != "" {
			res.Result = v
		} else {
			res.Result = "no response"
		}
	default: // "TCP" or unknown
		res.Result = probeTCPStatus(ctx, ip, spec.Port, timeout)
	}
	return res
}

// probeTCPStatus tries a TCP connect and returns "open", "refused", or "timeout".
func probeTCPStatus(ctx context.Context, ip string, port int, timeout time.Duration) string {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err == nil {
		conn.Close()
		return "open"
	}
	s := err.Error()
	if strings.Contains(s, "refused") || strings.Contains(s, "actively refused") {
		return "refused"
	}
	return "timeout"
}

// probeSSHBanner connects to ip:port and reads the SSH identification string.
func probeSSHBanner(ctx context.Context, ip net.IP, port int, timeout time.Duration) string {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp",
		net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck
	sc := bufio.NewScanner(conn)
	if sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "SSH-") {
			if parts := strings.SplitN(line, "-", 3); len(parts) == 3 {
				return parts[2]
			}
		}
		return line
	}
	return ""
}

// probeRDP connects to ip:port and checks for a TPKT first byte (0x03).
func probeRDP(ctx context.Context, ip net.IP, port int, timeout time.Duration) string {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp",
		net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	if err != nil {
		s := err.Error()
		if strings.Contains(s, "refused") || strings.Contains(s, "actively refused") {
			return "refused"
		}
		return "timeout"
	}
	defer conn.Close()
	rdpTimeout := timeout
	if rdpTimeout > 2*time.Second {
		rdpTimeout = 2 * time.Second
	}
	conn.SetDeadline(time.Now().Add(rdpTimeout)) //nolint:errcheck
	buf := make([]byte, 4)
	n, _ := conn.Read(buf)
	if n >= 1 && buf[0] == 0x03 {
		return "RDP (TPKT)"
	}
	return "open"
}

// probeSteam sends a Valve A2S_INFO UDP query and returns a one-line summary
// of the discovered game server: name, map, and player count.
func probeSteam(ctx context.Context, ip string, port int, timeout time.Duration) string {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// A2S_INFO with 0xFF placeholder challenge (accepted by most servers).
	query := append(
		[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x54},
		append([]byte("Source Engine Query\x00"), 0xFF, 0xFF, 0xFF, 0xFF)...,
	)
	buf := make([]byte, 1400)

	for attempt := 0; attempt < 2; attempt++ {
		conn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck
		if _, err := conn.Write(query); err != nil {
			return ""
		}
		n, err := conn.Read(buf)
		if err != nil || n < 6 {
			return ""
		}
		if buf[4] == 0x41 && n >= 9 { // challenge → embed and retry
			query = append(
				[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x54},
				append([]byte("Source Engine Query\x00"), buf[5:9]...)...,
			)
			continue
		}
		if buf[4] != 0x49 { // not an A2S_INFO response
			return ""
		}
		// Skip: 4-byte simple header + type (0x49) + protocol byte.
		data := buf[6:n]
		name, data := readNullStr(data)
		mapName, data := readNullStr(data)
		_, data = readNullStr(data) // folder
		_, data = readNullStr(data) // game
		if len(data) < 4 {
			if name != "" {
				return name
			}
			return "Steam server"
		}
		// rest[0:2] = app ID (LE int16), rest[2] = players, rest[3] = max_players
		players := data[2]
		maxPlayers := data[3]
		if name == "" {
			return "Steam server"
		}
		return name + " [" + mapName + "] " +
			strconv.Itoa(int(players)) + "/" + strconv.Itoa(int(maxPlayers)) + " players"
	}
	return ""
}

// readNullStr extracts a null-terminated string from b and returns the remaining bytes.
func readNullStr(b []byte) (string, []byte) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:]
		}
	}
	return string(b), nil
}
