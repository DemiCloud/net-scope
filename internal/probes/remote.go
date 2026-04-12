package probes

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/demicloud/net-scope/internal/scan"
)

func registerRemote() {
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "ssh", Group: "Remote Access", Name: "SSH [Banner]",
		ServiceName: "SSH Server",
		DefaultPort: 22, Transport: "TCP", Run: probeSSH,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "rdp-deep", Group: "Remote Access", Name: "RDP [Negotiate]",
		ServiceName: "Remote Desktop",
		DefaultPort: 3389, Transport: "TCP", Run: probeRDPDeep,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "vnc", Group: "Remote Access", Name: "VNC [Security]",
		ServiceName: "VNC Server",
		DefaultPort: 5900, Transport: "TCP", Run: probeVNC,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "telnet", Group: "Remote Access", Name: "Telnet [Banner]",
		ServiceName: "Telnet Service",
		DefaultPort: 23, Transport: "TCP", Run: probeTelnet,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "rsync", Group: "Remote Access", Name: "rsync [Modules]",
		ServiceName: "rsync Server",
		DefaultPort: 873, Transport: "TCP", Run: probeRsync,
	})
}

func probeSSH(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (SSH)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	banner, err := readLine(conn)
	if err != nil {
		emit("No banner received")
		return nil, nil
	}
	emit("Banner: " + banner)
	var result []scan.Observation
	result = append(result, obs("probe", "banner", banner))

	if strings.HasPrefix(banner, "SSH-") {
		parts := strings.SplitN(banner, "-", 3)
		if len(parts) == 3 {
			version := parts[1] // e.g. "2.0"
			software := parts[2] // e.g. "OpenSSH_9.3p2 Ubuntu-1"
			emit("Protocol version: SSH-" + version)
			emit("Software:         " + software)
			result = append(result, obs("probe", "ssh_version", version))
			result = append(result, obs("probe", "software", software))

			// Extract just the product name (before the first space)
			product := software
			if i := strings.Index(software, " "); i > 0 {
				product = software[:i]
			}
			if i := strings.Index(product, "_"); i > 0 {
				ver := product[i+1:]
				product = product[:i]
				emit("Product:          " + product + " " + ver)
				result = append(result, obs("probe", "ssh_software", product))
				result = append(result, obs("probe", "ssh_software_version", ver))
			}
		}
	}
	return result, nil
}

// probeRDPDeep performs the X.224 Connection Request / Confirm exchange and
// checks for Network Level Authentication (NLA) requirement.
func probeRDPDeep(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (RDP)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	emit("Sending X.224 Connection Request…")
	// T.125 / T.128 RDP Connection Request with negotiation request (NegReq).
	// Requests TLS (sec type 1), CredSSP/NLA (sec type 2), and RDPTLS (sec type 4).
	x224CR := []byte{
		// TPKT header: version=3, reserved=0, length=23 (big-endian uint16)
		0x03, 0x00, 0x00, 0x13,
		// X.224 COTP CR PDU length=14 (excludes length byte), CR code=0xE0
		0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
		// RDP Negotiation Request: type=1, flags=0, length=8, requestedProtocols=3 (TLS+CredSSP)
		0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
	}
	if _, err := conn.Write(x224CR); err != nil {
		emit("Write failed: " + err.Error())
		return nil, nil
	}

	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if n < 4 {
		emit("No RDP response (closed or not an RDP server)")
		return nil, nil
	}
	// TPKT version must be 3.
	if buf[0] != 0x03 {
		emit("Response is not TPKT (not an RDP server)")
		return nil, nil
	}
	emit("Got X.224 Connection Confirm")
	var result []scan.Observation
	result = append(result, obs("probe", "rdp_listening", "true"))

	// Parse RDP Negotiation Response (starts at byte 11 if present).
	if n >= 19 {
		respType := buf[11]
		switch respType {
		case 0x02: // Negotiation Response
			proto := uint32(buf[15]) | uint32(buf[16])<<8 | uint32(buf[17])<<16 | uint32(buf[18])<<24
			var protos []string
			if proto&0x01 != 0 {
				protos = append(protos, "TLS")
			}
			if proto&0x02 != 0 {
				protos = append(protos, "CredSSP (NLA)")
			}
			if proto&0x04 != 0 {
				protos = append(protos, "RDSTLS")
			}
			supported := joinStrings(protos, ", ")
			emit("Security:         " + supported)
			result = append(result, obs("probe", "rdp_security", supported))
			if proto&0x02 != 0 {
				emit("NLA required:     yes")
				result = append(result, obs("probe", "rdp_nla", "required"))
			} else {
				emit("⚠  NLA not required — password capture possible")
				result = append(result, obs("probe", "rdp_nla", "not required"))
			}
		case 0x03: // Negotiation Failure
			code := uint32(buf[15]) | uint32(buf[16])<<8 | uint32(buf[17])<<16 | uint32(buf[18])<<24
			emit(fmt.Sprintf("Negotiation failure code: 0x%08X", code))
		}
	}
	return result, nil
}

func probeVNC(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (VNC)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	// Server sends its version first.
	buf := make([]byte, 12)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		emit("No VNC version banner received")
		return nil, nil
	}
	version := strings.TrimRight(string(buf[:n]), "\n\r")
	emit("Server version: " + version)
	var result []scan.Observation
	result = append(result, obs("probe", "vnc_version", version))

	// Reply with the same version (or a downgrade we can parse).
	if _, err := conn.Write(buf[:12]); err != nil {
		return result, nil
	}

	// For RFB 3.7+, server sends: 1 byte = number of security types, then that many bytes.
	secBuf := make([]byte, 1)
	if _, err := conn.Read(secBuf); err != nil {
		return result, nil
	}
	count := int(secBuf[0])
	if count == 0 {
		emit("Server reported connection failure")
		return result, nil
	}
	types := make([]byte, count)
	if _, err := io.ReadFull(conn, types); err != nil {
		return result, nil
	}
	var secNames []string
	noAuth := false
	for _, t := range types {
		switch t {
		case 1:
			secNames = append(secNames, "None (no auth)")
			noAuth = true
		case 2:
			secNames = append(secNames, "VNC Authentication")
		case 16:
			secNames = append(secNames, "Tight")
		case 18:
			secNames = append(secNames, "TLS")
		case 19:
			secNames = append(secNames, "VeNCrypt")
		default:
			secNames = append(secNames, fmt.Sprintf("Type %d", t))
		}
	}
	secStr := joinStrings(secNames, ", ")
	emit("Security types:   " + secStr)
	result = append(result, obs("probe", "vnc_security", secStr))
	if noAuth {
		emit("⚠  CRITICAL: No authentication — VNC accessible without password!")
		result = append(result, obs("probe", "vnc_no_auth", "true"))
	}
	return result, nil
}

func probeTelnet(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (Telnet)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck

	// Read up to 512 bytes — strip Telnet IAC negotiation sequences for display.
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	raw := buf[:n]
	banner := strippedTelnet(raw)
	if banner == "" {
		emit("No banner received")
		return nil, nil
	}
	for _, line := range strings.Split(banner, "\n") {
		l := strings.TrimSpace(line)
		if l != "" {
			emit(l)
		}
	}
	return []scan.Observation{obs("probe", "banner", strings.TrimSpace(banner))}, nil
}

// strippedTelnet removes IAC escape sequences so the banner is printable.
func strippedTelnet(b []byte) string {
	var out []byte
	for i := 0; i < len(b); {
		if b[i] == 0xFF && i+2 < len(b) { // IAC
			i += 3 // skip IAC command option
			continue
		}
		if b[i] == 0xFF && i+1 < len(b) { // IAC + short
			i += 2
			continue
		}
		if b[i] >= 0x20 || b[i] == '\n' || b[i] == '\r' {
			out = append(out, b[i])
		}
		i++
	}
	return string(out)
}

func probeRsync(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (rsync)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	sc := bufio.NewScanner(conn)
	if !sc.Scan() {
		emit("No greeting received")
		return nil, nil
	}
	greeting := sc.Text()
	emit("Greeting: " + greeting)
	var result []scan.Observation
	result = append(result, obs("probe", "rsync_version", greeting))

	if !strings.HasPrefix(greeting, "@RSYNCD:") {
		emit("Not an rsync server")
		return result, nil
	}

	// Request module list.
	conn.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	fmt.Fprintln(conn, "#list") //nolint:errcheck
	emit("Requesting module list…")
	var modules []string
	for sc.Scan() {
		l := sc.Text()
		if l == "@RSYNCD: EXIT" {
			break
		}
		modules = append(modules, l)
		emit("  Module: " + l)
	}
	if len(modules) > 0 {
		emit(fmt.Sprintf("⚠  %d anonymous module(s) listed — check for sensitive shares", len(modules)))
		result = append(result, obs("probe", "rsync_modules", joinStrings(modules, "; ")))
	} else {
		emit("No anonymous modules listed")
	}
	return result, nil
}
