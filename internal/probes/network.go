package probes

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/demicloud/net-scope/internal/scan"
)

func registerNetwork() {
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "snmp-deep", Group: "Network", Name: "SNMP [sysDescr]",
		ServiceName: "SNMP Agent",
		DefaultPort: 161, Transport: "UDP", Run: probeSNMPDeep,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "dns-deep", Group: "Network", Name: "DNS [Version]",
		ServiceName: "DNS Server",
		DefaultPort: 53, Transport: "TCP", Run: probeDNSDeep,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "ntp", Group: "Network", Name: "NTP [Mode 6]",
		ServiceName: "NTP Server",
		DefaultPort: 123, Transport: "UDP", Run: probeNTP,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "wireguard", Group: "Network", Name: "WireGuard [Handshake]",
		ServiceName: "WireGuard VPN",
		DefaultPort: 51820, Transport: "UDP", Run: probeWireGuard,
	})
}

// probeSNMPDeep sends a minimal SNMP v1 GetRequest for sysDescr (1.3.6.1.2.1.1.1.0)
// with community "public" — the most common default.
func probeSNMPDeep(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Sending SNMP v1 GetRequest to %s…", joinHost(ip, port)))

	// Minimal SNMP v1 GetRequest, community "public", OID 1.3.6.1.2.1.1.1.0.
	snmpReq := []byte{
		// SEQUENCE (whole message)
		0x30, 0x26,
		// INTEGER version=0 (v1)
		0x02, 0x01, 0x00,
		// OCTET STRING "public"
		0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63,
		// GetRequest-PDU
		0xA0, 0x19,
		// request-id
		0x02, 0x04, 0x00, 0x00, 0x00, 0x01,
		// error-status
		0x02, 0x01, 0x00,
		// error-index
		0x02, 0x01, 0x00,
		// VarBind list
		0x30, 0x0B,
		// VarBind: OID 1.3.6.1.2.1.1.1.0, value NULL
		0x30, 0x09,
		0x06, 0x05, 0x2B, 0x06, 0x01, 0x02, 0x01,
		0x05, 0x00,
	}
	conn, err := dialUDP(ip, port, 5*time.Second)
	if err != nil {
		emit("Failed to open UDP socket: " + err.Error())
		return nil, nil
	}
	defer conn.Close()

	if _, err := conn.Write(snmpReq); err != nil {
		emit("Send failed: " + err.Error())
		return nil, nil
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil || n < 10 {
		emit("No SNMP response — community 'public' may be rejected or SNMP is disabled")
		return nil, nil
	}
	emit("Got SNMP response")

	// Scan for printable strings in the response payload = sysDescr value.
	raw := string(buf[:n])
	var result []scan.Observation
	if v := extractSNMPString(buf[:n]); v != "" {
		emit("sysDescr: " + v)
		result = append(result, obs("probe", "snmp_sysdescr", v))
		result = append(result, obs("probe", "snmp_community", "public"))
		emit("⚠  SNMP community 'public' is accepted — device information exposed!")
		_ = raw
	} else {
		emit("Response received but sysDescr not parseable")
	}
	return result, nil
}

// extractSNMPString finds the longest printable ASCII string (≥5 chars) in b.
func extractSNMPString(b []byte) string {
	var best string
	var cur []byte
	for _, c := range b {
		if c >= 0x20 && c < 0x7F {
			cur = append(cur, c)
		} else {
			if len(cur) > len(best) {
				best = string(cur)
			}
			cur = cur[:0]
		}
	}
	if len(cur) > len(best) {
		best = string(cur)
	}
	// Filter noise — must be at least 5 printable chars and not look like a community string.
	if len(best) < 5 || best == "public" || best == "private" {
		return ""
	}
	return best
}

// probeDNSDeep sends a version.bind CHAOS TXT query over TCP to reveal the
// server version string (published by ISC BIND and some others by default).
func probeDNSDeep(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (DNS/TCP)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	// version.bind TXT CHAOS query.
	// DNS wire format is well-known; we craft it manually.
	dnsQuery := []byte{
		// version.bind CHAOS TXT query, ID=0x1337
		0x13, 0x37, // ID
		0x00, 0x00, // flags (standard query)
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, // ANCOUNT=0
		0x00, 0x00, // NSCOUNT=0
		0x00, 0x00, // ARCOUNT=0
		// QNAME: 7 "version" 4 "bind" 0
		0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E,
		0x04, 0x62, 0x69, 0x6E, 0x64,
		0x00,
		0x00, 0x10, // QTYPE = TXT
		0x00, 0x03, // QCLASS = CHAOS (3)
	}
	// TCP DNS: prepend 2-byte length.
	pkt := make([]byte, 2+len(dnsQuery))
	binary.BigEndian.PutUint16(pkt, uint16(len(dnsQuery)))
	copy(pkt[2:], dnsQuery)

	emit("Sending version.bind CHAOS TXT query…")
	if _, err := conn.Write(pkt); err != nil {
		emit("Write failed: " + err.Error())
		return nil, nil
	}

	// Read response (TCP DNS: 2-byte length prefix).
	lenBuf := make([]byte, 2)
	if _, err := readN(conn, lenBuf); err != nil {
		emit("No DNS response")
		return nil, nil
	}
	msgLen := int(binary.BigEndian.Uint16(lenBuf))
	if msgLen < 12 || msgLen > 4096 {
		emit("Response length out of range")
		return nil, nil
	}
	resp := make([]byte, msgLen)
	if _, err := readN(conn, resp); err != nil {
		emit("Short read")
		return nil, nil
	}

	var result []scan.Observation
	// In the response, TXT RDATA is at a known offset IF there is one answer.
	// Rather than full DNS parsing, scan for printable strings of ≥5 chars.
	if v := extractDNSString(resp); v != "" {
		emit("version.bind: " + v)
		result = append(result, obs("probe", "dns_version", v))
	} else {
		emit("Server did not respond to version.bind query (good practice)")
	}
	return result, nil
}

func extractDNSString(b []byte) string {
	// Skip the 12-byte DNS header and question section.
	// Scan for printable runs ≥5 chars that look like version strings.
	if len(b) < 12 {
		return ""
	}
	var cur []byte
	var candidates []string
	for _, c := range b[12:] {
		if c >= 0x20 && c < 0x7F {
			cur = append(cur, c)
		} else {
			if len(cur) >= 5 {
				candidates = append(candidates, string(cur))
			}
			cur = cur[:0]
		}
	}
	if len(cur) >= 5 {
		candidates = append(candidates, string(cur))
	}
	// Return the candidate that looks most like a version string.
	for _, c := range candidates {
		lower := toLower(c)
		if strings.Contains(lower, "bind") ||
			strings.Contains(lower, "unbound") ||
			strings.Contains(lower, "powerdns") ||
			strings.Contains(lower, "dnsmasq") ||
			strings.Contains(lower, "named") ||
			containsDigit(c) && strings.Contains(c, ".") {
			return c
		}
	}
	return ""
}

func containsDigit(s string) bool {
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}

// probeNTP sends a minimal NTPv4 client request and parses the server response.
func probeNTP(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Sending NTP request to %s…", joinHost(ip, port)))
	conn, err := dialUDP(ip, port, 5*time.Second)
	if err != nil {
		emit("Failed to open UDP socket: " + err.Error())
		return nil, nil
	}
	defer conn.Close()

	// NTP client request: 48-byte packet, LI=0, VN=4, Mode=3 (client).
	req := make([]byte, 48)
	req[0] = 0x23 // LI=0, VN=4, Mode=3
	if _, err := conn.Write(req); err != nil {
		emit("Send failed: " + err.Error())
		return nil, nil
	}

	resp := make([]byte, 48)
	n, err := conn.Read(resp)
	if err != nil || n < 48 {
		emit("No NTP response received")
		return nil, nil
	}

	var result []scan.Observation
	// Byte 0: LI (bits 7-6), VN (bits 5-3), Mode (bits 2-0).
	mode := resp[0] & 0x07
	version := (resp[0] >> 3) & 0x07
	stratum := resp[1]

	emit(fmt.Sprintf("NTP server: version %d, mode %d, stratum %d", version, mode, stratum))
	result = append(result, obs("probe", "ntp_version", fmt.Sprintf("%d", version)))
	result = append(result, obs("probe", "ntp_stratum", fmt.Sprintf("%d", stratum)))

	switch stratum {
	case 0:
		emit("Stratum 0 — unspecified/invalid")
	case 1:
		emit("Stratum 1 — directly connected to reference clock (GPS/atomic)")
	default:
		emit(fmt.Sprintf("Stratum %d — synchronized (secondary source)", stratum))
	}

	// Reference ID (bytes 12-15): ASCII for stratum 1, IP for stratum 2+.
	refID := resp[12:16]
	if stratum == 1 {
		// Printable = GPS/PPS/ATOM type code.
		s := strings.TrimRight(string(refID), "\x00")
		if len(s) > 0 {
			emit("Reference:    " + s)
			result = append(result, obs("probe", "ntp_refid", s))
		}
	} else if stratum >= 2 {
		refIP := fmt.Sprintf("%d.%d.%d.%d", refID[0], refID[1], refID[2], refID[3])
		emit("Upstream:     " + refIP)
		result = append(result, obs("probe", "ntp_upstream", refIP))
	}
	return result, nil
}

// probeWireGuard sends a minimal WireGuard handshake-initiation packet (type=1,
// 148 bytes) to UDP port 51820 and checks for a handshake-response (type=2,
// 92 bytes).  WireGuard is intentionally silent — it will not respond to
// cryptographically invalid initiations — so a timeout here does not rule out
// a WireGuard endpoint; only a valid type=2 response is conclusive.
func probeWireGuard(_ context.Context, ip string, port int, _ scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Sending WireGuard handshake-initiation to %s (UDP)…", joinHost(ip, port)))

	conn, err := dialUDP(ip, port, 3*time.Second)
	if err != nil {
		emit("Failed to open UDP socket: " + err.Error())
		return nil, nil
	}
	defer conn.Close()

	// 148-byte handshake initiation: type=1 (LE uint32), sender_index (4 bytes),
	// unencrypted ephemeral key (32 bytes), encrypted static (48 bytes),
	// encrypted timestamp (28 bytes), mac1 (16 bytes), mac2 (16 bytes).
	// All fields beyond the type are zero — the handshake is cryptographically
	// invalid, but the packet length and type field are well-formed.
	pkt := make([]byte, 148)
	pkt[0] = 0x01 // message_type = 1 (initiation), reserved bytes 1-3 = 0

	if _, err := conn.Write(pkt); err != nil {
		emit("Send failed: " + err.Error())
		return nil, nil
	}

	conn.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil {
		// Timeout is the normal outcome: WireGuard drops invalid initiations silently.
		emit("No response received — WireGuard endpoints are intentionally silent to unauthenticated probes")
		emit("Note: silence on UDP 51820 does not rule out a WireGuard endpoint")
		return nil, nil
	}

	var result []scan.Observation
	// A genuine handshake response is type=2, exactly 92 bytes.
	if n >= 4 && resp[0] == 0x02 && resp[1] == 0x00 && resp[2] == 0x00 && resp[3] == 0x00 {
		emit("Received WireGuard handshake response (type=2) — endpoint confirmed!")
		result = append(result, obs("probe", "wireguard", "confirmed"))
		if n == 92 {
			emit("Response length matches WireGuard spec (92 bytes) ✓")
		}
	} else {
		emit(fmt.Sprintf("Received %d-byte UDP response; type byte=0x%02X — not a WireGuard handshake response", n, resp[0]))
	}
	return result, nil
}
