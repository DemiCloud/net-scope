package probes

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/demicloud/net-scope/internal/scan"
)

func registerMessaging() {
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "mqtt-deep", Group: "Messaging / IoT", Name: "MQTT CONNECT",
		DefaultPort: 1883, Transport: "TCP", Run: probeMQTTDeep,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "sip", Group: "Messaging / IoT", Name: "SIP OPTIONS",
		DefaultPort: 5060, Transport: "TCP", Run: probeSIP,
	})
}

// MQTT CONNECT packet — broker ID "probe", MQTT 3.1.1, no credentials.
var mqttConnect = []byte{
	0x10,       // fixed header: CONNECT
	0x11,       // remaining length = 17
	0x00, 0x04, // protocol name length = 4
	0x4D, 0x51, 0x54, 0x54, // "MQTT"
	0x04,       // protocol level = 4 (MQTT 3.1.1)
	0x02,       // connect flags: clean session only
	0x00, 0x3C, // keep-alive = 60 s
	0x00, 0x05, // client ID length = 5
	0x70, 0x72, 0x6F, 0x62, 0x65, // "probe"
}

func probeMQTTDeep(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (MQTT)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	emit("Sending CONNECT (anonymous client)…")
	if _, err := conn.Write(mqttConnect); err != nil {
		emit("Write failed: " + err.Error())
		return nil, nil
	}

	// Read CONNACK: fixed header (2 bytes) + variable header (2 bytes for MQTT 3.1.1).
	buf := make([]byte, 4)
	n, _ := io.ReadAtLeast(conn, buf, 4)
	if n < 4 {
		emit("No CONNACK received — may not be MQTT")
		return nil, nil
	}

	var result []scan.Observation
	switch {
	case buf[0] != 0x20: // CONNACK fixed header type
		emit(fmt.Sprintf("Unexpected packet type: 0x%02X (expected CONNACK 0x20)", buf[0]))

	case buf[3] == 0x00: // return code 0 = Connection Accepted
		emit("⚠  CRITICAL: MQTT broker accepted anonymous connection — no authentication!")
		result = append(result, obs("probe", "mqtt_auth", "none"))
		result = append(result, obs("probe", "mqtt_status", "accepted"))

	case buf[3] == 0x04: // return code 4 = Bad User Name or Password
		emit("Anonymous connection rejected — authentication required ✓")
		result = append(result, obs("probe", "mqtt_auth", "required"))
		result = append(result, obs("probe", "mqtt_status", "auth_required"))

	case buf[3] == 0x05: // return code 5 = Not Authorized
		emit("Connection not authorized — broker requires credentials ✓")
		result = append(result, obs("probe", "mqtt_auth", "required"))
		result = append(result, obs("probe", "mqtt_status", "not_authorized"))

	default:
		emit(fmt.Sprintf("CONNACK return code: 0x%02X", buf[3]))
		result = append(result, obs("probe", "mqtt_status", fmt.Sprintf("code_%02X", buf[3])))
	}
	return result, nil
}

func probeSIP(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (SIP)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	// Send a minimal SIP OPTIONS request to probe capabilities.
	target := fmt.Sprintf("sip:%s", ip)
	req := fmt.Sprintf(
		"OPTIONS %s SIP/2.0\r\n"+
			"Via: SIP/2.0/TCP %s;branch=z9hG4bKprobe\r\n"+
			"Max-Forwards: 1\r\n"+
			"To: <%s>\r\n"+
			"From: <sip:probe@probe.test>;tag=probe1\r\n"+
			"Call-ID: probe@probe.test\r\n"+
			"CSeq: 1 OPTIONS\r\n"+
			"Contact: <sip:probe@%s>\r\n"+
			"Accept: application/sdp\r\n"+
			"Content-Length: 0\r\n\r\n",
		target, ip, target, ip)
	emit("Sending OPTIONS request…")
	if _, err := fmt.Fprint(conn, req); err != nil {
		emit("Write failed: " + err.Error())
		return nil, nil
	}

	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if n == 0 {
		emit("No response to OPTIONS")
		return nil, nil
	}
	raw := string(buf[:n])
	emit("Response: " + firstLine(raw))
	var result []scan.Observation

	for _, line := range splitLines(raw) {
		lower := toLower(line)
		if hasPrefix(lower, "server:") {
			s := trimSpace(line[7:])
			emit("Server:   " + s)
			result = append(result, obs("probe", "sip_server", s))
		} else if hasPrefix(lower, "allow:") {
			methods := trimSpace(line[6:])
			emit("Methods:  " + methods)
			result = append(result, obs("probe", "sip_methods", methods))
		} else if hasPrefix(lower, "accept:") {
			result = append(result, obs("probe", "sip_accept", trimSpace(line[7:])))
		}
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Minimal string helpers to avoid importing strings in this file
// ---------------------------------------------------------------------------

func firstLine(s string) string {
	for i, c := range s {
		if c == '\r' || c == '\n' {
			return s[:i]
		}
	}
	return s
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			l := s[start:i]
			if len(l) > 0 && l[len(l)-1] == '\r' {
				l = l[:len(l)-1]
			}
			lines = append(lines, l)
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func hasPrefix(s, p string) bool { return strings.HasPrefix(s, p) }
func trimSpace(s string) string  { return strings.TrimSpace(s) }
