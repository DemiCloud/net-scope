package probes

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/demicloud/net-scope/internal/scan"
)

func registerDatabase() {
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "redis", Group: "Database", Name: "Redis [PING]",
		DefaultPort: 6379, Transport: "TCP", Run: probeRedis,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "mysql", Group: "Database", Name: "MySQL [Handshake]",
		DefaultPort: 3306, Transport: "TCP", Run: probeMySQL,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "mongodb", Group: "Database", Name: "MongoDB [hello]",
		DefaultPort: 27017, Transport: "TCP", Run: probeMongoDB,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "postgres", Group: "Database", Name: "PostgreSQL [Auth]",
		DefaultPort: 5432, Transport: "TCP", Run: probePostgres,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "memcached", Group: "Database", Name: "Memcached [stats]",
		DefaultPort: 11211, Transport: "TCP", Run: probeMemcached,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "elasticsearch", Group: "Database", Name: "Elasticsearch [Health]",
		DefaultPort: 9200, Transport: "TCP", Run: probeElasticsearch,
	})
}

func probeRedis(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (Redis)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	emit("Sending PING…")
	fmt.Fprintf(conn, "*1\r\n$4\r\nPING\r\n") //nolint:errcheck

	sc := bufio.NewScanner(conn)
	if !sc.Scan() {
		emit("No response to PING")
		return nil, nil
	}
	resp := sc.Text()
	emit("Response: " + resp)

	var result []scan.Observation
	switch {
	case resp == "+PONG" || strings.HasPrefix(resp, "+PONG"):
		emit("⚠  CRITICAL: Redis responds without authentication!")
		result = append(result, obs("probe", "redis_auth", "none"))

		// Fetch INFO server.
		conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
		emit("Fetching INFO server…")
		fmt.Fprintf(conn, "*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n") //nolint:errcheck
		// Skip the bulk header ($NNN\r\n).
		if sc.Scan() {
			_ = sc.Text() // e.g. "$2347"
		}
		for sc.Scan() {
			l := sc.Text()
			if l == "" {
				break
			}
			if strings.HasPrefix(l, "#") {
				continue
			}
			kv := strings.SplitN(l, ":", 2)
			if len(kv) != 2 {
				continue
			}
			k, v := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
			switch k {
			case "redis_version":
				emit("Version:  " + v)
				result = append(result, obs("probe", "version", v))
			case "os":
				emit("OS:       " + v)
				result = append(result, obs("probe", "redis_os", v))
			case "redis_mode":
				emit("Mode:     " + v)
				result = append(result, obs("probe", "redis_mode", v))
			case "role":
				emit("Role:     " + v)
				result = append(result, obs("probe", "redis_role", v))
			}
		}

	case strings.HasPrefix(resp, "-NOAUTH") || strings.Contains(resp, "WRONGPASS"):
		emit("Authentication required — server is protected ✓")
		result = append(result, obs("probe", "redis_auth", "required"))

	case strings.HasPrefix(resp, "-ERR"):
		emit("Error: " + resp)

	default:
		emit("Unexpected response: " + resp)
	}
	return result, nil
}

func probeMySQL(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (MySQL)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	// MySQL sends an initial handshake packet immediately on connect.
	// Packet format: 3-byte length (LE) + 1-byte sequence number + payload.
	hdr := make([]byte, 4)
	if _, err := readN(conn, hdr); err != nil {
		emit("No handshake received")
		return nil, nil
	}
	pktLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if pktLen < 1 || pktLen > 16384 {
		emit("Invalid packet length — may not be MySQL")
		return nil, nil
	}
	payload := make([]byte, pktLen)
	if _, err := readN(conn, payload); err != nil {
		emit("Short read: " + err.Error())
		return nil, nil
	}

	// Payload byte 0: protocol version (10 = MySQL 4.1+, 9 = very old).
	var result []scan.Observation
	switch payload[0] {
	case 0x0A: // Protocol 10
		// Null-terminated server version string starts at offset 1.
		end := 1
		for end < len(payload) && payload[end] != 0 {
			end++
		}
		if end < len(payload) {
			version := string(payload[1:end])
			emit("Version: " + version)
			result = append(result, obs("probe", "version", version))
		}
		// Capabilities at known offsets (protocol 10).
		if len(payload) >= 18 {
			caps := uint16(payload[len(payload)-4]) | uint16(payload[len(payload)-3])<<8
			_ = caps
		}
		emit("Protocol: MySQL 4.1+ (protocol version 10)")
		result = append(result, obs("probe", "mysql_proto", "10"))

	case 0xFF: // Error packet
		if len(payload) > 3 {
			emit("Server returned error: " + string(payload[3:]))
		}
	default:
		emit(fmt.Sprintf("Unknown protocol version: 0x%02X", payload[0]))
	}
	return result, nil
}

func probeMongoDB(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (MongoDB)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	// Minimal OP_MSG hello command.
	// Wire format: MsgHeader(16) + flagBits(4) + Section(type=0 + BSON doc).
	// BSON doc: { "hello": 1 } — length-prefixed little-endian.
	helloBSON := []byte{
		// BSON document: {"hello": 1}
		0x12, 0x00, 0x00, 0x00, // doc length = 18
		0x10,                   // type: int32
		0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x00, // key "hello\0"
		0x01, 0x00, 0x00, 0x00, // value: 1
		0x00,                   // trailing null
	}
	sectionLen := 1 + len(helloBSON) // type byte + doc
	msgBodyLen := 4 + sectionLen     // flagBits + section
	totalLen := 16 + msgBodyLen
	header := []byte{
		byte(totalLen), byte(totalLen >> 8), byte(totalLen >> 16), byte(totalLen >> 24),
		0x01, 0x00, 0x00, 0x00, // requestID
		0x00, 0x00, 0x00, 0x00, // responseTo
		0xDD, 0x07, 0x00, 0x00, // opCode = OP_MSG (2013)
		0x00, 0x00, 0x00, 0x00, // flagBits
		0x00,                   // section type = body
	}
	msg := append(header, helloBSON...)
	emit("Sending hello command…")
	if _, err := conn.Write(msg); err != nil {
		emit("Write failed: " + err.Error())
		return nil, nil
	}

	// Read response header (16 bytes).
	respHdr := make([]byte, 16)
	if _, err := readN(conn, respHdr); err != nil {
		emit("No response to hello command")
		return nil, nil
	}
	respLen := int(respHdr[0]) | int(respHdr[1])<<8 | int(respHdr[2])<<16 | int(respHdr[3])<<24
	if respLen < 20 || respLen > 65536 {
		emit("Response length out of range — may not be MongoDB")
		return nil, nil
	}
	body := make([]byte, respLen-16)
	readN(conn, body) //nolint:errcheck

	emit("Got MongoDB hello response")
	var result []scan.Observation

	// Scan BSON for known string fields (version, maxWireVersion, etc.).
	raw := string(body)
	if v := bsonStr(raw, "version"); v != "" {
		emit("Version:        " + v)
		result = append(result, obs("probe", "version", v))
	}
	if v := bsonStr(raw, "setName"); v != "" {
		emit("Replica set:    " + v)
		result = append(result, obs("probe", "mongo_replset", v))
	}
	if v := bsonStr(raw, "me"); v != "" {
		emit("Node address:   " + v)
	}
	// Check ismaster/isMaster (bool at offset after key).
	if strings.Contains(raw, "ismaster") || strings.Contains(raw, "isMaster") {
		emit("Role:           primary/standalone")
		result = append(result, obs("probe", "mongo_role", "primary"))
	}
	if len(result) == 0 {
		emit("Got a response but could not parse version — server may require auth")
	}
	return result, nil
}

func probePostgres(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (PostgreSQL)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	// Startup Message: int32 length (8), int32 protocol (196608 = 3.0), terminated by 0.
	startup := []byte{
		0x00, 0x00, 0x00, 0x08, // length = 8
		0x00, 0x03, 0x00, 0x00, // protocol 3.0
	}
	emit("Sending startup message…")
	if _, err := conn.Write(startup); err != nil {
		emit("Write failed: " + err.Error())
		return nil, nil
	}

	resp := make([]byte, 256)
	n, _ := conn.Read(resp)
	if n < 5 {
		emit("No response — may not be PostgreSQL")
		return nil, nil
	}

	msgType := resp[0]
	var result []scan.Observation
	switch msgType {
	case 'R': // Authentication
		authType := int(resp[1])<<24 | int(resp[2])<<16 | int(resp[3])<<8 | int(resp[4])
		var authName string
		switch authType {
		case 0:
			authName = "trust (no auth required)"
			emit("⚠  CRITICAL: Authentication type is TRUST — no password required!")
			result = append(result, obs("probe", "pg_auth", "trust"))
		case 3:
			authName = "cleartext password"
			emit("⚠  Cleartext password auth — credentials transmitted unencrypted")
			result = append(result, obs("probe", "pg_auth", "cleartext"))
		case 5:
			authName = "MD5 password"
			result = append(result, obs("probe", "pg_auth", "md5"))
		case 10:
			authName = "SASL (SCRAM)"
			result = append(result, obs("probe", "pg_auth", "sasl"))
		default:
			authName = fmt.Sprintf("type %d", authType)
		}
		emit("Auth method:    " + authName)

	case 'E': // Error
		// Error message follows as key=value pairs terminated by '\0'.
		msg := errorFieldsFromPG(resp[5:n])
		emit("Server error:   " + msg)
		result = append(result, obs("probe", "pg_error", msg))

	case 'S': // Parameter Status — PostgreSQL is responding normally
		// Some servers send ParameterStatus before auth request.
		// Parse as many key/value pairs as we can.
		emit("Got ParameterStatus (server is responding)")
		for i := 5; i < n; i++ {
			// Each parameter is key\0value\0
			kEnd := indexOf(resp[i:n], 0)
			if kEnd < 0 {
				break
			}
			k := string(resp[i : i+kEnd])
			i += kEnd + 1
			vEnd := indexOf(resp[i:n], 0)
			if vEnd < 0 {
				break
			}
			v := string(resp[i : i+vEnd])
			i += vEnd
			if k == "server_version" {
				emit("Version:        " + v)
				result = append(result, obs("probe", "version", v))
			}
		}

	default:
		emit(fmt.Sprintf("Unexpected response type: '%c' (0x%02X)", msgType, msgType))
	}
	return result, nil
}

func probeMemcached(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (Memcached)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	emit("Sending stats command…")
	fmt.Fprintf(conn, "stats\r\n") //nolint:errcheck

	sc := bufio.NewScanner(conn)
	var result []scan.Observation
	linesRead := 0
	for sc.Scan() {
		l := sc.Text()
		if l == "END" {
			break
		}
		// STAT key value
		parts := strings.Fields(l)
		if len(parts) != 3 || parts[0] != "STAT" {
			// Anything that isn't a STAT line = memcached not responding correctly.
			if linesRead == 0 {
				emit("Unexpected response — may not be Memcached: " + l)
			}
			break
		}
		k, v := parts[1], parts[2]
		switch k {
		case "version":
			emit("Version:          " + v)
			result = append(result, obs("probe", "version", v))
		case "curr_connections":
			emit("Connections:      " + v)
			result = append(result, obs("probe", "memcached_connections", v))
		case "bytes":
			emit("Memory used (B):  " + v)
		case "limit_maxbytes":
			emit("Memory limit (B): " + v)
		case "uptime":
			emit("Uptime (s):       " + v)
		}
		linesRead++
	}
	if len(result) > 0 {
		emit("⚠  Memcached responded without authentication — data may be exposed!")
	}
	return result, nil
}

func probeElasticsearch(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (Elasticsearch)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	emit("Sending GET /…")
	req := "GET / HTTP/1.0\r\nHost: " + joinHost(ip, port) + "\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
	fmt.Fprint(conn, req) //nolint:errcheck

	sc := bufio.NewScanner(conn)
	var result []scan.Observation
	inBody := false
	for sc.Scan() {
		l := sc.Text()
		if !inBody {
			if l == "" {
				inBody = true
			}
			if strings.HasPrefix(l, "HTTP/") {
				emit("Status: " + l)
				result = append(result, obs("probe", "es_status", l))
			}
			continue
		}
		// Parse key fields from JSON body inline (no JSON library needed for simple cases).
		if v := jsonStr(l, "number"); v != "" {
			emit("Version:          " + v)
			result = append(result, obs("probe", "version", v))
		}
		if v := jsonStr(l, "cluster_name"); v != "" {
			emit("Cluster:          " + v)
			result = append(result, obs("probe", "es_cluster", v))
		}
		if v := jsonStr(l, "name"); v != "" && !strings.Contains(l, "cluster_name") {
			emit("Node:             " + v)
		}
	}
	if len(result) == 0 {
		emit("No Elasticsearch response or authentication required")
	} else {
		emit("⚠  Elasticsearch responded without authentication — cluster data may be exposed!")
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// readN reads exactly len(buf) bytes from conn.
func readN(conn interface {
	Read([]byte) (int, error)
}, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// bsonStr naively extracts a string value from a BSON document by matching
// the key as a substring of the raw bytes. Not a full BSON decoder.
func bsonStr(raw, key string) string {
	idx := strings.Index(raw, key+"\x00")
	if idx < 0 {
		return ""
	}
	// Skip past key + null terminator.
	i := idx + len(key) + 1
	if i >= len(raw) {
		return ""
	}
	// BSON string: 4-byte LE length + bytes + null.
	if len(raw)-i < 5 {
		return ""
	}
	sLen := int(raw[i]) | int(raw[i+1])<<8 | int(raw[i+2])<<16 | int(raw[i+3])<<24
	i += 4
	if sLen <= 0 || i+sLen > len(raw) {
		return ""
	}
	val := raw[i : i+sLen]
	// Strip trailing nulls.
	val = strings.TrimRight(val, "\x00")
	// Reject non-printable strings.
	for _, c := range val {
		if c < 0x20 && c != '\n' && c != '\r' {
			return ""
		}
	}
	return val
}

// jsonStr extracts "key": "value" from a single JSON line without importing encoding/json.
func jsonStr(line, key string) string {
	needle := `"` + key + `"`
	i := strings.Index(line, needle)
	if i < 0 {
		return ""
	}
	i += len(needle)
	// Find the colon.
	for i < len(line) && (line[i] == ' ' || line[i] == ':') {
		i++
	}
	if i >= len(line) || line[i] != '"' {
		return ""
	}
	i++ // skip opening quote
	j := strings.Index(line[i:], `"`)
	if j < 0 {
		return ""
	}
	return line[i : i+j]
}

// errorFieldsFromPG extracts the message (M) field from a PostgreSQL error payload.
func errorFieldsFromPG(b []byte) string {
	for i := 0; i < len(b); {
		fType := b[i]
		i++
		end := indexOf(b[i:], 0)
		if end < 0 {
			break
		}
		val := string(b[i : i+end])
		i += end + 1
		if fType == 'M' {
			return val
		}
	}
	return "(no message)"
}

// indexOf returns the index of sep in b, or -1.
func indexOf(b []byte, sep byte) int {
	for i, c := range b {
		if c == sep {
			return i
		}
	}
	return -1
}
