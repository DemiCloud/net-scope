package scan

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ---------------------------------------------------------------------------
// SMB probe
// ---------------------------------------------------------------------------

// smbv2NegotiateReq is a minimal SMBv2 NEGOTIATE request offering dialects
// 2.0.2, 2.1, 3.0, 3.0.2, and 3.1.1. NetBIOS transport header included.
var smbv2NegotiateReq = []byte{
	// NetBIOS Session Message header: type=0, length=110 (0x6E)
	0x00, 0x00, 0x00, 0x6E,
	// SMBv2 Header (64 bytes)
	0xFE, 0x53, 0x4D, 0x42, // ProtocolId = "\xFESMB"
	0x40, 0x00,             // StructureSize = 64
	0x00, 0x00,             // CreditCharge = 0
	0x00, 0x00, 0x00, 0x00, // Status = 0
	0x00, 0x00,             // Command = NEGOTIATE (0x0000)
	0x01, 0x00,             // CreditRequest = 1
	0x00, 0x00, 0x00, 0x00, // Flags = 0
	0x00, 0x00, 0x00, 0x00, // NextCommand = 0
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MessageId = 0
	0x00, 0x00, 0x00, 0x00, // Reserved
	0xFF, 0xFE, 0x00, 0x00, // TreeId = 0
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SessionId = 0
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature[0:8]
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature[8:16]
	// NEGOTIATE request body (46 bytes)
	0x24, 0x00, // StructureSize = 36
	0x05, 0x00, // DialectCount = 5
	0x01, 0x00, // SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED
	0x00, 0x00, // Reserved
	0x7F, 0x00, 0x00, 0x00, // Capabilities = all common caps
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientGuid[0:8]
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientGuid[8:16]
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientStartTime = 0
	0x02, 0x02, // Dialect: SMB 2.0.2
	0x10, 0x02, // Dialect: SMB 2.1
	0x00, 0x03, // Dialect: SMB 3.0
	0x02, 0x03, // Dialect: SMB 3.0.2
	0x11, 0x03, // Dialect: SMB 3.1.1
}

// smbv1NegotiateReq is a minimal SMBv1 NEGOTIATE request offering only the
// "NT LM 0.12" dialect. Used to probe whether SMBv1 is still enabled.
var smbv1NegotiateReq = []byte{
	// NetBIOS Session Message header: type=0, length=47 (0x2F)
	0x00, 0x00, 0x00, 0x2F,
	// SMBv1 Header (32 bytes: \xFFSMB + command + status + flags + ...)
	0xFF, 0x53, 0x4D, 0x42, // \xFFSMB
	0x72,                   // Command = SMB_COM_NEGOTIATE
	0x00, 0x00, 0x00, 0x00, // NT Status = 0
	0x18,                   // Flags
	0x01, 0x28,             // Flags2
	0x00, 0x00,             // PID High
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Security Signature
	0x00, 0x00, // Reserved
	0x00, 0x00, // TreeID
	0x2F, 0x4B, // ProcessID
	0x00, 0x00, // UserID
	0xC5, 0xE2, // MultiplexID
	// Parameters + Data
	0x00,       // WordCount = 0
	0x0C, 0x00, // ByteCount = 12
	// Dialect string: format=0x02 + "NT LM 0.12" + NUL
	0x02, 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
}

// smbDialectString converts an SMBv2 DialectRevision value to a display string.
func smbDialectString(dialect uint16) string {
	switch dialect {
	case 0x0202:
		return "SMB 2.0.2"
	case 0x0210:
		return "SMB 2.1"
	case 0x0300:
		return "SMB 3.0"
	case 0x0302:
		return "SMB 3.0.2"
	case 0x0311:
		return "SMB 3.1.1"
	case 0x02FF:
		return "SMB 2.x (multi-protocol)"
	default:
		if dialect >= 0x0200 && dialect <= 0x03FF {
			return fmt.Sprintf("SMB %d.%d", (dialect>>8)&0xFF, dialect&0xFF)
		}
		return fmt.Sprintf("SMB 0x%04X", dialect)
	}
}

// probeSMB attempts to fingerprint the SMB server at ip:port.
// Returns nil when the host does not respond with a valid SMBv2 NEGOTIATE.
// On success the returned map contains:
//
//	"smb_dialect" – highest negotiated dialect (e.g. "SMB 3.1.1")
//	"smb1"        – "true" if the server also accepts SMBv1 connections
func probeSMB(ctx context.Context, ip net.IP, port int, timeout time.Duration, dial DialFunc) map[string]string {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	// --- SMBv2 probe ---
	conn, err := dialOrDirect(dial)(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck

	if _, err := conn.Write(smbv2NegotiateReq); err != nil {
		return nil
	}

	var nbHdr [4]byte
	if _, err := io.ReadFull(conn, nbHdr[:]); err != nil {
		return nil
	}
	msgLen := binary.BigEndian.Uint32(nbHdr[:]) & 0x00FFFFFF
	if msgLen < 70 || msgLen > 65535 {
		return nil
	}

	resp := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil
	}

	// Validate SMBv2 response: ProtocolId = \xFE S M B, Command = NEGOTIATE.
	if len(resp) < 70 || resp[0] != 0xFE || resp[1] != 0x53 || resp[2] != 0x4D || resp[3] != 0x42 {
		return nil
	}
	if resp[12] != 0x00 || resp[13] != 0x00 { // Command must be NEGOTIATE
		return nil
	}

	// DialectRevision at offset 68 within the SMBv2 payload (after 64-byte
	// header: StructureSize[2] + SecurityMode[2] = 4 bytes, then DialectRevision).
	// In resp[] (which starts at the SMBv2 header): offset 64+4 = 68.
	if len(resp) < 70 {
		return nil
	}
	dialect := binary.LittleEndian.Uint16(resp[68:70])

	result := map[string]string{
		"smb_dialect": smbDialectString(dialect),
	}

	// --- SMBv1 probe on a separate connection ---
	smb1 := false
	func() {
		c2, err := dialOrDirect(dial)(ctx, "tcp", addr)
		if err != nil {
			return
		}
		defer c2.Close()
		half := timeout / 2
		if half < 300*time.Millisecond {
			half = 300 * time.Millisecond
		}
		c2.SetDeadline(time.Now().Add(half)) //nolint:errcheck

		if _, err := c2.Write(smbv1NegotiateReq); err != nil {
			return
		}
		var hdr2 [4]byte
		if _, err := io.ReadFull(c2, hdr2[:]); err != nil {
			return
		}
		l2 := binary.BigEndian.Uint32(hdr2[:]) & 0x00FFFFFF
		if l2 < 4 {
			return
		}
		peek := make([]byte, 4)
		if _, err := io.ReadFull(c2, peek); err != nil {
			return
		}
		// SMBv1 response header signature: \xFFSMB.
		if peek[0] == 0xFF && peek[1] == 0x53 && peek[2] == 0x4D && peek[3] == 0x42 {
			smb1 = true
		}
	}()

	if smb1 {
		result["smb1"] = "true"
	} else {
		result["smb1"] = "false"
	}
	return result
}

// ---------------------------------------------------------------------------
// DNS probe
// ---------------------------------------------------------------------------

// probeDNSPort queries the DNS server at ip:53 over TCP and returns:
//
//	"dns_recursion" – "true" if the RA bit is set in the response
//	"dns_server"    – software version from version.bind TXT query (BIND only)
//
// Returns nil when it cannot establish a TCP connection to port 53.
func probeDNSPort(ctx context.Context, ip net.IP, timeout time.Duration, dial DialFunc) map[string]string {
	addr := net.JoinHostPort(ip.String(), "53")
	conn, err := dialOrDirect(dial)(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck

	result := map[string]string{}

	// Build a DNS query for . (root) NS with RD bit set.
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0x4E53, RecursionDesired: true},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName("."),
				Type:  dnsmessage.TypeNS,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	pkt, err := msg.Pack()
	if err != nil {
		return nil
	}

	// DNS over TCP: 2-byte big-endian length prefix.
	tcpBuf := make([]byte, 2+len(pkt))
	binary.BigEndian.PutUint16(tcpBuf, uint16(len(pkt)))
	copy(tcpBuf[2:], pkt)

	if _, err := conn.Write(tcpBuf); err != nil {
		return nil
	}

	// Read 2-byte length, then the response.
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil
	}
	respLen := binary.BigEndian.Uint16(lenBuf[:])
	if respLen < 12 || respLen > 4096 {
		return nil
	}
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil
	}

	var resp dnsmessage.Message
	if err := resp.Unpack(respBuf); err != nil {
		return nil
	}

	if resp.Header.RecursionAvailable {
		result["dns_recursion"] = "true"
	} else {
		result["dns_recursion"] = "false"
	}

	// Try version.bind CHAOS TXT query for server software identification.
	// Many servers won't respond; that is fine — we proceed without a version.
	func() {
		vb := dnsmessage.Message{
			Header: dnsmessage.Header{ID: 0x4E54},
			Questions: []dnsmessage.Question{
				{
					Name:  dnsmessage.MustNewName("version.bind."),
					Type:  dnsmessage.TypeTXT,
					Class: dnsmessage.ClassCHAOS,
				},
			},
		}
		vbPkt, err := vb.Pack()
		if err != nil {
			return
		}
		vbBuf := make([]byte, 2+len(vbPkt))
		binary.BigEndian.PutUint16(vbBuf, uint16(len(vbPkt)))
		copy(vbBuf[2:], vbPkt)

		conn.SetDeadline(time.Now().Add(timeout / 2)) //nolint:errcheck
		if _, err := conn.Write(vbBuf); err != nil {
			return
		}
		var vbLen [2]byte
		if _, err := io.ReadFull(conn, vbLen[:]); err != nil {
			return
		}
		vbRespLen := binary.BigEndian.Uint16(vbLen[:])
		if vbRespLen < 12 || vbRespLen > 512 {
			return
		}
		vbRespBuf := make([]byte, vbRespLen)
		if _, err := io.ReadFull(conn, vbRespBuf); err != nil {
			return
		}
		var vbResp dnsmessage.Message
		if err := vbResp.Unpack(vbRespBuf); err != nil {
			return
		}
		for _, ans := range vbResp.Answers {
			if ans.Header.Type == dnsmessage.TypeTXT {
				if txt, ok := ans.Body.(*dnsmessage.TXTResource); ok && len(txt.TXT) > 0 {
					ver := strings.Join(txt.TXT, " ")
					if ver != "" {
						result["dns_server"] = ver
					}
				}
			}
		}
	}()

	return result
}

// ---------------------------------------------------------------------------
// LDAP probe
// ---------------------------------------------------------------------------

// ldapRootDSEQuery is a BER-encoded LDAP SearchRequest for the RootDSE entry
// (baseObject = "", scope = baseObject, filter = present(objectClass),
// attributes = all). Length-39 wire message.
var ldapRootDSEQuery = []byte{
	0x30, 0x25, // LDAPMessage SEQUENCE, length 37
	0x02, 0x01, 0x01, // messageID = 1
	0x63, 0x20, // searchRequest [3], length 32
	0x04, 0x00, // baseObject = "" (RootDSE)
	0x0A, 0x01, 0x00, // scope = baseObject (0)
	0x0A, 0x01, 0x00, // derefAliases = neverDeref (0)
	0x02, 0x01, 0x00, // sizeLimit = 0
	0x02, 0x01, 0x00, // timeLimit = 0 (caller's conn deadline applies)
	0x01, 0x01, 0x00, // typesOnly = FALSE
	// Filter: present("objectClass") — tag 0x87 = context[7] primitive
	0x87, 0x0B,
	0x6F, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x43, 0x6C, 0x61, 0x73, 0x73, // "objectClass"
	// Attributes: SEQUENCE OF { } — empty = return all user attributes
	0x30, 0x00,
}

// probeLDAP sends a minimally-anonymous RootDSE LDAP SearchRequest and parses
// the response to identify Active Directory / OpenLDAP servers.
// Returns nil when the port does not speak LDAP.
// On success the returned map may contain:
//
//	"ldap_domain"  – AD domain deduced from defaultNamingContext
//	"ldap_version" – supported LDAP protocol version(s)
func probeLDAP(ctx context.Context, ip net.IP, port int, timeout time.Duration, dial DialFunc) map[string]string {
	conn, err := dialOrDirect(dial)(ctx, "tcp", net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck

	if _, err := conn.Write(ldapRootDSEQuery); err != nil {
		return nil
	}

	// Read up to 4 KB of response. We only need a handful of attribute values.
	respBuf := make([]byte, 4096)
	n, err := conn.Read(respBuf)
	if n < 4 || err != nil && n == 0 {
		return nil
	}
	respBuf = respBuf[:n]

	// Validate: first byte must be 0x30 (SEQUENCE = valid LDAP message).
	if respBuf[0] != 0x30 {
		return nil
	}

	result := map[string]string{}

	// Extract attribute values by scanning for known attribute name strings.
	// This avoids a full BER decoder while remaining reliable for our targets.
	raw := string(respBuf)
	if v := ldapExtractAttr(raw, "defaultNamingContext"); v != "" {
		// Convert "DC=corp,DC=example,DC=com" → "corp.example.com".
		result["ldap_domain"] = dcToFQDN(v)
	}
	if v := ldapExtractAttr(raw, "supportedLDAPVersion"); v != "" {
		result["ldap_version"] = v
	}

	return result
}

// ldapExtractAttr searches the raw BER-decoded bytes (treated as a string) for
// the named attribute and returns its first value. This works because LDAP
// attribute names and string values appear as literal UTF-8 in BER, surrounded
// only by length bytes we can skip.
func ldapExtractAttr(raw, name string) string {
	idx := strings.Index(raw, name)
	if idx < 0 {
		return ""
	}
	// Skip past the attribute name + BER overhead (≤ 4 bytes).
	pos := idx + len(name)
	// Find the next 0x04 (OCTET STRING) tag after the name.
	for i := pos; i < len(raw)-3 && i < pos+16; i++ {
		if raw[i] == 0x04 {
			vlen := int(raw[i+1])
			start := i + 2
			end := start + vlen
			if vlen > 0 && end <= len(raw) {
				v := raw[start:end]
				// Filter out non-printable results (binary values).
				if isPrintableASCII(v) {
					return strings.TrimSpace(v)
				}
			}
			break
		}
	}
	return ""
}

// dcToFQDN converts an LDAP distinguishedName like "DC=corp,DC=example,DC=com"
// to a dot-separated FQDN "corp.example.com". Non-DC components are ignored.
func dcToFQDN(dn string) string {
	var parts []string
	for _, comp := range strings.Split(dn, ",") {
		comp = strings.TrimSpace(comp)
		up := strings.ToUpper(comp)
		if strings.HasPrefix(up, "DC=") {
			parts = append(parts, comp[3:])
		}
	}
	if len(parts) == 0 {
		return dn // return as-is if not a DC-style DN
	}
	return strings.Join(parts, ".")
}

// isPrintableASCII reports whether every byte of s is a printable ASCII character.
func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b > 0x7E {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// MQTT probe
// ---------------------------------------------------------------------------

// mqttConnectPkt is a minimal MQTT 3.1.1 CONNECT with no credentials and an
// empty client ID. Remaining length = 12.
var mqttConnectPkt = []byte{
	0x10, 0x0C, // Fixed header: CONNECT (0x10), remaining length = 12
	0x00, 0x04, 'M', 'Q', 'T', 'T', // Protocol Name: "MQTT"
	0x04,       // Protocol Level: 4 = MQTT 3.1.1
	0x02,       // Connect Flags: CleanSession only
	0x00, 0x3C, // Keep Alive: 60 s
	0x00, 0x00, // Client ID: empty string (length 0)
}

// probeMQTT sends a bare MQTT CONNECT packet and checks the CONNACK response.
// Returns nil when the port does not respond with a valid CONNACK.
// On success the returned map contains:
//
//	"mqtt_anon" – "allowed" if anonymous connection accepted, "rejected" otherwise
func probeMQTT(ctx context.Context, ip net.IP, port int, timeout time.Duration, dial DialFunc) map[string]string {
	conn, err := dialOrDirect(dial)(ctx, "tcp", net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck

	if _, err := conn.Write(mqttConnectPkt); err != nil {
		return nil
	}

	// CONNACK is always exactly 4 bytes: 0x20 0x02 <session_present> <return_code>
	var connack [4]byte
	if _, err := io.ReadFull(conn, connack[:]); err != nil {
		return nil
	}

	// Validate CONNACK header: fixed header = 0x20, remaining length = 0x02.
	if connack[0] != 0x20 || connack[1] != 0x02 {
		return nil
	}

	result := map[string]string{}
	returnCode := connack[3]
	switch returnCode {
	case 0x00:
		result["mqtt_anon"] = "allowed"
	case 0x04, 0x05:
		// 0x04 = bad username/password (we sent none → auth required)
		// 0x05 = not authorized
		result["mqtt_anon"] = "rejected"
	default:
		// 0x01 = unacceptable protocol version (won't happen with 3.1.1)
		// 0x02 = identifier rejected, 0x03 = server unavailable
		result["mqtt_anon"] = "rejected"
	}
	return result
}
