package probes

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/demicloud/net-scope/internal/scan"
)

func registerDirectory() {
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "ldap-deep", Group: "Directory", Name: "LDAP [RootDSE]",
		ServiceName: "Directory Server",
		DefaultPort: 389, Transport: "TCP", Run: probeLDAPDeep,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "ldap-gc-deep", Group: "Directory", Name: "LDAP GC [RootDSE]",
		ServiceName: "AD Global Catalog",
		DefaultPort: 3268, Transport: "TCP", Run: probeLDAPDeep,
	})
}

// ldapRootDSEQuery is a minimal LDAP SearchRequest for the RootDSE entry.
// Identical to the one in internal/scan/svc_probes.go but reproduced here
// to avoid depending on unexported symbols.
var ldapRootDSEQuery = []byte{
	0x30, 0x25,
	0x02, 0x01, 0x01,
	0x63, 0x20,
	0x04, 0x00,
	0x0A, 0x01, 0x00,
	0x0A, 0x01, 0x00,
	0x02, 0x01, 0x00,
	0x02, 0x01, 0x00,
	0x01, 0x01, 0x00,
	0x87, 0x0B, 0x6F, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x43, 0x6C, 0x61, 0x73, 0x73,
	0x30, 0x00,
}

func probeLDAPDeep(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (LDAP)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	emit("Sending anonymous RootDSE search…")
	if _, err := conn.Write(ldapRootDSEQuery); err != nil {
		emit("Write failed: " + err.Error())
		return nil, nil
	}

	buf := make([]byte, 8192)
	n, _ := io.ReadAtLeast(conn, buf, 4)
	if n < 4 || buf[0] != 0x30 {
		emit("Response is not valid LDAP (expected SEQUENCE 0x30)")
		return nil, nil
	}
	emit("Got LDAP response")

	raw := string(buf[:n])
	var result []scan.Observation

	// Extract defaultNamingContext → AD domain.
	if v := ldapAttr(raw, "defaultNamingContext"); v != "" {
		domain := dcToFQDN(v)
		emit("Domain:           " + domain)
		result = append(result, obs("probe", "ldap_domain", domain))
	}
	if v := ldapAttr(raw, "supportedLDAPVersion"); v != "" {
		emit("LDAP version:     " + v)
		result = append(result, obs("probe", "ldap_version", v))
	}
	if v := ldapAttr(raw, "supportedSASLMechanisms"); v != "" {
		emit("SASL mechanisms:  " + v)
		result = append(result, obs("probe", "ldap_sasl", v))
	}
	if v := ldapAttr(raw, "serverType"); v != "" {
		emit("Server type:      " + v)
		result = append(result, obs("probe", "ldap_type", v))
	}

	if len(result) == 0 {
		emit("RootDSE returned no useful attributes (anonymous access may be restricted)")
	}
	return result, nil
}

// ldapAttr locates an attribute value by name in a raw BER response.
// This avoids a full BER decoder — the attribute name appears as a UTF-8
// string in the response, followed shortly by the attribute value.
func ldapAttr(raw, name string) string {
	idx := strings.Index(raw, name)
	if idx < 0 {
		return ""
	}
	// After the attribute name, skip BER tag+length bytes to reach the value.
	rest := raw[idx+len(name):]
	if len(rest) < 4 {
		return ""
	}
	// Value starts after a 2-byte type+length BER TLV.
	valOff := 2
	valLen := int(rest[1])
	if valLen > 127 {
		if len(rest) < 4 {
			return ""
		}
		valLen = int(rest[2])<<8 | int(rest[3])
		valOff = 4
	}
	end := valOff + valLen
	if end > len(rest) {
		end = len(rest)
	}
	val := strings.TrimRight(rest[valOff:end], "\x00\r\n")
	// Strip any remaining non-printable bytes.
	var clean []byte
	for i := 0; i < len(val); i++ {
		if val[i] >= 0x20 {
			clean = append(clean, val[i])
		}
	}
	return string(clean)
}

// dcToFQDN converts "DC=corp,DC=example,DC=com" → "corp.example.com".
func dcToFQDN(dn string) string {
	var parts []string
	for _, seg := range strings.Split(dn, ",") {
		seg = strings.TrimSpace(seg)
		if strings.HasPrefix(strings.ToUpper(seg), "DC=") {
			parts = append(parts, seg[3:])
		}
	}
	if len(parts) == 0 {
		return dn
	}
	return strings.Join(parts, ".")
}
