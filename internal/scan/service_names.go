package scan

import "strings"

// svcTypeFriendly maps well-known mDNS/DNS-SD service type strings to
// human-readable protocol/role names. Used by the sensor service registry
// when computing Service.Name for broadcast-discovered services.
var svcTypeFriendly = map[string]string{
	"_airplay._tcp":        "AirPlay",
	"_raop._tcp":           "AirPlay Audio",
	"_googlecast._tcp":     "Google Cast",
	"_http._tcp":           "HTTP",
	"_https._tcp":          "HTTPS",
	"_ssh._tcp":            "SSH",
	"_smb._tcp":            "SMB",
	"_afp._tcp":            "AFP",
	"_nfs._tcp":            "NFS",
	"_printer._tcp":        "Printer",
	"_ipp._tcp":            "IPP",
	"_ipps._tcp":           "IPP (TLS)",
	"_hap._tcp":            "HomeKit",
	"_homekit._tcp":        "HomeKit",
	"_workstation._tcp":    "Workstation",
	"_device-info._tcp":    "Device Info",
	"_sleep-proxy._udp":    "Sleep Proxy",
	"_companion-link._tcp": "Apple Companion",
	"_spotifyd._tcp":       "Spotify",
	"_daap._tcp":           "iTunes",
	"_dacp._tcp":           "iTunes Remote",
	"_rdlink._tcp":         "AirDrop",
	"_pdl-datastream._tcp": "Printer (raw)",
	"_ftp._tcp":            "FTP",
	"_telnet._tcp":         "Telnet",
	"_amqp._tcp":           "AMQP",
	"_mqtt._tcp":           "MQTT",
	"_ldap._tcp":           "LDAP",
	"_xmpp-client._tcp":    "XMPP",
}

// ServiceFriendlyName returns a human-readable display name for the given
// service type identifier. Works for:
//   - mDNS/DNS-SD types: "_airplay._tcp" → "AirPlay"
//   - SSDP ST values:    "urn:dial-multiscreen-org:service:dial:1" → "dial"
//   - WSD type strings:  "pub:Computer" → "Computer"
//
// If no friendly name is known, a best-effort extraction is returned.
func ServiceFriendlyName(svcType string) string {
	// Strip trailing .local. or trailing dot (mDNS fully-qualified form).
	t := strings.TrimSuffix(strings.TrimSuffix(svcType, ".local."), ".")
	if name, ok := svcTypeFriendly[t]; ok {
		return name
	}
	// "_name._tcp" or "_name._udp" → "Name".
	if strings.HasPrefix(t, "_") {
		if dot := strings.Index(t, "."); dot > 1 {
			name := t[1:dot]
			if name != "" {
				return strings.ToUpper(name[:1]) + name[1:]
			}
		}
	}
	// URN / namespace-qualified: take last colon-or-slash segment.
	// If that segment is purely numeric (a version suffix like ":1"), step back
	// one more level: "urn:schemas-upnp-org:service:AVTransport:1" → "AVTransport".
	if i := strings.LastIndexAny(t, ":/"); i >= 0 {
		name := t[i+1:]
		// If the last segment is purely numeric, it's a version suffix — use the
		// second-to-last segment instead.
		if svcNameAllDigits(name) {
			t2 := t[:i]
			if j := strings.LastIndexAny(t2, ":/"); j >= 0 {
				name = t2[j+1:]
			} else {
				name = t2
			}
		}
		if name != "" && !svcNameAllDigits(name) {
			return name
		}
	}
	return svcType
}

// svcNameAllDigits reports whether s is non-empty and consists entirely of ASCII digits.
func svcNameAllDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// cleanDNSLabel strips DNS label backslash escapes from s and removes the
// leading MAC-address prefix used in RAOP mDNS instance names
// ("AABBCCDDEEFF@Name" → "Name").  The result is a plain Unicode string
// suitable for display.
func cleanDNSLabel(s string) string {
	// Strip RAOP MAC prefix: 12 uppercase hex digits followed by '@'.
	if at := strings.IndexByte(s, '@'); at >= 6 && at <= 17 && at < len(s)-1 {
		allHex := true
		for i := 0; i < at; i++ {
			c := s[i]
			if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
				allHex = false
				break
			}
		}
		if allHex {
			s = s[at+1:]
		}
	}
	// Remove DNS label backslash escapes so "SONY\ XR-65A95L" → "SONY XR-65A95L".
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i++ // skip backslash, write next byte literally
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
