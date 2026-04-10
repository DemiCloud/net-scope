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
	// Strip a trailing numeric version: "urn:foo:bar:1" → "bar"
	if i := strings.LastIndexAny(t, ":/"); i >= 0 {
		name := t[i+1:]
		// Check if last colon-separated token is purely numeric (version suffix).
		if colon := strings.LastIndex(name, ":"); colon >= 0 {
			suffix := name[colon+1:]
			allDigits := len(suffix) > 0
			for _, c := range suffix {
				if c < '0' || c > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				name = name[:colon]
			}
		}
		if name != "" {
			return name
		}
	}
	return svcType
}
