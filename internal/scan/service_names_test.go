package scan

import "testing"

// ---------------------------------------------------------------------------
// ServiceFriendlyName
// ---------------------------------------------------------------------------

func TestServiceFriendlyName_KnownMDNS(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"_airplay._tcp", "AirPlay"},
		{"_googlecast._tcp", "Google Cast"},
		{"_http._tcp", "HTTP"},
		{"_https._tcp", "HTTPS"},
		{"_ssh._tcp", "SSH"},
		{"_smb._tcp", "SMB"},
		{"_hap._tcp", "HomeKit"},
		{"_mqtt._tcp", "MQTT"},
		{"_ldap._tcp", "LDAP"},
		{"_ftp._tcp", "FTP"},
	}
	for _, tc := range cases {
		got := ServiceFriendlyName(tc.in)
		if got != tc.want {
			t.Errorf("ServiceFriendlyName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestServiceFriendlyName_TrailingLocalDot(t *testing.T) {
	// mDNS fully-qualified form "._tcp.local." must be stripped before lookup.
	cases := []struct {
		in   string
		want string
	}{
		{"_airplay._tcp.local.", "AirPlay"},
		{"_http._tcp.", "HTTP"},
	}
	for _, tc := range cases {
		got := ServiceFriendlyName(tc.in)
		if got != tc.want {
			t.Errorf("ServiceFriendlyName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestServiceFriendlyName_UnknownMDNS_Capitalised(t *testing.T) {
	// Unknown "_xyz._tcp" → capitalised first-segment fallback "Xyz".
	got := ServiceFriendlyName("_myproto._tcp")
	if got != "Myproto" {
		t.Errorf("got %q, want %q", got, "Myproto")
	}
}

func TestServiceFriendlyName_URN_VersionSuffix(t *testing.T) {
	// "urn:schemas-upnp-org:service:AVTransport:1" → "AVTransport" (not "1")
	got := ServiceFriendlyName("urn:schemas-upnp-org:service:AVTransport:1")
	if got != "AVTransport" {
		t.Errorf("got %q, want %q", got, "AVTransport")
	}
}

func TestServiceFriendlyName_URN_NoVersionSuffix(t *testing.T) {
	// "urn:dial-multiscreen-org:service:dial:1" → "dial"
	got := ServiceFriendlyName("urn:dial-multiscreen-org:service:dial:1")
	if got != "dial" {
		t.Errorf("got %q, want %q", got, "dial")
	}
}

func TestServiceFriendlyName_WSD(t *testing.T) {
	// "pub:Computer" → "Computer"
	got := ServiceFriendlyName("pub:Computer")
	if got != "Computer" {
		t.Errorf("got %q, want %q", got, "Computer")
	}
}

func TestServiceFriendlyName_Passthrough(t *testing.T) {
	// A completely unrecognised string with no special structure is returned as-is.
	got := ServiceFriendlyName("something-opaque")
	if got != "something-opaque" {
		t.Errorf("got %q, want %q", got, "something-opaque")
	}
}

// ---------------------------------------------------------------------------
// SvcTypeWellKnownPort
// ---------------------------------------------------------------------------

func TestSvcTypeWellKnownPort_Known(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"_ssh._tcp", 22},
		{"_http._tcp", 80},
		{"_https._tcp", 443},
		{"_smb._tcp", 445},
		{"_mqtt._tcp", 1883},
		{"_ldap._tcp", 389},
		{"_ftp._tcp", 21},
		// FQDN form should still resolve.
		{"_ssh._tcp.local.", 22},
		{"_http._tcp.", 80},
	}
	for _, tc := range cases {
		got := SvcTypeWellKnownPort(tc.in)
		if got != tc.want {
			t.Errorf("SvcTypeWellKnownPort(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestSvcTypeWellKnownPort_Unknown(t *testing.T) {
	cases := []string{
		"_googlecast._tcp",
		"_airplay._tcp",
		"urn:schemas-upnp-org:device:MediaServer:1",
		"",
	}
	for _, svc := range cases {
		got := SvcTypeWellKnownPort(svc)
		if got != 0 {
			t.Errorf("SvcTypeWellKnownPort(%q) = %d, want 0", svc, got)
		}
	}
}

// ---------------------------------------------------------------------------
// cleanDNSLabel (package-internal)
// ---------------------------------------------------------------------------

func TestCleanDNSLabel_RAOPPrefix(t *testing.T) {
	// 12 uppercase hex digits + '@' prefix → strip prefix.
	got := cleanDNSLabel("AABBCCDDEEFF@My Speaker")
	if got != "My Speaker" {
		t.Errorf("got %q, want %q", got, "My Speaker")
	}
}

func TestCleanDNSLabel_RAOPPrefix_LowerHex(t *testing.T) {
	// Lowercase hex digits in prefix → still stripped.
	got := cleanDNSLabel("aabbccddeeff@Lowercase Mac")
	if got != "Lowercase Mac" {
		t.Errorf("got %q, want %q", got, "Lowercase Mac")
	}
}

func TestCleanDNSLabel_BackslashEscape(t *testing.T) {
	got := cleanDNSLabel(`SONY\ XR-65A95L`)
	if got != "SONY XR-65A95L" {
		t.Errorf("got %q, want %q", got, "SONY XR-65A95L")
	}
}

func TestCleanDNSLabel_NoEscape(t *testing.T) {
	got := cleanDNSLabel("Plain Name")
	if got != "Plain Name" {
		t.Errorf("got %q, want %q", got, "Plain Name")
	}
}

func TestCleanDNSLabel_NotEnoughHexForRAOP(t *testing.T) {
	// Fewer than 6 hex chars before '@' → not a RAOP prefix, leave as-is.
	got := cleanDNSLabel("AB@Name")
	if got != "AB@Name" {
		t.Errorf("got %q, want %q", got, "AB@Name")
	}
}
