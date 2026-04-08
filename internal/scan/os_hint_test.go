package scan

import (
	"testing"
)

func TestGuessOS_SNMP(t *testing.T) {
	cases := []struct {
		descr string
		want  OSHint
	}{
		{"Windows Server 2022", OSWindows},
		{"Linux Kernel 5.15", OSLinux},
		{"RouterOS 7.14.3 (stable) on RB4011iGS+", OSRouterOS},
		{"Cisco IOS 15.6", OSCiscoIOS},
		{"JunOS 23.1", OSJunOS},
		{"Darwin 23.0", OSMacOS},
	}
	for _, tc := range cases {
		got, _ := guessOS(0, BannerInfo{}, nil, &SNMPInfo{SysDescr: tc.descr}, "", SYNProbeInfo{})
		if got != tc.want {
			t.Errorf("SNMP %q: got %q, want %q", tc.descr, got, tc.want)
		}
	}
}

func TestGuessOS_SSHBanner(t *testing.T) {
	cases := []struct {
		banner string
		want   OSHint
	}{
		{"OpenSSH_9.3p2 Ubuntu-1", OSLinux},
		{"OpenSSH_8.9 Debian-3", OSLinux},
		// Generic OpenSSH → Linux fallback
		{"OpenSSH_8.0", OSLinux},
		// MikroTik RouterOS
		{"SSH-2.0-ROSSSH", OSRouterOS},
		// Cisco IOS
		{"SSH-2.0-Cisco-1.25", OSCiscoIOS},
	}
	for _, tc := range cases {
		got, _ := guessOS(0, BannerInfo{SSH: tc.banner}, nil, nil, "", SYNProbeInfo{})
		if got != tc.want {
			t.Errorf("SSH %q: got %q, want %q", tc.banner, got, tc.want)
		}
	}
}

func TestGuessOS_HTTPHeader(t *testing.T) {
	cases := []struct {
		server string
		want   OSHint
	}{
		{"Microsoft-IIS/10.0", OSWindows},
		{"Microsoft-HTTPAPI/2.0", OSWindows},
		{"Apache/2.4.51 (Ubuntu)", OSLinux},
		{"nginx/1.24.0", OSLinux},
	}
	for _, tc := range cases {
		got, _ := guessOS(0, BannerInfo{HTTP: tc.server}, nil, nil, "", SYNProbeInfo{})
		if got != tc.want {
			t.Errorf("HTTP %q: got %q, want %q", tc.server, got, tc.want)
		}
	}
}

func TestGuessOS_TTL(t *testing.T) {
	cases := []struct {
		ttl  uint8
		want OSHint
	}{
		{128, OSWindows},
		{64, OSLinux},
		{255, OSNetwork},
		{50, OSUnknown}, // ambiguous
	}
	for _, tc := range cases {
		got, _ := guessOS(tc.ttl, BannerInfo{}, nil, nil, "", SYNProbeInfo{})
		if got != tc.want {
			t.Errorf("TTL %d: got %q, want %q", tc.ttl, got, tc.want)
		}
	}
}

func TestGuessOS_Precedence(t *testing.T) {
	// SNMP should win over TTL
	got, _ := guessOS(128 /* windows TTL */, BannerInfo{}, nil, &SNMPInfo{SysDescr: "Linux Kernel"}, "", SYNProbeInfo{})
	if got != OSLinux {
		t.Errorf("SNMP should beat TTL: got %q", got)
	}
}

func TestGuessOS_VendorOUI(t *testing.T) {
	cases := []struct {
		vendor string
		want   OSHint
	}{
		{"Apple, Inc.", OSMacOS},
		{"Apple Inc", OSMacOS},
		{"Raspberry Pi Foundation", OSLinux},
		{"Cisco Systems, Inc", OSCiscoIOS},
		{"Juniper Networks", OSJunOS},
		{"Ubiquiti Inc.", OSUbiquiti},
		{"MikroTik", OSRouterOS},
		{"Aruba Networks", OSAruba},
		{"Fortinet, Inc.", OSFortinet},
		{"Palo Alto Networks", OSNetwork},
		{"Dell Inc.", OSUnknown}, // unknown vendor → falls through to TTL=0 → unknown
	}
	for _, tc := range cases {
		got, _ := guessOS(0, BannerInfo{}, nil, nil, tc.vendor, SYNProbeInfo{})
		if got != tc.want {
			t.Errorf("vendor %q: got %q, want %q", tc.vendor, got, tc.want)
		}
	}
}

func TestGuessOS_SNMPBeatsVendor(t *testing.T) {
	// SNMP "Linux" should win over Apple vendor OUI
	got, _ := guessOS(0, BannerInfo{}, nil, &SNMPInfo{SysDescr: "Linux Kernel"}, "Apple, Inc.", SYNProbeInfo{})
	if got != OSLinux {
		t.Errorf("SNMP should beat vendor OUI: got %q", got)
	}
}

func TestGuessOS_SYNProbe(t *testing.T) {
	cases := []struct {
		win  uint16
		opts string
		want OSHint
	}{
		{64240, "MSS(1460) NOP NOP SACK NOP WScale(8)", OSWindows}, // Windows 10/11
		{29200, "MSS(1460) SACK TS NOP WScale(7)", OSLinux},        // Linux 3.12+
		{65535, "MSS(1460) NOP WScale(6) NOP NOP TS SACK", OSMacOS}, // macOS
		{65535, "MSS(1460) SACK", OSUnknown},                        // 65535 without TS → not confident
		{8192, "MSS(1460)", OSUnknown},                              // ambiguous
		{0, "", OSUnknown},                                          // probe unavailable
	}
	for _, tc := range cases {
		got, _ := guessOS(0, BannerInfo{}, nil, nil, "", SYNProbeInfo{WindowSize: tc.win, Options: tc.opts})
		if got != tc.want {
			t.Errorf("SYN win=%d opts=%q: got %q, want %q", tc.win, tc.opts, got, tc.want)
		}
	}
}

func TestGuessOS_SYNBeatsVendor(t *testing.T) {
	// Vendor OUI fires BEFORE SYN tier, so Apple OUI should still win over
	// a Linux-looking window (Apple hardware CAN run Linux via Boot Camp, etc.)
	got, _ := guessOS(0, BannerInfo{}, nil, nil, "Apple, Inc.", SYNProbeInfo{WindowSize: 29200, Options: "MSS(1460) SACK TS NOP WScale(7)"})
	if got != OSMacOS {
		t.Errorf("vendor OUI should beat SYN window: got %q", got)
	}
}

func TestGuessOS_RouterOSCHR(t *testing.T) {
	// RouterOS Cloud Hosted Router: x86 hardware (no MikroTik OUI), no SNMP,
	// but ROSSSH banner. SYN window would be 29200 (Linux kernel). SSH must
	// fire before SYN so ROSSSH is correctly identified.
	got, _ := guessOS(
		64, // Linux-looking TTL
		BannerInfo{SSH: "SSH-2.0-ROSSSH"},
		nil, nil, "",
		SYNProbeInfo{WindowSize: 29200, Options: "MSS(1460) SACK TS NOP WScale(7)"},
	)
	if got != OSRouterOS {
		t.Errorf("RouterOS CHR should be OSRouterOS, got %q", got)
	}
}

func TestGuessOS_Confidence(t *testing.T) {
	// SNMP alone → near-maximum confidence.
	_, conf := guessOS(0, BannerInfo{}, nil, &SNMPInfo{SysDescr: "Linux Kernel"}, "", SYNProbeInfo{})
	if conf < 85 {
		t.Errorf("SNMP alone: expected conf ≥ 85, got %d", conf)
	}

	// TTL alone → low confidence (30, just above threshold).
	_, conf = guessOS(64, BannerInfo{}, nil, nil, "", SYNProbeInfo{})
	if conf > 35 {
		t.Errorf("TTL alone: expected conf ≤ 35, got %d", conf)
	}

	// No signals → unknown, confidence 0.
	hint, conf := guessOS(0, BannerInfo{}, nil, nil, "", SYNProbeInfo{})
	if hint != OSUnknown || conf != 0 {
		t.Errorf("no signals: expected (OSUnknown, 0), got (%q, %d)", hint, conf)
	}

	// Multiple corroborating signals for Windows → higher confidence than SNMP alone.
	_, confSingle := guessOS(0, BannerInfo{}, nil, &SNMPInfo{SysDescr: "Windows Server"}, "", SYNProbeInfo{})
	_, confMulti := guessOS(
		128, // Windows TTL
		BannerInfo{SSH: "OpenSSH_9.0 Windows", HTTP: "Microsoft-IIS/10.0"},
		nil, &SNMPInfo{SysDescr: "Windows Server"},
		"",
		SYNProbeInfo{WindowSize: 64240},
	)
	if confMulti <= confSingle {
		t.Errorf("corroborating signals should raise confidence: single=%d multi=%d", confSingle, confMulti)
	}
}
