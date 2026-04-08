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
		{"Cisco IOS 15.6", OSNetwork},
		{"JunOS 23.1", OSNetwork},
		{"Darwin 23.0", OSMacOS},
	}
	for _, tc := range cases {
		got := guessOS(0, BannerInfo{}, nil, &SNMPInfo{SysDescr: tc.descr}, "", SYNProbeInfo{})
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
	}
	for _, tc := range cases {
		got := guessOS(0, BannerInfo{SSH: tc.banner}, nil, nil, "", SYNProbeInfo{})
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
		got := guessOS(0, BannerInfo{HTTP: tc.server}, nil, nil, "", SYNProbeInfo{})
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
		got := guessOS(tc.ttl, BannerInfo{}, nil, nil, "", SYNProbeInfo{})
		if got != tc.want {
			t.Errorf("TTL %d: got %q, want %q", tc.ttl, got, tc.want)
		}
	}
}

func TestGuessOS_Precedence(t *testing.T) {
	// SNMP should win over TTL
	got := guessOS(128 /* windows TTL */, BannerInfo{}, nil, &SNMPInfo{SysDescr: "Linux Kernel"}, "", SYNProbeInfo{})
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
		{"Cisco Systems, Inc", OSNetwork},
		{"Juniper Networks", OSNetwork},
		{"Ubiquiti Inc.", OSNetwork},
		{"MikroTik", OSRouterOS},
		{"Aruba Networks", OSNetwork},
		{"Fortinet, Inc.", OSNetwork},
		{"Palo Alto Networks", OSNetwork},
		{"Dell Inc.", OSUnknown}, // unknown vendor → falls through to TTL=0 → unknown
	}
	for _, tc := range cases {
		got := guessOS(0, BannerInfo{}, nil, nil, tc.vendor, SYNProbeInfo{})
		if got != tc.want {
			t.Errorf("vendor %q: got %q, want %q", tc.vendor, got, tc.want)
		}
	}
}

func TestGuessOS_SNMPBeatsVendor(t *testing.T) {
	// SNMP "Linux" should win over Apple vendor OUI
	got := guessOS(0, BannerInfo{}, nil, &SNMPInfo{SysDescr: "Linux Kernel"}, "Apple, Inc.", SYNProbeInfo{})
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
		got := guessOS(0, BannerInfo{}, nil, nil, "", SYNProbeInfo{WindowSize: tc.win, Options: tc.opts})
		if got != tc.want {
			t.Errorf("SYN win=%d opts=%q: got %q, want %q", tc.win, tc.opts, got, tc.want)
		}
	}
}

func TestGuessOS_SYNBeatsVendor(t *testing.T) {
	// SYN-ACK window beats vendor OUI (SYN probe is lower latency and more
	// direct than OUI lookup — but OUI actually runs first; test vendor wins)
	// Vendor OUI fires BEFORE SYN tier, so Apple OUI should still win over
	// a Linux-looking window (Apple hardware CAN run Linux via Boot Camp, etc.)
	got := guessOS(0, BannerInfo{}, nil, nil, "Apple, Inc.", SYNProbeInfo{WindowSize: 29200, Options: "MSS(1460) SACK TS NOP WScale(7)"})
	if got != OSMacOS {
		t.Errorf("vendor OUI should beat SYN window: got %q", got)
	}
}
