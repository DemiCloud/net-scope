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
		{"Cisco IOS 15.6", OSNetwork},
		{"JunOS 23.1", OSNetwork},
		{"Darwin 23.0", OSMacOS},
	}
	for _, tc := range cases {
		got := guessOS(0, BannerInfo{}, nil, &SNMPInfo{SysDescr: tc.descr}, nil, "")
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
	}
	for _, tc := range cases {
		got := guessOS(0, BannerInfo{SSH: tc.banner}, nil, nil, nil, "")
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
		got := guessOS(0, BannerInfo{HTTP: tc.server}, nil, nil, nil, "")
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
		got := guessOS(tc.ttl, BannerInfo{}, nil, nil, nil, "")
		if got != tc.want {
			t.Errorf("TTL %d: got %q, want %q", tc.ttl, got, tc.want)
		}
	}
}

func TestGuessOS_Precedence(t *testing.T) {
	// SNMP should win over TTL
	got := guessOS(128 /* windows TTL */, BannerInfo{}, nil, &SNMPInfo{SysDescr: "Linux Kernel"}, nil, "")
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
		{"MikroTik", OSNetwork},
		{"Aruba Networks", OSNetwork},
		{"Fortinet, Inc.", OSNetwork},
		{"Palo Alto Networks", OSNetwork},
		{"Dell Inc.", OSUnknown}, // unknown vendor → falls through to TTL=0 → unknown
	}
	for _, tc := range cases {
		got := guessOS(0, BannerInfo{}, nil, nil, nil, tc.vendor)
		if got != tc.want {
			t.Errorf("vendor %q: got %q, want %q", tc.vendor, got, tc.want)
		}
	}
}

func TestGuessOS_PortFingerprint(t *testing.T) {
	cases := []struct {
		ports []int
		want  OSHint
	}{
		{[]int{445, 80, 3389}, OSWindows},
		{[]int{139}, OSWindows},
		{[]int{3389}, OSWindows},     // RDP alone → Windows
		{[]int{22, 80, 443}, OSLinux},
		{[]int{22}, OSLinux},
		{[]int{548}, OSMacOS},        // AFP → macOS
		{[]int{8291}, OSNetwork},     // MikroTik Winbox
		{[]int{8728}, OSNetwork},     // MikroTik API
		{[]int{179}, OSNetwork},      // BGP
		{[]int{830}, OSNetwork},      // NETCONF
		{[]int{23}, OSNetwork},
		{[]int{161}, OSNetwork},
		{[]int{80, 443}, OSUnknown},  // no fingerprint signals
	}
	for _, tc := range cases {
		got := guessOS(0, BannerInfo{}, nil, nil, tc.ports, "")
		if got != tc.want {
			t.Errorf("ports %v: got %q, want %q", tc.ports, got, tc.want)
		}
	}
}

func TestGuessOS_SNMPBeatsVendor(t *testing.T) {
	// SNMP "Linux" should win over Apple vendor OUI
	got := guessOS(0, BannerInfo{}, nil, &SNMPInfo{SysDescr: "Linux Kernel"}, nil, "Apple, Inc.")
	if got != OSLinux {
		t.Errorf("SNMP should beat vendor OUI: got %q", got)
	}
}

func TestGuessOS_VendorBeatsPort(t *testing.T) {
	// Apple vendor should win over port-22 Linux signal
	got := guessOS(0, BannerInfo{}, nil, nil, []int{22}, "Apple, Inc.")
	if got != OSMacOS {
		t.Errorf("vendor OUI should beat port fingerprint: got %q", got)
	}
}
