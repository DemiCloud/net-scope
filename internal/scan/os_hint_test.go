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
		got := guessOS(0, BannerInfo{}, nil, &SNMPInfo{SysDescr: tc.descr})
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
		got := guessOS(0, BannerInfo{SSH: tc.banner}, nil, nil)
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
		got := guessOS(0, BannerInfo{HTTP: tc.server}, nil, nil)
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
		got := guessOS(tc.ttl, BannerInfo{}, nil, nil)
		if got != tc.want {
			t.Errorf("TTL %d: got %q, want %q", tc.ttl, got, tc.want)
		}
	}
}

func TestGuessOS_Precedence(t *testing.T) {
	// SNMP should win over TTL
	got := guessOS(128 /* windows TTL */, BannerInfo{}, nil, &SNMPInfo{SysDescr: "Linux Kernel"})
	if got != OSLinux {
		t.Errorf("SNMP should beat TTL: got %q", got)
	}
}
