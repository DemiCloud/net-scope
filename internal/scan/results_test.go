package scan

import (
	"net"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Result.String()
// ---------------------------------------------------------------------------

func TestResult_String_Down(t *testing.T) {
	r := Result{
		IP:    net.ParseIP("10.0.0.1").To4(),
		Alive: false,
	}
	got := r.String()
	if !strings.Contains(got, "10.0.0.1") || !strings.Contains(got, "down") {
		t.Errorf("down host string = %q; want IP and 'down'", got)
	}
}

func TestResult_String_Partial(t *testing.T) {
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	r := Result{
		IP:      net.ParseIP("10.0.0.2").To4(),
		Alive:   true,
		Partial: true,
		MAC:     mac,
		Vendor:  "Acme",
		Latency: 5 * time.Millisecond,
	}
	got := r.String()
	if !strings.Contains(got, "10.0.0.2") {
		t.Errorf("partial host string missing IP: %q", got)
	}
	if !strings.Contains(got, "discovering") {
		t.Errorf("partial host string should contain 'discovering': %q", got)
	}
	if !strings.Contains(got, "Acme") {
		t.Errorf("partial host string missing vendor: %q", got)
	}
}

func TestResult_String_Partial_NoMAC(t *testing.T) {
	r := Result{
		IP:      net.ParseIP("10.0.0.3").To4(),
		Alive:   true,
		Partial: true,
		Latency: 1 * time.Millisecond,
	}
	got := r.String()
	if !strings.Contains(got, "-") {
		t.Errorf("partial host with no MAC should show '-': %q", got)
	}
}

func TestResult_String_Alive(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	r := Result{
		IP:        net.ParseIP("192.168.1.5").To4(),
		Alive:     true,
		MAC:       mac,
		Vendor:    "Corp Inc",
		Hostname:  "myhost.local",
		OpenPorts: []int{22, 80},
		OS:        OSLinux,
		Latency:   3 * time.Millisecond,
		TTL:       64,
	}
	got := r.String()
	if !strings.Contains(got, "192.168.1.5") {
		t.Errorf("alive host string missing IP: %q", got)
	}
	if !strings.Contains(got, "myhost.local") {
		t.Errorf("alive host string missing hostname: %q", got)
	}
	if !strings.Contains(got, "22,80") {
		t.Errorf("alive host string missing ports: %q", got)
	}
	if !strings.Contains(got, "Linux") {
		t.Errorf("alive host string missing OS: %q", got)
	}
}

func TestResult_String_Alive_NoHostname_FallsBackToNetBIOS(t *testing.T) {
	r := Result{
		IP:      net.ParseIP("10.1.2.3").To4(),
		Alive:   true,
		NetBIOS: "WORKSTATION",
		Latency: 2 * time.Millisecond,
	}
	got := r.String()
	if !strings.Contains(got, "WORKSTATION") {
		t.Errorf("string should contain NetBIOS name when Hostname is empty: %q", got)
	}
}

func TestResult_String_Alive_NoPorts(t *testing.T) {
	r := Result{
		IP:      net.ParseIP("10.1.2.4").To4(),
		Alive:   true,
		Latency: 2 * time.Millisecond,
	}
	got := r.String()
	// No ports → should contain the dash placeholder.
	if !strings.Contains(got, "-") {
		t.Errorf("no-ports result should contain '-': %q", got)
	}
}

func TestResult_String_Alive_WithSNMP(t *testing.T) {
	r := Result{
		IP:      net.ParseIP("10.0.0.10").To4(),
		Alive:   true,
		Latency: 1 * time.Millisecond,
		SNMP: &SNMPInfo{
			SysDescr: "Linux 5.15 ARM64",
		},
	}
	got := r.String()
	if !strings.Contains(got, "Linux 5.15 ARM64") {
		t.Errorf("SNMP SysDescr should appear in string output: %q", got)
	}
}
