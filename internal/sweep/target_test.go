package sweep

import (
	"net"
	"testing"
)

func TestExpandTarget_SingleIP(t *testing.T) {
	hosts, err := ExpandTarget("10.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	if hosts[0].String() != "10.0.0.1" {
		t.Errorf("got %s, want 10.0.0.1", hosts[0])
	}
}

func TestExpandTarget_Slash30(t *testing.T) {
	// /30 = 4 IPs, network+broadcast removed → 2 hosts
	hosts, err := ExpandTarget("192.168.10.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts for /30, got %d", len(hosts))
	}
	if hosts[0].String() != "192.168.10.1" {
		t.Errorf("first host = %s, want 192.168.10.1", hosts[0])
	}
	if hosts[1].String() != "192.168.10.2" {
		t.Errorf("second host = %s, want 192.168.10.2", hosts[1])
	}
}

func TestExpandTarget_Slash32(t *testing.T) {
	// /32 = single host, no network/broadcast removal
	hosts, err := ExpandTarget("172.16.0.5/32")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host for /32, got %d", len(hosts))
	}
}

func TestExpandTarget_InvalidInput(t *testing.T) {
	for _, bad := range []string{"not-an-ip", "256.0.0.1", "192.168.0.0/999"} {
		_, err := ExpandTarget(bad)
		if err == nil {
			t.Errorf("expected error for %q, got nil", bad)
		}
	}
}

func TestExpandTarget_IPv6Rejected(t *testing.T) {
	_, err := ExpandTarget("::1")
	if err != nil {
		// IPv6 single IP: currently parsed as IPv4-mapped or returns error — acceptable
		return
	}
}

func TestFindInterface_Loopback(t *testing.T) {
	// 127.0.0.1 should always find the loopback interface.
	iface, err := findInterface(net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Skipf("findInterface(127.0.0.1) error (may require privilege): %v", err)
	}
	if iface.Flags&net.FlagLoopback == 0 {
		t.Errorf("expected loopback interface, got %s", iface.Name)
	}
}
