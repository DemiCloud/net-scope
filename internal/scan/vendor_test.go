//go:build with_oui

package scan

import (
	"net"
	"testing"
	"time"
)

func initOUIForTest(t *testing.T) {
	t.Helper()
	InitVendorDB("")
	select {
	case <-ouiReady:
	case <-time.After(5 * time.Second):
		t.Fatal("OUI DB did not load within 5s")
	}
	if len(ouiDB) == 0 {
		t.Skip("embedded OUI DB is empty; run make fetch-oui first")
	}
}

// TestOUI_MAL verifies a plain 24-bit MA-L entry resolves correctly.
// Cisco OUI 00:00:0C is the first entry in the maclookup.app dataset.
func TestOUI_MAL(t *testing.T) {
	initOUIForTest(t)
	mac, _ := net.ParseMAC("00:00:0C:AA:BB:CC")
	got := LookupVendor(mac)
	if got != "Cisco Systems, Inc" {
		t.Errorf("MA-L 00:00:0C: got %q, want %q", got, "Cisco Systems, Inc")
	}
}

// TestOUI_MAM verifies a 28-bit MA-M entry returns the sub-block vendor,
// not the MA-L owner of the same 3-byte OUI.
// 1C:87:76:D0:xx:xx belongs to "Qivivo"; no MA-L record covers 1C:87:76.
func TestOUI_MAM(t *testing.T) {
	initOUIForTest(t)
	mac, _ := net.ParseMAC("1C:87:76:D0:AA:BB")
	got := LookupVendor(mac)
	if got != "Qivivo" {
		t.Errorf("MA-M 1C:87:76:D: got %q, want %q", got, "Qivivo")
	}
}

// TestOUI_MAS verifies a 36-bit MA-S entry returns the sub-block vendor.
// 00:50:C2:00:0x:xx belongs to "T.L.S. Corp."; the MA-L at 00:50:C2 is
// "IEEE Registration Authority", which should NOT be returned.
func TestOUI_MAS(t *testing.T) {
	initOUIForTest(t)
	mac, _ := net.ParseMAC("00:50:C2:00:00:AA")
	got := LookupVendor(mac)
	if got != "T.L.S. Corp." {
		t.Errorf("MA-S 00:50:C2:00:0: got %q, want %q", got, "T.L.S. Corp.")
	}
}

// TestOUI_MAS_fallback verifies that a MAC in a MA-L-only OUI (no sub-blocks)
// returns the MA-L vendor, not "" — the MA-S and MA-M searches must fall
// through cleanly.  Cisco 00:00:0C has no MA-M/MA-S sub-allocations.
func TestOUI_MAS_fallback(t *testing.T) {
	initOUIForTest(t)
	mac, _ := net.ParseMAC("00:00:0C:AB:CD:EF")
	got := LookupVendor(mac)
	if got != "Cisco Systems, Inc" {
		t.Errorf("MA-L fallback 00:00:0C: got %q, want %q", got, "Cisco Systems, Inc")
	}
}

// TestOUI_short ensures MACs shorter than 3 bytes return "" without panicking.
func TestOUI_short(t *testing.T) {
	initOUIForTest(t)
	if v := LookupVendor(net.HardwareAddr{0x00, 0x50}); v != "" {
		t.Errorf("short MAC should return \"\", got %q", v)
	}
}
