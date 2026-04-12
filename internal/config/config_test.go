package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Default()
// ---------------------------------------------------------------------------

func TestDefault_Timeout(t *testing.T) {
	cfg := Default()
	if cfg.Scan.Timeout != "1s" {
		t.Errorf("Timeout = %q, want %q", cfg.Scan.Timeout, "1s")
	}
}

func TestDefault_Concurrency(t *testing.T) {
	cfg := Default()
	if cfg.Scan.Concurrency != 256 {
		t.Errorf("Concurrency = %d, want 256", cfg.Scan.Concurrency)
	}
}

func TestDefault_BroadcastListen(t *testing.T) {
	cfg := Default()
	if cfg.Scan.BroadcastListen != "3s" {
		t.Errorf("BroadcastListen = %q, want %q", cfg.Scan.BroadcastListen, "3s")
	}
}

func TestDefault_PortsNonEmpty(t *testing.T) {
	cfg := Default()
	if len(cfg.Scan.Ports) == 0 {
		t.Error("Default ports list should not be empty")
	}
}

func TestDefault_StandardPortsPresent(t *testing.T) {
	cfg := Default()
	want := map[int]bool{22: false, 80: false, 443: false}
	for _, p := range cfg.Scan.Ports {
		want[p] = true
	}
	for port, found := range want {
		if !found {
			t.Errorf("standard port %d missing from defaults", port)
		}
	}
}

func TestDefault_BannerGrabEnabled(t *testing.T) {
	cfg := Default()
	if !cfg.Scan.BannerGrab {
		t.Error("BannerGrab should be enabled by default")
	}
}

func TestDefault_ServiceMinConfidence(t *testing.T) {
	cfg := Default()
	if cfg.Scan.ServiceMinConfidence != 60 {
		t.Errorf("ServiceMinConfidence = %d, want 60", cfg.Scan.ServiceMinConfidence)
	}
}

// ---------------------------------------------------------------------------
// ScanConfig.ParseTimeout()
// ---------------------------------------------------------------------------

func TestParseTimeout_Valid(t *testing.T) {
	s := ScanConfig{Timeout: "500ms"}
	got := s.ParseTimeout()
	if got != 500*time.Millisecond {
		t.Errorf("ParseTimeout = %v, want 500ms", got)
	}
}

func TestParseTimeout_Invalid_FallsBackToOneSecond(t *testing.T) {
	s := ScanConfig{Timeout: "not-a-duration"}
	got := s.ParseTimeout()
	if got != time.Second {
		t.Errorf("ParseTimeout with bad value = %v, want 1s fallback", got)
	}
}

func TestParseTimeout_Empty_FallsBackToOneSecond(t *testing.T) {
	s := ScanConfig{Timeout: ""}
	got := s.ParseTimeout()
	if got != time.Second {
		t.Errorf("ParseTimeout with empty value = %v, want 1s fallback", got)
	}
}

// ---------------------------------------------------------------------------
// SaveTo / loadFile round-trip
// ---------------------------------------------------------------------------

func TestSaveToAndLoadFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	orig := Default()
	orig.Scan.Timeout = "2s"
	orig.Scan.Concurrency = 64
	orig.Scan.SNMPCommunity = "testcommunity"
	orig.DefaultMode = "tui"

	if err := SaveTo(orig, path); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}

	loaded, err := loadFile(path)
	if err != nil {
		t.Fatalf("loadFile: %v", err)
	}

	if loaded.Scan.Timeout != "2s" {
		t.Errorf("Timeout: got %q, want %q", loaded.Scan.Timeout, "2s")
	}
	if loaded.Scan.Concurrency != 64 {
		t.Errorf("Concurrency: got %d, want 64", loaded.Scan.Concurrency)
	}
	if loaded.Scan.SNMPCommunity != "testcommunity" {
		t.Errorf("SNMPCommunity: got %q, want %q", loaded.Scan.SNMPCommunity, "testcommunity")
	}
	if loaded.DefaultMode != "tui" {
		t.Errorf("DefaultMode: got %q, want %q", loaded.DefaultMode, "tui")
	}
}

func TestLoadFile_MissingFile_ReturnsError(t *testing.T) {
	_, err := loadFile("/nonexistent/path/config.toml")
	if err == nil {
		t.Error("loadFile with missing file should return an error")
	}
}

func TestLoadFile_InvalidTOML_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(path, []byte("not = [[valid toml"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadFile(path)
	if err == nil {
		t.Error("loadFile with invalid TOML should return an error")
	}
}

// ---------------------------------------------------------------------------
// ToScanConfig()
// ---------------------------------------------------------------------------

func TestToScanConfig_Timeout(t *testing.T) {
	cfg := Default()
	cfg.Scan.Timeout = "2s"
	sc := cfg.ToScanConfig()
	if sc.Timeout != 2*time.Second {
		t.Errorf("ToScanConfig Timeout = %v, want 2s", sc.Timeout)
	}
}

func TestToScanConfig_BroadcastListen(t *testing.T) {
	cfg := Default()
	cfg.Scan.BroadcastListen = "5s"
	sc := cfg.ToScanConfig()
	if sc.BroadcastListen != 5*time.Second {
		t.Errorf("ToScanConfig BroadcastListen = %v, want 5s", sc.BroadcastListen)
	}
}

func TestToScanConfig_Fields(t *testing.T) {
	cfg := Default()
	cfg.Scan.Concurrency = 32
	cfg.Scan.SNMPCommunity = "private"
	cfg.Scan.Interface = "eth0"
	cfg.Scan.BannerGrab = false
	cfg.Scan.SOCKSProxy = "127.0.0.1:1080"

	sc := cfg.ToScanConfig()
	if sc.Concurrency != 32 {
		t.Errorf("Concurrency: got %d, want 32", sc.Concurrency)
	}
	if sc.SNMPCommunity != "private" {
		t.Errorf("SNMPCommunity: got %q, want %q", sc.SNMPCommunity, "private")
	}
	if sc.Interface != "eth0" {
		t.Errorf("Interface: got %q, want %q", sc.Interface, "eth0")
	}
	if sc.BannerGrab != false {
		t.Error("BannerGrab: got true, want false")
	}
	if sc.SOCKSProxy != "127.0.0.1:1080" {
		t.Errorf("SOCKSProxy: got %q, want %q", sc.SOCKSProxy, "127.0.0.1:1080")
	}
}

func TestToScanConfig_InvalidTimeout_FallsBack(t *testing.T) {
	cfg := Default()
	cfg.Scan.Timeout = "bogus"
	sc := cfg.ToScanConfig()
	if sc.Timeout != time.Second {
		t.Errorf("ToScanConfig with invalid timeout = %v, want 1s fallback", sc.Timeout)
	}
}
