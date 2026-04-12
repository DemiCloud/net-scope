package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// DefaultState()
// ---------------------------------------------------------------------------

func TestDefaultState_Version(t *testing.T) {
	s := DefaultState()
	if s.Version != stateVersion {
		t.Errorf("Version = %d, want %d", s.Version, stateVersion)
	}
}

func TestDefaultState_ActiveView(t *testing.T) {
	s := DefaultState()
	if s.ActiveView != "hosts" {
		t.Errorf("ActiveView = %q, want %q", s.ActiveView, "hosts")
	}
}

// ---------------------------------------------------------------------------
// SaveState / LoadState round-trip
// ---------------------------------------------------------------------------

func TestSaveAndLoadState_RoundTrip(t *testing.T) {
	dir := t.TempDir()

	s := DefaultState()
	s.ActiveView = "services"
	s.Window = WindowState{X: 100, Y: 200, Width: 1024, Height: 768, State: "maximized"}

	SaveState(dir, s)

	loaded := LoadState(dir)
	if loaded.ActiveView != "services" {
		t.Errorf("ActiveView: got %q, want %q", loaded.ActiveView, "services")
	}
	if loaded.Window.Width != 1024 {
		t.Errorf("Window.Width: got %d, want 1024", loaded.Window.Width)
	}
	if loaded.Window.State != "maximized" {
		t.Errorf("Window.State: got %q, want %q", loaded.Window.State, "maximized")
	}
}

func TestLoadState_MissingFile_ReturnsDefault(t *testing.T) {
	dir := t.TempDir()
	s := LoadState(dir)
	def := DefaultState()
	if s.Version != def.Version || s.ActiveView != def.ActiveView {
		t.Errorf("missing file should return DefaultState, got %+v", s)
	}
}

func TestLoadState_CorruptJSON_ReturnsDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, StateFile)
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := LoadState(dir)
	def := DefaultState()
	if s.ActiveView != def.ActiveView {
		t.Errorf("corrupt JSON should return DefaultState, got %+v", s)
	}
}

func TestLoadState_VersionMismatch_ReturnsDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, StateFile)

	// Write a state with a different version number.
	wrong := map[string]interface{}{
		"version":     stateVersion + 99,
		"active_view": "custom",
	}
	data, _ := json.Marshal(wrong)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	s := LoadState(dir)
	if s.ActiveView == "custom" {
		t.Error("version mismatch should discard saved state and return DefaultState")
	}
}

func TestSaveState_EmptyDir_Noop(t *testing.T) {
	// SaveState with dir=="" must not panic and must not write any file.
	SaveState("", DefaultState())
}

func TestSaveState_WritesVersionField(t *testing.T) {
	dir := t.TempDir()
	s := DefaultState()
	s.Version = 0 // intentionally wrong — SaveState must fix it
	SaveState(dir, s)

	loaded := LoadState(dir)
	if loaded.Version != stateVersion {
		t.Errorf("saved state version = %d, want %d", loaded.Version, stateVersion)
	}
}

// ---------------------------------------------------------------------------
// TabColumnState / SortState helpers via round-trip
// ---------------------------------------------------------------------------

func TestSaveAndLoadState_ColumnState(t *testing.T) {
	dir := t.TempDir()

	col := "hostname"
	s := DefaultState()
	s.Columns = map[string]TabColumnState{
		"hosts": {
			Cols: map[string]ColumnState{
				"hostname": {Visible: true, Width: 200},
				"ip":       {Visible: false, Width: 100},
			},
			Sort: SortState{Column: &col, Asc: true},
		},
	}
	SaveState(dir, s)

	loaded := LoadState(dir)
	tab, ok := loaded.Columns["hosts"]
	if !ok {
		t.Fatal("hosts tab not found in loaded state")
	}
	hcol, ok := tab.Cols["hostname"]
	if !ok || !hcol.Visible || hcol.Width != 200 {
		t.Errorf("hostname column: got %+v", hcol)
	}
	ipcol := tab.Cols["ip"]
	if ipcol.Visible {
		t.Error("ip column should not be visible")
	}
	if tab.Sort.Column == nil || *tab.Sort.Column != "hostname" {
		t.Errorf("sort column: got %v", tab.Sort.Column)
	}
	if !tab.Sort.Asc {
		t.Error("sort direction should be ascending")
	}
}
