package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// StateFile is the filename for persisted UI state, stored alongside config.toml.
const StateFile = "state.json"

// stateVersion is incremented when the State schema changes incompatibly.
// Mismatched versions are silently discarded and defaults are used.
const stateVersion = 1

// State holds transient UI state that survives process restarts.
// It is written silently on clean exit and read silently on startup.
// Any error (missing file, corrupt JSON, version mismatch) falls back to
// DefaultState without bothering the user.
//
// State is deliberately separate from Config (config.toml) because:
//   - State is machine-local; Config is portable and user-editable.
//   - State is written automatically; Config is only written on explicit save.
//   - Mixing them would make diffs of config.toml noisy.
type State struct {
	Version   int                       `json:"v"`
	Window    WindowState               `json:"window"`
	ActiveTab int                       `json:"active_tab"`
	Columns   map[string]TabColumnState `json:"columns,omitempty"`
}

// WindowState captures the main window geometry and maximized flag.
// Valid is false for the zero value; the GUI falls back to defaults when false.
type WindowState struct {
	X         int  `json:"x"`
	Y         int  `json:"y"`
	W         int  `json:"w"`
	H         int  `json:"h"`
	Maximized bool `json:"maximized"`
	Valid     bool `json:"valid"`
}

// TabColumnState holds per-tab column persistence data.
type TabColumnState struct {
	// Visible[i] is false when the user has hidden column i.
	Visible []bool `json:"visible,omitempty"`
	// Widths[i] is the column width in Win32 device pixels (0 for hidden columns).
	Widths []int `json:"widths,omitempty"`
	// SortCol is the sorted column index, or -1 when unsorted.
	SortCol int  `json:"sort_col"`
	SortAsc bool `json:"sort_asc"`
}

// DefaultState returns the baseline: default window placement, Hosts tab
// active, all columns visible at their default widths, no sort applied.
func DefaultState() State {
	return State{
		Version:   stateVersion,
		ActiveTab: 0,
		Window:    WindowState{}, // Valid = false → GUI uses CW_USEDEFAULT
	}
}

// LoadState reads state.json from dir. Any error returns DefaultState silently.
// The caller should never need to check the return value for errors.
func LoadState(dir string) State {
	data, err := os.ReadFile(filepath.Join(dir, StateFile))
	if err != nil {
		return DefaultState()
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return DefaultState()
	}
	if s.Version != stateVersion {
		return DefaultState()
	}
	return s
}

// SaveState writes s atomically to state.json in dir (temp file → rename).
// Errors are silently discarded — state loss on a single exit is not critical.
// dir == "" is a no-op (no config file was found at startup).
func SaveState(dir string, s State) {
	if dir == "" {
		return
	}
	s.Version = stateVersion
	data, err := json.Marshal(s)
	if err != nil {
		return
	}
	path := filepath.Join(dir, StateFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}
