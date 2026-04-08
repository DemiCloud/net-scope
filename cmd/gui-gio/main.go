// Package guigio implements the Gio-based GUI for NetScope.
//
// It supports Windows (Direct3D 11, no CGo) and Linux (OpenGL/EGL, CGo required).
// FreeBSD uses the CLI/TUI; no GUI is provided there.
//
// Architecture:
//   - All network I/O is handled by the sensor service subprocess.
//   - The IPC client (service.go) has zero Gio/Win32 imports; it is reusable
//     by the TUI and any other front-end.
//   - The token-authenticated IPC channel prevents local process hijacking.
//   - Elevation on Linux uses pkexec (PolicyKit); on Windows "runas" ShellExecute.
package guigio

import (
	"github.com/demicloud/net-scope/internal/config"
	"github.com/demicloud/net-scope/internal/scan"
)

// Run starts the Gio GUI.
// v is the version string (injected at link time).
// target is an optional initial scan target (e.g. "192.168.1.0/24").
func Run(v, target string) {
	cfg, _, _ := config.Load()

	if target == "" {
		if cfg.Scan.DefaultTarget != "" {
			target = cfg.Scan.DefaultTarget
		} else if detected := scan.DetectLocalSubnets(); len(detected) > 0 {
			target = detected[0]
		} else {
			target = "192.168.1.0/24"
		}
	}

	runUI(v, target, cfg)
}
