// Package guigtk implements the GTK3 GUI for NetScope on Linux.
//
// Build constraints: linux AND gui tag (make linux-gui).
// The standard static Linux binary (make linux) does NOT include this package.
//
// Architecture:
//   - All network I/O is handled by the sensor service subprocess.
//   - The IPC client (service.go) has zero GTK imports; it is reusable
//     by the TUI and any other front-end.
//   - CGo is required (GTK3 via gotk3).
//   - The binary is dynamically linked against system GTK3 libraries.
//go:build linux && gui

package guigtk

import (
	"github.com/demicloud/net-scope/internal/config"
	"github.com/demicloud/net-scope/internal/netinfo"
	"github.com/demicloud/net-scope/internal/scan"
)

// Run starts the GTK3 GUI.
// v is the version string (injected at link time).
// target is an optional initial scan target (e.g. "192.168.1.0/24").
func Run(v, target string) {
	cfg, _, _ := config.Load()

	if target == "" {
		if cfg.Scan.DefaultTarget != "" {
			target = cfg.Scan.DefaultTarget
		} else if detected := netinfo.DetectLocalSubnets(); len(detected) > 0 {
			target = detected[0]
		} else {
			target = "192.168.1.0/24"
		}
	}

	runUI(v, target, cfg)
}
