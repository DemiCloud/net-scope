//go:build linux && gui

package guigtk

import (
	"fmt"
	"os"

	"github.com/demicloud/net-scope/internal/config"
)

// runUI is the GTK3 main window entry point.
// TODO: implement GTK3 window, widgets, and event loop using gotk3.
func runUI(version, initialTarget string, cfg config.Config) {
	// Placeholder — GTK3 implementation pending.
	fmt.Fprintf(os.Stderr, "net-scope: GTK GUI not yet implemented (version %s, target %s)\n", version, initialTarget)
	os.Exit(1)
}
