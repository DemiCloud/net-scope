//go:build linux && gui

package main

import (
	"fmt"
	"os"
	"strings"

	guigtk "github.com/demicloud/net-scope/cmd/gui-gtk"
	"github.com/demicloud/net-scope/internal/config"
	"github.com/demicloud/net-scope/internal/scan"
)

func run() {
	// ── service subcommand ──────────────────────────────────────────────────
	if len(os.Args) == 4 && os.Args[1] == "service" {
		conn, err := scan.DialService(os.Args[2], os.Args[3])
		if err != nil {
			fmt.Fprintf(os.Stderr, "service dial: %v\n", err)
			os.Exit(1)
		}
		if err := scan.RunServiceConn(conn); err != nil {
			fmt.Fprintf(os.Stderr, "service: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// ── explicit subcommand ──────────────────────────────────────────────────
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "cli":
			os.Args = append(os.Args[:1], os.Args[2:]...)
			runCLI()
			return
		case "tui":
			os.Args = append(os.Args[:1], os.Args[2:]...)
			runTUI()
			return
		case "gui":
			os.Args = append(os.Args[:1], os.Args[2:]...)
			target := ""
			for _, a := range os.Args[1:] {
				if !strings.HasPrefix(a, "-") {
					target = a
					break
				}
			}
			guigtk.Run(version, target)
			return
		}
	}

	// ── no explicit subcommand: config default or platform default (CLI) ─────
	cfg, _, _ := config.Load()
	switch cfg.DefaultMode {
	case "tui":
		runTUI()
		return
	case "gui":
		guigtk.Run(version, "")
		return
	}

	runCLI()
}
