//go:build !windows && !gui

package main

import (
	"fmt"
	"os"

	"github.com/demicloud/net-scope/internal/config"
	"github.com/demicloud/net-scope/internal/scan"
)

func run() {
	// ── service subcommand ──────────────────────────────────────────────────
	// Spawned internally by the GUI: net-scope service <addr> <fingerprint>
	if len(os.Args) == 4 && os.Args[1] == "service" {
		conn, err := scan.DialService(os.Args[2], os.Args[3])
		if err != nil {
			fmt.Fprintf(os.Stderr, "service dial: %v\n", err)
			writeSvcErrorLog(err)
			os.Exit(1)
		}
		defer func() {
			if r := recover(); r != nil {
				writeSvcCrashLog(r)
				os.Exit(2)
			}
		}()
		if err := scan.RunServiceConn(conn); err != nil {
			fmt.Fprintf(os.Stderr, "service: %v\n", err)
			writeSvcErrorLog(err)
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
			fmt.Fprintln(os.Stderr, "net-scope: gui mode is not available in this build (use make linux-gui)")
			os.Exit(1)
		}
	}

	// ── no explicit subcommand: config default or platform default (CLI) ─────
	cfg, _, _ := config.Load()
	switch cfg.DefaultMode {
	case "tui":
		runTUI()
		return
	case "gui":
		fmt.Fprintln(os.Stderr, "net-scope: gui mode is not available in this build (use make linux-gui)")
		os.Exit(1)
	}

	// Platform default for Linux static / BSD: CLI.
	runCLI()
}
