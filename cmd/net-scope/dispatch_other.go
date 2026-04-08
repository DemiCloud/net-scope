//go:build !windows

package main

import "os"

func run() {
	// Strip --tui from os.Args if present and run TUI mode.
	for i, a := range os.Args[1:] {
		if a == "--tui" {
			// Remove the --tui flag so the TUI's own flag parser sees only scan args.
			os.Args = append(os.Args[:i+1], os.Args[i+2:]...)
			runTUI()
			return
		}
	}
	runCLI()
}
