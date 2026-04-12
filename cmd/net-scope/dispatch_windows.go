//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	guiwin "github.com/demicloud/net-scope/cmd/gui-win"
	"github.com/demicloud/net-scope/internal/config"
	"github.com/demicloud/net-scope/internal/scan"
)

var (
	modKernel32Disp   = syscall.NewLazyDLL("kernel32.dll")
	procAttachConsole = modKernel32Disp.NewProc("AttachConsole")
	procAllocConsole  = modKernel32Disp.NewProc("AllocConsole")
	procGetConsoleWin = modKernel32Disp.NewProc("GetConsoleWindow")
	modUser32Disp     = syscall.NewLazyDLL("user32.dll")
	procShowWindow    = modUser32Disp.NewProc("ShowWindow")
)

const swHide = 0

func hideOwnConsole() {
	hwnd, _, _ := procGetConsoleWin.Call()
	if hwnd != 0 {
		procShowWindow.Call(hwnd, swHide)
	}
}

func run() {
	// ── service subcommand ──────────────────────────────────────────────────
	// Spawned internally by the GUI: net-scope service <addr> <fingerprint>
	if len(os.Args) == 4 && os.Args[1] == "service" {
		hideOwnConsole()
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
			r, _, _ := procAttachConsole.Call(0xFFFFFFFF)
			if r == 0 {
				procAllocConsole.Call()
			}
			reopenConsoleHandles()
			runCLI()
			return
		case "tui":
			// TUI is not available on Windows.
			r, _, _ := procAttachConsole.Call(0xFFFFFFFF)
			if r == 0 {
				procAllocConsole.Call()
			}
			reopenConsoleHandles()
			fmt.Fprintln(os.Stderr, "net-scope: tui mode is not available on Windows")
			os.Exit(1)
		case "gui":
			os.Args = append(os.Args[:1], os.Args[2:]...)
			target := ""
			for _, a := range os.Args[1:] {
				if !strings.HasPrefix(a, "-") {
					target = a
					break
				}
			}
			guiwin.Run(version, target)
			return
		}
	}

	// ── no explicit subcommand: config default or platform heuristic ─────────
	cfg, _, _ := config.Load()
	switch cfg.DefaultMode {
	case "cli":
		r, _, _ := procAttachConsole.Call(0xFFFFFFFF)
		if r == 0 {
			procAllocConsole.Call()
		}
		reopenConsoleHandles()
		runCLI()
		return
	case "tui":
		r, _, _ := procAttachConsole.Call(0xFFFFFFFF)
		if r == 0 {
			procAllocConsole.Call()
		}
		reopenConsoleHandles()
		fmt.Fprintln(os.Stderr, "net-scope: tui mode is not available on Windows")
		os.Exit(1)
	case "gui":
		guiwin.Run(version, "")
		return
	}

	// Platform default: CLI when launched from a terminal, GUI on double-click.
	// ATTACH_PARENT_PROCESS = 0xFFFFFFFF succeeds when run from cmd/PowerShell.
	r, _, _ := procAttachConsole.Call(0xFFFFFFFF)
	if r != 0 {
		reopenConsoleHandles()
		runCLI()
		return
	}

	// No parent console. Any flag-style arg means the user wants CLI
	// (e.g. net-scope --help from a launcher shortcut).
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "-") {
			procAllocConsole.Call()
			reopenConsoleHandles()
			runCLI()
			return
		}
	}

	target := ""
	for _, arg := range os.Args[1:] {
		if !strings.HasPrefix(arg, "-") {
			target = arg
			break
		}
	}
	guiwin.Run(version, target)
}

func reopenConsoleHandles() {
	// CONIN$ / CONOUT$ are Windows magic filenames for the attached console.
	if f, err := os.OpenFile("CONIN$", os.O_RDONLY, 0); err == nil {
		os.Stdin = f
		syscall.Stdin = syscall.Handle(f.Fd())
	}
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout = f
		syscall.Stdout = syscall.Handle(f.Fd())
	}
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stderr = f
		syscall.Stderr = syscall.Handle(f.Fd())
	}
}
