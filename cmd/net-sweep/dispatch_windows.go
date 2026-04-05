//go:build windows

package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"

	guiwin "github.com/demicloud/net-sweep/cmd/gui-win"
	"github.com/demicloud/net-sweep/internal/sweep"
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
	// Elevated probe-server mode: spawned by the GUI with --probe=addr.
	// Argument is a single token (no space) so Windows command-line parsing
	// can never accidentally merge or re-quote it.
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "--probe=") {
			addr := strings.TrimPrefix(arg, "--probe=")
			hideOwnConsole()
			// The GUI already holds the listener; we connect to it.
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "probe dial: %v\n", err)
				os.Exit(1)
			}
			if err := sweep.RunProbeConn(conn); err != nil {
				fmt.Fprintf(os.Stderr, "probe server: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	// ATTACH_PARENT_PROCESS = 0xFFFFFFFF
	// Succeeds when launched from cmd.exe / PowerShell.
	// Fails (sets last error) when launched by double-clicking.
	r, _, _ := procAttachConsole.Call(0xFFFFFFFF)
	if r != 0 {
		// Launched from a terminal: reconnect Go's std handles and run CLI mode.
		reopenConsoleHandles()
		runCLI()
		return
	}

	// No parent console (e.g. double-click, or a hosted terminal that doesn't
	// expose a Win32 console). If any flag-style arg is present, allocate a
	// fresh console and run CLI mode so --help / --version work correctly.
	// Only a bare target (no leading dash) is passed on to the GUI.
	for _, arg := range os.Args[1:] {
		if arg == "--gui" {
			break
		}
		if strings.HasPrefix(arg, "-") {
			procAllocConsole.Call()
			reopenConsoleHandles()
			runCLI()
			return
		}
	}

	target := ""
	if len(os.Args) > 1 && os.Args[1] != "--gui" {
		target = os.Args[1]
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
