//go:build windows

package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"

	guiwin "github.com/demicloud/net-scope/cmd/gui-win"
	"github.com/demicloud/net-scope/internal/sweep"
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
	// Service mode: spawned by the GUI with --service=addr.
	// The service handles all scanning (elevated or not) for the GUI.
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "--service=") {
			addr := strings.TrimPrefix(arg, "--service=")
			hideOwnConsole()
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "service dial: %v\n", err)
				os.Exit(1)
			}
			if err := sweep.RunServiceConn(conn); err != nil {
				fmt.Fprintf(os.Stderr, "service: %v\n", err)
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
