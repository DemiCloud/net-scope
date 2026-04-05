//go:build windows

package main

import (
	"os"
	"syscall"

	guiwin "github.com/demicloud/net-sweep/cmd/gui-win"
)

var (
	modKernel32Disp   = syscall.NewLazyDLL("kernel32.dll")
	procAttachConsole = modKernel32Disp.NewProc("AttachConsole")
)

func run() {
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

	// No parent console → GUI mode.
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
