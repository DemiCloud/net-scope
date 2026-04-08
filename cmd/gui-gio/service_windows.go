//go:build windows

package guigio

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	modShell32      = syscall.NewLazyDLL("shell32.dll")
	procShellExecEx = modShell32.NewProc("ShellExecuteW")
)

func spawnServiceProcess(addr, token string, elevated bool) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("executable path: %w", err)
	}
	params := "service " + addr + " " + token

	verb := "open"
	if elevated {
		verb = "runas"
	}

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	paramsPtr, _ := syscall.UTF16PtrFromString(params)

	const SW_HIDE = 0
	r, _, _ := procShellExecEx.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(exePtr)),
		uintptr(unsafe.Pointer(paramsPtr)),
		0,
		SW_HIDE,
	)
	// ShellExecuteW returns a value > 32 on success.
	if r <= 32 {
		return fmt.Errorf("ShellExecuteW returned %d", r)
	}
	return nil
}
