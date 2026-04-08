//go:build windows

package scan

import (
	"syscall"
	"unsafe"
)

var (
	modAdvapi32Sw        = syscall.NewLazyDLL("advapi32.dll")
	procOpenProcessTokenSw = modAdvapi32Sw.NewProc("OpenProcessToken")
	procGetTokenInfoSw   = modAdvapi32Sw.NewProc("GetTokenInformation")
	procCloseHandleSw    = syscall.NewLazyDLL("kernel32.dll").NewProc("CloseHandle")
	procGetCurrentProcSw = syscall.NewLazyDLL("kernel32.dll").NewProc("GetCurrentProcess")
)

// IsElevated reports whether the current process has administrator privileges.
func IsElevated() bool {
	proc, _, _ := procGetCurrentProcSw.Call()
	var token uintptr
	r, _, _ := procOpenProcessTokenSw.Call(proc, 0x0008 /* TOKEN_QUERY */, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return false
	}
	defer procCloseHandleSw.Call(token)

	var elevation uint32
	var retLen uint32
	const tokenElevation = 20
	r, _, _ = procGetTokenInfoSw.Call(
		token,
		tokenElevation,
		uintptr(unsafe.Pointer(&elevation)),
		unsafe.Sizeof(elevation),
		uintptr(unsafe.Pointer(&retLen)),
	)
	return r != 0 && elevation != 0
}
