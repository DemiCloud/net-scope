//go:build windows

package guiwin

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"
)

// crashLogPath returns the path to the crash log file.
// Writes next to the executable first; falls back to %APPDATA%\net-sweep\.
func crashLogPath() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "net-sweep-crash.log")
	}
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		appdata = os.TempDir()
	}
	dir := filepath.Join(appdata, "net-sweep")
	_ = os.MkdirAll(dir, 0700)
	return filepath.Join(dir, "net-sweep-crash.log")
}

// writeCrashLog appends a timestamped crash entry (panic value + stack trace)
// to the crash log file and shows a message box.
func writeCrashLog(hwnd HWND, recovered any) {
	path := crashLogPath()

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err == nil {
		stamp := time.Now().Format("2006-01-02 15:04:05")
		fmt.Fprintf(f, "\n=== CRASH %s ===\npanic: %v\n\n%s\n", stamp, recovered, debug.Stack())
		f.Close()
	}

	msg := fmt.Sprintf(
		"net-sweep encountered an unexpected error:\n\n%v\n\nDetails saved to:\n%s",
		recovered, path,
	)
	messageBox(hwnd, msg, "net-sweep — Unexpected Error", MB_ICONERROR)
}
