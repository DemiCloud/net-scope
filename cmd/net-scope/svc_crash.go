package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"
)

// svcCrashLogPath returns the path to the sensor service crash log file.
// Tries the directory next to the executable first; falls back to the OS temp dir.
func svcCrashLogPath() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "net-scope-sensor-crash.log")
	}
	return filepath.Join(os.TempDir(), "net-scope-sensor-crash.log")
}

// writeSvcCrashLog appends a timestamped crash entry (panic value + stack trace)
// to the sensor service crash log file.
func writeSvcCrashLog(recovered any) {
	path := svcCrashLogPath()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	stamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(f, "\n=== SENSOR CRASH %s ===\npanic: %v\n\n%s\n", stamp, recovered, debug.Stack())
}

// writeSvcErrorLog appends a non-panic sensor service error to the same log file.
func writeSvcErrorLog(err error) {
	path := svcCrashLogPath()
	f, ferr := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if ferr != nil {
		return
	}
	defer f.Close()
	stamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(f, "\n=== SENSOR ERROR %s ===\n%v\n", stamp, err)
}
