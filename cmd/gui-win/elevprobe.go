//go:build windows

package guiwin

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/demicloud/net-sweep/internal/sweep"
)

// startElevatedScan spawns an elevated copy of the binary with --probe <addr>,
// connects over TCP localhost, sends a ProbeRequest, and streams results back
// through the normal WM_SCAN_RESULT / WM_SCAN_COMPLETE pipeline.
//
// The original window stays open and responsive throughout. No second GUI
// window appears because the helper process has no window procedure.
func startElevatedScan(hwnd HWND, target string, cfg sweep.Config) {
	exe, err := os.Executable()
	if err != nil {
		messageBox(hwnd, "Cannot locate executable:\n"+err.Error(), "net-sweep", MB_ICONERROR)
		postMessage(hwnd, WM_SCAN_COMPLETE, 0, 0)
		return
	}

	// Listen on a random localhost port — used as the rendezvous point.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		messageBox(hwnd, "Cannot open probe listener:\n"+err.Error(), "net-sweep", MB_ICONERROR)
		postMessage(hwnd, WM_SCAN_COMPLETE, 0, 0)
		return
	}
	addr := ln.Addr().String()

	// Spawn elevated helper: net-sweep.exe --probe=127.0.0.1:<port>
	// Single --probe=addr token avoids any Windows command-line quoting
	// ambiguity. ShellExecute runas triggers one UAC prompt; no second GUI
	// window appears because the helper detects --probe= and runs headless.
	shellExecute(0, "runas", exe, "--probe="+addr, "", SW_HIDE)

	go func() {
		defer func() {
			if p := recover(); p != nil {
				writeCrashLog(hwnd, p)
				postMessage(hwnd, WM_SCAN_COMPLETE, 0, 0)
			}
		}()

		// Give the user up to 60s to approve the UAC prompt.
		ln.(*net.TCPListener).SetDeadline(time.Now().Add(60 * time.Second))

		// Accept the single connection from the elevated helper.
		conn, err := ln.Accept()
		ln.Close()
		if err != nil {
			postMessage(hwnd, WM_SCAN_COMPLETE, 0, 0)
			return
		}
		defer conn.Close()

		// Send the scan request.
		enc := json.NewEncoder(conn)
		if err := enc.Encode(sweep.ProbeRequest{Target: target, Config: cfg}); err != nil {
			postMessage(hwnd, WM_SCAN_COMPLETE, 0, 0)
			return
		}

		// Stream results back into the normal WM_SCAN_RESULT pipeline.
		dec := json.NewDecoder(conn)
		var mu sync.Mutex
		_ = mu
		for {
			var pr sweep.ProbeResult
			if err := dec.Decode(&pr); err != nil {
				break
			}
			if pr.Done {
				if pr.Stats != nil {
					pendingMu.Lock()
					lastStats = *pr.Stats
					pendingMu.Unlock()
				}
				break
			}
			if pr.Result != nil {
				pendingMu.Lock()
				idx := len(pendingResults)
				pendingResults = append(pendingResults, *pr.Result)
				pendingMu.Unlock()
				postMessage(hwnd, WM_SCAN_RESULT, uintptr(idx), 0)
			}
		}
		postMessage(hwnd, WM_SCAN_COMPLETE, 0, 0)
	}()
}

// statusForMode returns a toolbar annotation describing the current scan mode.
func statusForMode(wantAdmin, elevated bool) string {
	switch {
	case elevated:
		return fmt.Sprintf("Scanning (elevated — ARP+ICMP active)")
	case wantAdmin:
		return "Scanning (elevated helper — ARP+ICMP via subprocess)"
	default:
		return "Scanning (TCP only — check Admin/ARP for full results)"
	}
}
