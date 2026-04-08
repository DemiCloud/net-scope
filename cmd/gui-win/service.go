//go:build windows

package guiwin

import (
	"encoding/json"
	"net"
	"os"
	"sync"
	"time"

	"github.com/demicloud/net-scope/internal/scan"
)

// ---------------------------------------------------------------------------
// Persistent scan service state
// ---------------------------------------------------------------------------

var (
	serviceMu       sync.Mutex
	serviceConn     net.Conn
	serviceEnc      *json.Encoder
	serviceDec      *json.Decoder
	serviceElevated bool // true if the running service process is admin

	// serviceDecMu serialises access to serviceDec. The JSON decoder is not
	// goroutine-safe; holding this for the entire decode loop in
	// sendScanViaService prevents a second scan goroutine from reading
	// concurrently with an outgoing one (stop → immediate rescan race).
	serviceDecMu sync.Mutex
)

// serviceRunning returns true if there is a live service connection.
func serviceRunning() bool {
	serviceMu.Lock()
	defer serviceMu.Unlock()
	return serviceConn != nil
}

// startService spawns a new service subprocess (user-level, no UAC).
// Must be called from the UI thread; the goroutine handles the connection.
func startService(hwnd HWND) {
	spawnService(hwnd, false)
}

// elevateService spawns a new service subprocess via UAC (admin).
// Stops any existing service first.
func elevateService(hwnd HWND) {
	stopService()
	spawnService(hwnd, true)
}

// stopService tears down the current service connection if any.
func stopService() {
	serviceMu.Lock()
	defer serviceMu.Unlock()
	if serviceConn != nil {
		enc := serviceEnc
		serviceConn = nil
		serviceEnc = nil
		serviceDec = nil
		serviceElevated = false
		// Best-effort graceful shutdown.
		_ = enc.Encode(scan.ServiceCmd{Cmd: "shutdown"})
	}
}

func spawnService(hwnd HWND, elevated bool) {
	exe, err := os.Executable()
	if err != nil {
				messageBox(hwnd, "Cannot locate executable:\n"+err.Error(), "NetScope", MB_ICONERROR)
		return
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
				messageBox(hwnd, "Cannot open service listener:\n"+err.Error(), "NetScope", MB_ICONERROR)
		return
	}
	addr := ln.Addr().String()

	if elevated {
		shellExecute(0, "runas", exe, "--service="+addr, "", SW_HIDE)
	} else {
		shellExecute(0, "open", exe, "--service="+addr, "", SW_HIDE)
	}

	go func() {
		defer func() {
			if p := recover(); p != nil {
				writeCrashLog(hwnd, p)
			}
		}()

		ln.(*net.TCPListener).SetDeadline(time.Now().Add(60 * time.Second))
		conn, err := ln.Accept()
		ln.Close()
		if err != nil {
			postMessage(hwnd, WM_SERVICE_DOWN, 0, 0)
			return
		}

		dec := json.NewDecoder(conn)
		enc := json.NewEncoder(conn)

		// First message must be the ready handshake.
		var msg scan.ServiceMsg
		if err := dec.Decode(&msg); err != nil || !msg.Ready {
			conn.Close()
			postMessage(hwnd, WM_SERVICE_DOWN, 0, 0)
			return
		}

		serviceMu.Lock()
		// Close any previous connection.
		if serviceConn != nil {
			serviceConn.Close()
		}
		serviceConn = conn
		serviceEnc = enc
		serviceDec = dec
		serviceElevated = msg.Elevated
		serviceMu.Unlock()

		postMessage(hwnd, WM_SERVICE_UP, 0, 0)
	}()
}

// sendScanViaService sends a scan command to the running service and pumps
// results back through the normal WM_SCAN_RESULT / WM_SCAN_COMPLETE pipeline.
func sendScanViaService(hwnd HWND, target string, cfg scan.Config) {
	serviceMu.Lock()
	enc := serviceEnc
	dec := serviceDec
	conn := serviceConn
	serviceMu.Unlock()

	if enc == nil {
		postMessage(hwnd, WM_SCAN_COMPLETE, 0, 0)
		return
	}

	go func() {
		defer func() {
			if p := recover(); p != nil {
				writeCrashLog(hwnd, p)
				postMessage(hwnd, WM_SCAN_COMPLETE, 0, 0)
			}
		}()

		// Acquire exclusive ownership of the decoder for the lifetime of this
		// scan's response stream. A previous scan goroutine may still be
		// draining its final messages; block until it is done.
		serviceDecMu.Lock()
		defer serviceDecMu.Unlock()

		if err := enc.Encode(scan.ServiceCmd{Cmd: "scan", Target: target, Config: &cfg}); err != nil {
			postMessage(hwnd, WM_SCAN_COMPLETE, 0, 0)
			return
		}

		for {
			var msg scan.ServiceMsg
			if err := dec.Decode(&msg); err != nil {
				// Connection lost mid-scan.
				serviceMu.Lock()
				if serviceConn == conn {
					serviceConn = nil
					serviceEnc = nil
					serviceDec = nil
					serviceElevated = false
					conn.Close()
				}
				serviceMu.Unlock()
				postMessage(hwnd, WM_SERVICE_DOWN, 0, 0)
				break
			}
			if msg.Err != "" {
				break
			}
			if msg.Done {
				if msg.Stats != nil {
					pendingMu.Lock()
					lastStats = *msg.Stats
					pendingMu.Unlock()
				}
				break
			}
			if msg.Result != nil {
				pendingMu.Lock()
				idx := len(pendingResults)
				pendingResults = append(pendingResults, *msg.Result)
				pendingMu.Unlock()
				postMessage(hwnd, WM_SCAN_RESULT, uintptr(idx), 0)
			}
			if msg.DHCP != nil {
				pendingDHCPMu.Lock()
				idx := len(pendingDHCP)
				pendingDHCP = append(pendingDHCP, *msg.DHCP)
				pendingDHCPMu.Unlock()
				postMessage(hwnd, WM_DHCP_EVENT, uintptr(idx), 0)
			}
		}
		postMessage(hwnd, WM_SCAN_COMPLETE, 0, 0)
	}()
}

// stopServiceScan sends a stop command to the running service, if any.
// Safe to call when no service is running.
func stopServiceScan() {
	serviceMu.Lock()
	enc := serviceEnc
	serviceMu.Unlock()
	if enc != nil {
		_ = enc.Encode(scan.ServiceCmd{Cmd: "stop"})
	}
}

// startDHCPCapture tells the elevated service to begin passive DHCP capture.
// Events stream back as ServiceMsg{DHCP: &evt} and are posted to the UI thread
// as WM_DHCP_EVENT. Safe to call when no service is running (no-op).
func startDHCPCapture(hwnd HWND) {
	serviceMu.Lock()
	enc := serviceEnc
	serviceMu.Unlock()
	if enc == nil {
		return
	}
	_ = enc.Encode(scan.ServiceCmd{Cmd: "dhcp-start"})
}

// statusForService returns a short label for the service-state overlay.
func statusForService() string {
	serviceMu.Lock()
	defer serviceMu.Unlock()
	if serviceConn == nil {
		return "Service: starting…"
	}
	if serviceElevated {
		return "Service: running (Admin)"
	}
	return "Service: running (User)"
}
