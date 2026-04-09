//go:build windows

package guiwin

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
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
	serviceElevated bool // true if the running service process is admin

	// serviceEncMu serialises all writes to serviceEnc. json.Encoder has no
	// internal lock; concurrent Encode calls (scan + probe + stopServiceScan
	// + startDHCPCapture) corrupt the wire stream and cause the remote
	// decoder to panic.
	serviceEncMu sync.Mutex

	// hwndActiveProbeDialogAtomic holds the HWND of the currently-open host
	// detail dialog, or 0 if none is open. Accessed atomically: written by
	// the UI thread (open/close), read by the service receive goroutine.
	hwndActiveProbeDialogAtomic uintptr
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
		serviceElevated = false
		// Best-effort graceful shutdown — hold serviceEncMu so we don't
		// race with a concurrent Encode.
		serviceEncMu.Lock()
		_ = enc.Encode(scan.ServiceCmd{Cmd: "shutdown"})
		serviceEncMu.Unlock()
	}
}

func spawnService(hwnd HWND, elevated bool) {
	exe, err := os.Executable()
	if err != nil {
		messageBox(hwnd, "Cannot locate executable:\n"+err.Error(), "NetScope", MB_ICONERROR)
		return
	}

	// Generate an ephemeral TLS certificate for this service session.
	// The hex-encoded SHA-256 cert fingerprint is passed to the subprocess via
	// argv. The subprocess pins this fingerprint when dialling, verifying it
	// connected to our listener. Because the private key never leaves this
	// process, knowing the fingerprint alone cannot impersonate the server.
	// All session traffic is encrypted (TLS 1.3).
	tcpLn, tlsCfg, fingerprint, err := scan.NewServiceTLS()
	if err != nil {
		messageBox(hwnd, "Cannot create service listener:\n"+err.Error(), "NetScope", MB_ICONERROR)
		return
	}
	tlsLn := tls.NewListener(tcpLn, tlsCfg)
	addr := tcpLn.Addr().String()

	// Spawn: net-scope service <addr> <fingerprint>
	params := "service " + addr + " " + fingerprint
	if elevated {
		shellExecute(0, "runas", exe, params, "", SW_HIDE)
	} else {
		shellExecute(0, "open", exe, params, "", SW_HIDE)
	}

	go func() {
		defer func() {
			if p := recover(); p != nil {
				writeCrashLog(hwnd, p)
			}
		}()

		tcpLn.SetDeadline(time.Now().Add(60 * time.Second))
		conn, err := tlsLn.Accept()
		tlsLn.Close()
		if err != nil {
			postMessage(hwnd, WM_SERVICE_DOWN, 0, 0)
			return
		}

		dec := json.NewDecoder(conn)
		enc := json.NewEncoder(conn)

		// First message must be the ready handshake. Authentication has already
		// been established by the TLS handshake with cert fingerprint pinning.
		var msg scan.ServiceMsg
		conn.SetDeadline(time.Now().Add(10 * time.Second))
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
		conn.SetDeadline(time.Time{}) // clear deadline for subsequent reads
		serviceConn = conn
		serviceEnc = enc
		serviceElevated = msg.Elevated
		serviceMu.Unlock()

		postMessage(hwnd, WM_SERVICE_UP, 0, 0)

		// Persistent receive loop — runs for the lifetime of this connection.
		// Routes incoming service messages to the appropriate WndProc messages.
		for {
			var m scan.ServiceMsg
			if err := dec.Decode(&m); err != nil {
				break
			}
			if m.Done {
				if m.Stats != nil {
					pendingMu.Lock()
					lastStats = *m.Stats
					pendingMu.Unlock()
				}
				postMessage(hwnd, WM_SCAN_COMPLETE, uintptr(m.ScanID), 0)
			} else if m.Result != nil {
				pendingMu.Lock()
				idx := len(pendingResults)
				pendingResults = append(pendingResults, *m.Result)
				pendingMu.Unlock()
				postMessage(hwnd, WM_SCAN_RESULT, uintptr(idx), uintptr(m.ScanID))
			} else if m.DHCP != nil {
				pendingDHCPMu.Lock()
				idx := len(pendingDHCP)
				pendingDHCP = append(pendingDHCP, *m.DHCP)
				pendingDHCPMu.Unlock()
				postMessage(hwnd, WM_DHCP_EVENT, uintptr(idx), 0)
			} else if m.ProbeResult != nil {
				pendingProbeResultsMu.Lock()
				idx := len(pendingProbeResults)
				pendingProbeResults = append(pendingProbeResults, *m.ProbeResult)
				pendingProbeResultsMu.Unlock()
				if h := atomic.LoadUintptr(&hwndActiveProbeDialogAtomic); h != 0 {
					postMessage(HWND(h), WM_PROBE_RESULT, uintptr(idx), 0)
				}
			}
		}

		// Connection closed (normally or due to error). Clean up.
		serviceMu.Lock()
		if serviceConn == conn {
			serviceConn = nil
			serviceEnc = nil
			serviceElevated = false
			conn.Close()
		}
		serviceMu.Unlock()
		postMessage(hwnd, WM_SERVICE_DOWN, 0, 0)
	}()
}

// sendScanViaService sends a scan command to the running service. Results are
// delivered asynchronously through the persistent receive loop as
// WM_SCAN_RESULT / WM_SCAN_COMPLETE messages. gen is echoed back by the
// service in every message so the UI thread can discard results from
// superseded scans.
func sendScanViaService(hwnd HWND, target string, cfg scan.Config, gen uint64) {
	serviceMu.Lock()
	enc := serviceEnc
	serviceMu.Unlock()

	if enc == nil {
		postMessage(hwnd, WM_SCAN_COMPLETE, uintptr(gen), 0)
		return
	}

	serviceEncMu.Lock()
	err := enc.Encode(scan.ServiceCmd{Cmd: "scan", Target: target, Config: &cfg, ScanID: gen})
	serviceEncMu.Unlock()
	if err != nil {
		postMessage(hwnd, WM_SCAN_COMPLETE, uintptr(gen), 0)
	}
	// Results arrive through the persistent receive loop; no goroutine needed here.
}

// sendProbeViaService sends a single on-demand probe to the running service.
// The result is delivered asynchronously as WM_PROBE_RESULT posted to the
// active host detail dialog (hwndActiveProbeDialogAtomic).
func sendProbeViaService(ip string, spec scan.ProbeSpec, socksProxy string) error {
	serviceMu.Lock()
	enc := serviceEnc
	serviceMu.Unlock()
	if enc == nil {
		return errors.New("sensor service is not running")
	}
	serviceEncMu.Lock()
	err := enc.Encode(scan.ServiceCmd{Cmd: "probe", Target: ip, Probe: &spec, SOCKSProxy: socksProxy})
	serviceEncMu.Unlock()
	return err
}

// stopServiceScan sends a stop command to the running service, if any.
// Safe to call when no service is running.
func stopServiceScan() {
	serviceMu.Lock()
	enc := serviceEnc
	serviceMu.Unlock()
	if enc != nil {
		serviceEncMu.Lock()
		_ = enc.Encode(scan.ServiceCmd{Cmd: "stop"})
		serviceEncMu.Unlock()
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
	serviceEncMu.Lock()
	_ = enc.Encode(scan.ServiceCmd{Cmd: "dhcp-start"})
	serviceEncMu.Unlock()
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
