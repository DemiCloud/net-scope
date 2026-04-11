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

	// hwndActiveDBDialogAtomic holds the HWND of the currently-open Databases
	// dialog, or 0 if none is open. Used to forward OUI download results.
	hwndActiveDBDialogAtomic uintptr

	// hwndPickDialogAtomic holds the HWND of the currently-open Query Host
	// (pick host) dialog, or 0 if none is open. Used to route ResolveResult
	// messages back to the dialog that issued the "resolve" command.
	hwndPickDialogAtomic uintptr
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
				// WorkUpdate is often bundled with Result in the same message.
				// Handle it here so state transitions aren't lost.
				if m.WorkUpdate != nil {
					pendingWorkUpdatesMu.Lock()
					widx := len(pendingWorkUpdates)
					pendingWorkUpdates = append(pendingWorkUpdates, *m.WorkUpdate)
					pendingWorkUpdatesMu.Unlock()
					postMessage(hwnd, WM_WORK_UPDATE, uintptr(widx), 0)
				}
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
			} else if m.BcastReady {
				pendingListenerMsgsMu.Lock()
				idx := len(pendingListenerMsgs)
				pendingListenerMsgs = append(pendingListenerMsgs, m.BcastErr)
				pendingListenerMsgsMu.Unlock()
				postMessage(hwnd, WM_LISTENER_STATUS, uintptr(idx), 0)
			} else if m.BcastSvc != nil {
				pendingBcastMu.Lock()
				idx := len(pendingBcast)
				pendingBcast = append(pendingBcast, bcastEntry{m.BcastIP, *m.BcastSvc})
				pendingBcastMu.Unlock()
				postMessage(hwnd, WM_BCAST_SVC, uintptr(idx), 0)
			} else if m.SvcUpdate != nil {
				pendingSvcUpdatesMu.Lock()
				idx := len(pendingSvcUpdates)
				pendingSvcUpdates = append(pendingSvcUpdates, *m.SvcUpdate)
				pendingSvcUpdatesMu.Unlock()
				postMessage(hwnd, WM_SVC_UPDATE, uintptr(idx), 0)
			} else if m.WorkUpdate != nil {
				pendingWorkUpdatesMu.Lock()
				idx := len(pendingWorkUpdates)
				pendingWorkUpdates = append(pendingWorkUpdates, *m.WorkUpdate)
				pendingWorkUpdatesMu.Unlock()
				postMessage(hwnd, WM_WORK_UPDATE, uintptr(idx), 0)		} else if m.WorkerStatus != nil {
			pendingWorkerStatusesMu.Lock()
			idx := len(pendingWorkerStatuses)
			pendingWorkerStatuses = append(pendingWorkerStatuses, *m.WorkerStatus)
			pendingWorkerStatusesMu.Unlock()
			postMessage(hwnd, WM_WORKER_STATUS, uintptr(idx), 0)			} else if m.PTRUpdate != nil {
				if m.PTRUpdate.Hostname != "" {
					pendingEnrichMu.Lock()
					idx := len(pendingEnriches)
					pendingEnriches = append(pendingEnriches, enrichEvent{ip: m.PTRUpdate.IP, hostname: m.PTRUpdate.Hostname})
					pendingEnrichMu.Unlock()
					postMessage(hwnd, WM_HOST_ENRICH, uintptr(idx), 0)
				}
			} else if m.ARPEntry != nil {
				mac, _ := net.ParseMAC(m.ARPEntry.MAC)
				if mac != nil {
					pendingEnrichMu.Lock()
					idx := len(pendingEnriches)
					pendingEnriches = append(pendingEnriches, enrichEvent{ip: m.ARPEntry.IP, mac: mac})
					pendingEnrichMu.Unlock()
					postMessage(hwnd, WM_HOST_ENRICH, uintptr(idx), 0)
				}
			} else if m.Netbios != nil {
				if m.Netbios.Name != "" {
					pendingEnrichMu.Lock()
					idx := len(pendingEnriches)
					pendingEnriches = append(pendingEnriches, enrichEvent{ip: m.Netbios.IP, netbios: m.Netbios.Name})
					pendingEnrichMu.Unlock()
					postMessage(hwnd, WM_HOST_ENRICH, uintptr(idx), 0)
				}
			} else if m.ProxyOK {
				postMessage(hwnd, WM_PROXY_VALID, 0, 0)
			} else if m.ProxyErr != "" {
				pendingProxyErrMu.Lock()
				idx := len(pendingProxyErrors)
				pendingProxyErrors = append(pendingProxyErrors, m.ProxyErr)
				pendingProxyErrMu.Unlock()
				postMessage(hwnd, WM_PROXY_FAIL, uintptr(idx), 0)
			} else if m.OUIComplete {
				if h := atomic.LoadUintptr(&hwndActiveDBDialogAtomic); h != 0 {
					postMessage(HWND(h), WM_OUI_SUCCESS, 0, 0)
				}
			} else if m.OUIErr != "" {
				if h := atomic.LoadUintptr(&hwndActiveDBDialogAtomic); h != 0 {
					postMessage(HWND(h), WM_OUI_FAIL, 0, 0)
				}
			} else if m.ResolveResult != nil {
				rr := m.ResolveResult
				pendingResolveHostsMu.Lock()
				idx := len(pendingResolveHosts)
				pendingResolveHosts = append(pendingResolveHosts, resolveHostResult{
					hostname: rr.Hostname,
					ips:      rr.IPs,
					ptrNames: rr.PTRNames,
					err:      rr.Err,
				})
				pendingResolveHostsMu.Unlock()
				if h := atomic.LoadUintptr(&hwndPickDialogAtomic); h != 0 {
					postMessage(HWND(h), WM_RESOLVE_HOST, uintptr(idx), 0)
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

// sendResolveViaService asks the service to perform a forward DNS lookup for
// hostname. The result is delivered asynchronously as WM_RESOLVE_HOST posted
// to the active pick-host dialog (hwndPickDialogAtomic).
func sendResolveViaService(hostname string) error {
	serviceMu.Lock()
	enc := serviceEnc
	serviceMu.Unlock()
	if enc == nil {
		return errors.New("sensor service is not running")
	}
	serviceEncMu.Lock()
	err := enc.Encode(scan.ServiceCmd{Cmd: "resolve", Target: hostname})
	serviceEncMu.Unlock()
	return err
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

// serviceCmd is a low-level helper that encodes a single command if the
// service is connected. Returns false if no service is running.
func serviceCmd(cmd scan.ServiceCmd) bool {
	serviceMu.Lock()
	enc := serviceEnc
	serviceMu.Unlock()
	if enc == nil {
		return false
	}
	serviceEncMu.Lock()
	_ = enc.Encode(cmd)
	serviceEncMu.Unlock()
	return true
}

// startBroadcastListenerViaService tells the service to start the mDNS/SSDP/WSD
// listener. The service streams results back as BcastSvc events and sends a
// BcastReady message once the listener starts or fails to bind.
// Returns false if the service is not running.
func startBroadcastListenerViaService(bcastListen string) bool {
	return serviceCmd(scan.ServiceCmd{Cmd: "bcast-start", BcastListen: bcastListen})
}

// stopBroadcastListenerViaService cancels the service-side broadcast listener.
func stopBroadcastListenerViaService() {
	serviceCmd(scan.ServiceCmd{Cmd: "bcast-stop"}) //nolint:errcheck
}

// startARPPollViaService tells the service to begin periodic ARP table reads.
// Each entry streams back as a WM_HOST_ENRICH enrichment event.
func startARPPollViaService() {
	serviceCmd(scan.ServiceCmd{Cmd: "arp-start"}) //nolint:errcheck
}

// stopARPPollViaService cancels the service-side ARP polling loop.
func stopARPPollViaService() {
	serviceCmd(scan.ServiceCmd{Cmd: "arp-stop"}) //nolint:errcheck
}

// sendNetBIOSViaService asks the service to query the NetBIOS name for ip.
// If found, it streams back a Netbios enrichment event.
func sendNetBIOSViaService(ip string) {
	serviceCmd(scan.ServiceCmd{Cmd: "netbios", Target: ip}) //nolint:errcheck
}

// testProxyViaService asks the service to test TCP connectivity to proxyAddr.
// The result arrives as WM_PROXY_VALID or WM_PROXY_FAIL. Returns false if the
// service is not running.
func testProxyViaService(proxyAddr string) bool {
	return serviceCmd(scan.ServiceCmd{Cmd: "proxy-test", SOCKSProxy: proxyAddr})
}

// downloadOUIViaService asks the service to download and install the OUI
// database into dataDir. The result arrives as WM_OUI_SUCCESS or WM_OUI_FAIL
// posted to hwndActiveDBDialogAtomic. Returns false if the service is not running.
func downloadOUIViaService(dataDir string) bool {
	return serviceCmd(scan.ServiceCmd{Cmd: "oui-update", DataDir: dataDir})
}
