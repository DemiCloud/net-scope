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
// Persistent sensor service state
// ---------------------------------------------------------------------------

// svcRestartMaxAttempts is the maximum number of automatic restart attempts
// allowed within svcRestartWindow before giving up and showing an error.
const (
	svcRestartMaxAttempts = 3
	svcRestartWindow      = 30 * time.Second
)

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

	// serviceShuttingDown is set to true during WM_DESTROY to suppress
	// automatic service restarts while the application is closing.
	// Accessed only from the UI thread.
	serviceShuttingDown bool

	// svcRestartCount and svcRestartWindowStart track how many automatic
	// restarts have occurred within the current svcRestartWindow interval.
	// These are accessed only from the UI thread (WM_SERVICE_DOWN handler).
	svcRestartCount       int
	svcRestartWindowStart time.Time

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

	// hwndARPCacheDialogAtomic holds the HWND of the currently-open ARP
	// Cache dialog, or 0. Used to route arp-snapshot and cache-op messages.
	hwndARPCacheDialogAtomic uintptr

	// hwndDNSCacheDialogAtomic holds the HWND of the currently-open DNS
	// Cache dialog, or 0. Used to route dns-snapshot and cache-op messages.
	hwndDNSCacheDialogAtomic uintptr

	// hwndRouteTableDialogAtomic holds the HWND of the currently-open Route
	// Table dialog, or 0. Used to route route-snapshot and cache-op messages.
	hwndRouteTableDialogAtomic uintptr

	// hwndConnectionsDialogAtomic holds the HWND of the currently-open Active
	// Connections dialog, or 0.
	hwndConnectionsDialogAtomic uintptr

	// hwndHostsDialogAtomic holds the HWND of the currently-open Hosts File
	// dialog, or 0.
	hwndHostsDialogAtomic uintptr

	// hwndInterfacesDialogAtomic holds the HWND of the currently-open Local
	// Interfaces dialog, or 0.
	hwndInterfacesDialogAtomic uintptr

	// hwndEvtLogDialogAtomic holds the HWND of the currently-open Network
	// Event Log dialog, or 0.
	hwndEvtLogDialogAtomic uintptr

	// hwndProbeDlgAtomic holds the HWND of the currently-open deep Probe
	// dialog, or 0 if none is open.
	hwndProbeDlgAtomic uintptr

	// svcGeneration is incremented each time spawnService is called. Each
	// spawned goroutine captures its generation at creation and only posts
	// WM_SERVICE_DOWN when its generation still matches the current value.
	// This prevents stale goroutines (e.g. from a stopped service that was
	// intentionally replaced) from triggering spurious auto-restarts.
	svcGeneration uint64
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

// svcMaybeRestart attempts to automatically restart the sensor service after
// an unexpected disconnect. Returns true if a restart was attempted, false if
// the restart limit was reached (caller should surface an error to the user).
// Must be called from the UI thread.
func svcMaybeRestart(hwnd HWND) bool {
	if serviceShuttingDown {
		return false
	}
	now := time.Now()
	if now.Sub(svcRestartWindowStart) > svcRestartWindow {
		// Reset the counter when the previous window has expired.
		svcRestartCount = 0
		svcRestartWindowStart = now
	}
	if svcRestartCount >= svcRestartMaxAttempts {
		return false
	}
	svcRestartCount++
	startService(hwnd)
	return true
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
	// Claim a generation ticket before spawning. Any goroutine from a
	// previous spawnService call now has a stale generation and will not
	// post WM_SERVICE_DOWN when it eventually finishes.
	gen := atomic.AddUint64(&svcGeneration, 1)

	exe, err := os.Executable()
	if err != nil {
		showError(hwnd, ErrFindExe, "Cannot locate executable:\n"+err.Error(), "NetScope")
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
		showError(hwnd, ErrCreateListener, "Cannot create service listener:\n"+err.Error(), "NetScope")
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
			if atomic.LoadUint64(&svcGeneration) == gen {
				postMessage(hwnd, WM_SERVICE_DOWN, 0, 0)
			}
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
			if atomic.LoadUint64(&svcGeneration) == gen {
				postMessage(hwnd, WM_SERVICE_DOWN, 0, 0)
			}
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
			} else if m.ProbeHost != nil {
				pendingProbeHostsMu.Lock()
				idx := len(pendingProbeHosts)
				pendingProbeHosts = append(pendingProbeHosts, *m.ProbeHost)
				pendingProbeHostsMu.Unlock()
				postMessage(hwnd, WM_PROBE_HOST, uintptr(idx), 0)
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
				if m.ARPSnapshot {
					// Snapshot entry: route to main window (handler in ui.go) only
					// when the ARP Cache dialog is open.
					if atomic.LoadUintptr(&hwndARPCacheDialogAtomic) != 0 {
						pendingARPSnapMu.Lock()
						idx := len(pendingARPSnap)
						pendingARPSnap = append(pendingARPSnap, *m.ARPEntry)
						pendingARPSnapMu.Unlock()
						postMessage(hwnd, WM_ARP_SNAP_ENTRY, uintptr(idx), 0)
					}
				} else {
					// Poll entry: enrich the hosts list (existing behaviour).
					mac, _ := net.ParseMAC(m.ARPEntry.MAC)
					if mac != nil {
						pendingEnrichMu.Lock()
						idx := len(pendingEnriches)
						pendingEnriches = append(pendingEnriches, enrichEvent{ip: m.ARPEntry.IP, mac: mac})
						pendingEnrichMu.Unlock()
						postMessage(hwnd, WM_HOST_ENRICH, uintptr(idx), 0)
					}
				}
			} else if m.ARPSnapDone {
				if atomic.LoadUintptr(&hwndARPCacheDialogAtomic) != 0 {
					postMessage(hwnd, WM_ARP_SNAP_DONE, 0, 0)
				}
			} else if m.DNSEntry != nil {
				if atomic.LoadUintptr(&hwndDNSCacheDialogAtomic) != 0 {
					pendingDNSSnapMu.Lock()
					idx := len(pendingDNSSnap)
					pendingDNSSnap = append(pendingDNSSnap, *m.DNSEntry)
					pendingDNSSnapMu.Unlock()
					postMessage(hwnd, WM_DNS_SNAP_ENTRY, uintptr(idx), 0)
				}
			} else if m.DNSSnapDone {
				if atomic.LoadUintptr(&hwndDNSCacheDialogAtomic) != 0 {
					postMessage(hwnd, WM_DNS_SNAP_DONE, 0, 0)
				}
			} else if m.CacheOp != nil {
				pendingCacheOpMu.Lock()
				idx := len(pendingCacheOps)
				pendingCacheOps = append(pendingCacheOps, *m.CacheOp)
				pendingCacheOpMu.Unlock()
				// Route to main window if any write-op dialog is open.
				if atomic.LoadUintptr(&hwndARPCacheDialogAtomic) != 0 ||
					atomic.LoadUintptr(&hwndDNSCacheDialogAtomic) != 0 ||
					atomic.LoadUintptr(&hwndRouteTableDialogAtomic) != 0 ||
					atomic.LoadUintptr(&hwndHostsDialogAtomic) != 0 {
					postMessage(hwnd, WM_CACHE_OP, uintptr(idx), 0)
				}
			} else if m.RouteEntry != nil {
				if atomic.LoadUintptr(&hwndRouteTableDialogAtomic) != 0 {
					pendingRouteSnapMu.Lock()
					idx := len(pendingRouteSnap)
					pendingRouteSnap = append(pendingRouteSnap, *m.RouteEntry)
					pendingRouteSnapMu.Unlock()
					postMessage(hwnd, WM_ROUTE_SNAP_ENTRY, uintptr(idx), 0)
				}
			} else if m.RouteSnapDone {
				if atomic.LoadUintptr(&hwndRouteTableDialogAtomic) != 0 {
					postMessage(hwnd, WM_ROUTE_SNAP_DONE, 0, 0)
				}
			} else if m.SocketEntry != nil {
				if atomic.LoadUintptr(&hwndConnectionsDialogAtomic) != 0 {
					pendingSocketSnapMu.Lock()
					idx := len(pendingSocketSnap)
					pendingSocketSnap = append(pendingSocketSnap, *m.SocketEntry)
					pendingSocketSnapMu.Unlock()
					postMessage(hwnd, WM_SOCKET_SNAP_ENTRY, uintptr(idx), 0)
				}
			} else if m.SocketSnapDone {
				if atomic.LoadUintptr(&hwndConnectionsDialogAtomic) != 0 {
					postMessage(hwnd, WM_SOCKET_SNAP_DONE, 0, 0)
				}
			} else if m.HostsEntry != nil {
				if atomic.LoadUintptr(&hwndHostsDialogAtomic) != 0 {
					pendingHostsSnapMu.Lock()
					idx := len(pendingHostsSnap)
					pendingHostsSnap = append(pendingHostsSnap, *m.HostsEntry)
					pendingHostsSnapMu.Unlock()
					postMessage(hwnd, WM_HOSTS_SNAP_ENTRY, uintptr(idx), 0)
				}
			} else if m.HostsSnapDone {
				if atomic.LoadUintptr(&hwndHostsDialogAtomic) != 0 {
					postMessage(hwnd, WM_HOSTS_SNAP_DONE, 0, 0)
				}
			} else if m.IfEntry != nil {
				if atomic.LoadUintptr(&hwndInterfacesDialogAtomic) != 0 {
					pendingIfSnapMu.Lock()
					idx := len(pendingIfSnap)
					pendingIfSnap = append(pendingIfSnap, *m.IfEntry)
					pendingIfSnapMu.Unlock()
					postMessage(hwnd, WM_IF_SNAP_ENTRY, uintptr(idx), 0)
				}
			} else if m.IfSnapDone {
				if atomic.LoadUintptr(&hwndInterfacesDialogAtomic) != 0 {
					postMessage(hwnd, WM_IF_SNAP_DONE, 0, 0)
				}
			} else if m.EventLogEntry != nil {
				if atomic.LoadUintptr(&hwndEvtLogDialogAtomic) != 0 {
					pendingEvtLogSnapMu.Lock()
					idx := len(pendingEvtLogSnap)
					pendingEvtLogSnap = append(pendingEvtLogSnap, *m.EventLogEntry)
					pendingEvtLogSnapMu.Unlock()
					postMessage(hwnd, WM_EVT_SNAP_ENTRY, uintptr(idx), 0)
				}
			} else if m.EventLogSnapDone {
				if atomic.LoadUintptr(&hwndEvtLogDialogAtomic) != 0 {
					postMessage(hwnd, WM_EVT_SNAP_DONE, 0, 0)
				}
			} else if m.ProbeEvent != nil {
				pendingProbeEventsMu.Lock()
				idx := len(pendingProbeEvents)
				pendingProbeEvents = append(pendingProbeEvents, *m.ProbeEvent)
				pendingProbeEventsMu.Unlock()
				if h := atomic.LoadUintptr(&hwndProbeDlgAtomic); h != 0 {
					if m.ProbeEvent.Done {
						postMessage(HWND(h), WM_PROBE_DONE, uintptr(idx), 0)
					} else {
						postMessage(HWND(h), WM_PROBE_EVENT, uintptr(idx), 0)
					}
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
			} else if m.WolResult != nil {
				pendingWolMu.Lock()
				idx := len(pendingWolResults)
				pendingWolResults = append(pendingWolResults, *m.WolResult)
				pendingWolMu.Unlock()
				postMessage(hwnd, WM_WOL_RESULT, uintptr(idx), 0)
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
		// Only signal a service-down event if this goroutine's generation is
		// still current. A stale goroutine (whose service was intentionally
		// replaced by elevateService or a respawn) must not trigger a fresh
		// auto-restart on top of the new service.
		if atomic.LoadUint64(&svcGeneration) == gen {
			postMessage(hwnd, WM_SERVICE_DOWN, 0, 0)
		}
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

// dhcpPlaceholderText returns the correct empty-state message for the DHCP tab
// based on the current proxy and elevation state.
func dhcpPlaceholderText() string {
	if proxyEnabled {
		return "Not available in proxy mode \u2014 DHCP capture requires local network interface access"
	}
	if serviceElevated {
		return "Listening \u2014 no DHCP traffic detected"
	}
	return "Not listening \u2014 sensor is running in user mode (requires elevation)"
}

// statusForService returns a short label for the service-state overlay.
func statusForService() string {
	serviceMu.Lock()
	defer serviceMu.Unlock()
	if serviceConn == nil {
		return "Sensor: offline"
	}
	if serviceElevated {
		return "Sensor: ready (Admin)"
	}
	return "Sensor: ready (User)"
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

// requestARPSnapshot sends an "arp-snapshot" command; entries arrive as
// WM_ARP_SNAP_ENTRY posted to hwndARPCacheDialogAtomic, followed by
// WM_ARP_SNAP_DONE. Returns false if the service is not running.
func requestARPSnapshot() bool {
	return serviceCmd(scan.ServiceCmd{Cmd: "arp-snapshot"})
}

// requestARPDelete asks the (elevated) service to remove the ARP entry for ip.
// The result arrives as WM_CACHE_OP posted to hwndARPCacheDialogAtomic.
func requestARPDelete(ip string) bool {
	return serviceCmd(scan.ServiceCmd{Cmd: "arp-delete", Target: ip})
}

// requestARPClear asks the (elevated) service to flush all dynamic ARP entries.
// The result arrives as WM_CACHE_OP.
func requestARPClear() bool {
	return serviceCmd(scan.ServiceCmd{Cmd: "arp-clear"})
}

// requestDNSSnapshot sends a "dns-snapshot" command; entries arrive as
// WM_DNS_SNAP_ENTRY posted to hwndDNSCacheDialogAtomic, followed by
// WM_DNS_SNAP_DONE. Returns false if the service is not running.
func requestDNSSnapshot() bool {
	return serviceCmd(scan.ServiceCmd{Cmd: "dns-snapshot"})
}

// requestDNSDelete asks the (elevated) service to remove the DNS cache entry
// for the given hostname. The result arrives as WM_CACHE_OP.
func requestDNSDelete(name string) bool {
	return serviceCmd(scan.ServiceCmd{Cmd: "dns-delete", Target: name})
}

// requestDNSClear asks the service to flush the DNS resolver cache.
// The result arrives as WM_CACHE_OP posted to hwndDNSCacheDialogAtomic.
func requestDNSClear() bool {
	return serviceCmd(scan.ServiceCmd{Cmd: "dns-clear"})
}

// requestRouteSnapshot sends a "route-snapshot" command; entries arrive as
// WM_ROUTE_SNAP_ENTRY posted to the main window, followed by WM_ROUTE_SNAP_DONE.
// Returns false if the service is not running.
func requestRouteSnapshot() bool {
	return serviceCmd(scan.ServiceCmd{Cmd: "route-snapshot"})
}

// requestRouteDelete asks the (elevated) service to remove a routing-table
// entry. target is "dest|mask|gateway" in dotted-decimal notation.
// The result arrives as WM_CACHE_OP.
func requestRouteDelete(target string) bool {
	return serviceCmd(scan.ServiceCmd{Cmd: "route-delete", Target: target})
}

// requestSocketSnapshot sends a "socket-snapshot" command; entries arrive as
// WM_SOCKET_SNAP_ENTRY followed by WM_SOCKET_SNAP_DONE.
// Returns false if the service is not running.
func requestSocketSnapshot() bool {
	return serviceCmd(scan.ServiceCmd{Cmd: "socket-snapshot"})
}

// requestHostsSnapshot sends a "hosts-snapshot" command; entries arrive as
// WM_HOSTS_SNAP_ENTRY followed by WM_HOSTS_SNAP_DONE.
// Returns false if the service is not running.
func requestHostsSnapshot() bool {
	return serviceCmd(scan.ServiceCmd{Cmd: "hosts-snapshot"})
}

// requestHostsAdd asks the service to append a new entry to the hosts file.
// The result arrives as WM_CACHE_OP (op = "hosts-add").
func requestHostsAdd(ip string, hostnames []string) bool {
	return serviceCmd(scan.ServiceCmd{
		Cmd:      "hosts-add",
		HostsAdd: &scan.HostsAddParams{IP: ip, Hostnames: hostnames},
	})
}

// requestHostsDelete asks the service to remove a hosts-file entry.
// target is "IP\thostname1 hostname2..." as produced by hostsEntryTarget.
// The result arrives as WM_CACHE_OP (op = "hosts-delete").
func requestHostsDelete(target string) bool {
	return serviceCmd(scan.ServiceCmd{Cmd: "hosts-delete", Target: target})
}

// requestIfSnapshot sends an "if-snapshot" command; entries arrive as
// WM_IF_SNAP_ENTRY followed by WM_IF_SNAP_DONE.
// Returns false if the service is not running.
func requestIfSnapshot() bool {
	return serviceCmd(scan.ServiceCmd{Cmd: "if-snapshot"})
}

// requestEventLogSnapshot sends an "eventlog-snapshot" command; entries arrive
// as WM_EVT_SNAP_ENTRY (posted to hwndEvtLogDialogAtomic) followed by
// WM_EVT_SNAP_DONE. Returns false if the service is not running.
func requestEventLogSnapshot() bool {
	return serviceCmd(scan.ServiceCmd{Cmd: "eventlog-snapshot"})
}

// requestWakeOnLAN asks the service to send a Wake-on-LAN magic packet.
// mac is a MAC address string (e.g. "aa:bb:cc:dd:ee:ff") and broadcast is the
// UDP destination (e.g. "192.168.1.255"); an empty broadcast defaults to
// "255.255.255.255" in the service.
// The result arrives as WM_WOL_RESULT. Returns false if the service is not running.
func requestWakeOnLAN(mac, broadcast string) bool {
	return serviceCmd(scan.ServiceCmd{Cmd: "wake", WolMAC: mac, WolBroadcast: broadcast})
}
