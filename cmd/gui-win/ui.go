//go:build windows

package guiwin

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/demicloud/net-scope/internal/config"
	"github.com/demicloud/net-scope/internal/scan"
)

// ---------------------------------------------------------------------------
// Global UI handles / resources
// ---------------------------------------------------------------------------

// Win32 COLORREF is 0x00BBGGRR (low byte = red).

// searchEditOrigProc holds the original EDIT window procedure, replaced when
// the find bar's edit control is subclassed to intercept VK_ESCAPE.
var searchEditOrigProc uintptr

// searchEditSubclassCb is the subclass proc for the find bar's EDIT control.
// It intercepts Escape (to dismiss the bar) and forwards everything else
// to the original EDIT procedure.
var searchEditSubclassCb = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	if uint32(msg) == WM_KEYDOWN && wParam == VK_ESCAPE {
		hideFindBar()
		return 0
	}
	return callWindowProc(searchEditOrigProc, HWND(hwnd), uint32(msg), wParam, lParam)
})

// proxyEnabled is set at runtime (session-only; never touches the config file).
// It defaults to true when a SOCKS5 proxy is already configured in settings,
// meaning the proxy starts active on launch if one is saved.
var proxyEnabled bool

// pendingProxyErrors carries error strings from proxy connectivity test goroutines
// back to the UI thread via WM_PROXY_FAIL.
var (
	pendingProxyErrors  []string
	pendingProxyErrMu   sync.Mutex
)

var (
	appFont        HFONT // Segoe UI 9pt — shared by main window and all dialogs
	hwndMain       HWND
	headerHwnd     HWND  // header control of hwndList, for right-click detection
	// Global options bar (top strip, replaces old elevation bar)
	hwndServiceBtn  HWND // "Elevate Sensor" button (disabled once service reports it is elevated)
	hwndProxyCheck  HWND // "Proxy Mode" checkbox
	// Scan bar (shown only when Hosts tab is active)
	hwndTargetLabel     HWND // "Target:" static label
	hwndTarget          HWND
	hwndDetect          HWND // "⟲" detect local subnet button
	hwndScan            HWND // toggle: "Scan" at rest, "Stop" while scanning
	hwndActiveOnly      HWND // "Active only" filter checkbox
	// Content panes
	hwndList            HWND
	hwndListPlaceholder HWND // empty-state overlay for Scanner tab
	hwndMDNSPlaceholder HWND // empty-state overlay for mDNS tab
	hwndSSDPPlaceholder HWND // empty-state overlay for SSDP tab
	hwndWSDPlaceholder  HWND // empty-state overlay for WSD tab
	hwndDHCPPlaceholder HWND // empty-state overlay for DHCP tab
	hwndListMDNS   HWND // mDNS tab
	hwndListSSDP   HWND // SSDP tab
	hwndListWSD    HWND // WS-Discovery tab
	hwndListDHCP   HWND // DHCP tab
	hwndListNetwork HWND // Network tab — live broadcast stats
	hwndListHealth        HWND // Scan Report tab
	hwndHealthPlaceholder HWND // empty-state overlay for Scan Report tab
	hwndListServices       HWND // Services tab
	hwndServicesPlaceholder HWND // empty-state overlay for Services tab
	scanEverCompleted     bool // true once the first scan has completed
	hwndTabCtrl      HWND
	hwndScanStatus   HWND // inline scan status label on the scan bar
	hwndStatus       HWND // bottom status bar (2 parts: listener | service)
	// Find bar (Ctrl+F): a floating edit + dismiss button, one instance shared
	// across all tabs.  Both are direct children of the main window.
	hwndSearchEdit  HWND
	hwndSearchClose HWND
)

// ---------------------------------------------------------------------------
// Scan state
// ---------------------------------------------------------------------------

var (
	scanCancel context.CancelFunc
	scanMu     sync.Mutex

	// Cross-thread result queue: scan goroutine appends, UI thread reads.
	pendingResults []scan.Result
	pendingMu      sync.Mutex
	liveCount      int
	lastStats      scan.ScanStats // populated after scan completes
	scanStartTime  time.Time      // set when scan begins, used for duration metric
	listHasHosts   bool           // true once ≥1 alive host found in current/last scan
	isScanning     bool           // true while a scan is in progress (UI thread only)
	activeTab      int            // current tab index; tracked for state persistence
	scanGeneration uint64         // incremented on each new scan; guards against stale WM_SCAN_COMPLETE

	// ipRowMap maps IP string → row index in hwndList.
	// Written on the UI thread (startScan), read on the UI thread (WM_SCAN_RESULT).
	ipRowMap    map[string]int32
	// rowResultMap maps ListView row index → scan Result, for right-click menus.
	rowResultMap map[int32]scan.Result
	// allScanResults holds every result received in the current scan (by IP),
	// including dead hosts. Used by applyActiveFilter to restore rows when
	// the "Active only" filter is toggled off.
	allScanResults map[string]scan.Result
	// activeOnlyFilter reflects the state of the "Active only" checkbox.
	activeOnlyFilter bool

	// tabSearchFilter stores the Ctrl+F search string for each tab (indexed
	// by tab number 0–7).  An empty string means no filter is active.
	tabSearchFilter [8]string

	// dhcpAllEvents is the backing store for DHCP filter repopulation.
	// Every DHCP event is appended here when received, before being rendered.
	dhcpAllEvents []scan.DHCPEvent
)

// ---------------------------------------------------------------------------
// Background broadcast listener state
// ---------------------------------------------------------------------------

var (
	// bcastServiceActive is true after we have sent "bcast-start" to the
	// current service connection and before it disconnects or we stop it.
	// Read/written only on the UI thread.
	bcastServiceActive bool
	bcastCount         int // total services received since app start
	bcastMDNS      int // mDNS entries
	bcastSSDP      int // SSDP entries
	bcastWSD       int // WSD entries
	bcastDHCP      int // DHCP entries
	pendingBcast   []bcastEntry
	pendingBcastMu sync.Mutex

	// Listener status messages: probe goroutine appends, UI thread reads via WM_LISTENER_STATUS.
	pendingListenerMsgs   []string
	pendingListenerMsgsMu sync.Mutex

	// DHCP event queue: service goroutine appends, UI thread reads via WM_DHCP_EVENT.
	pendingDHCP   []scan.DHCPEvent
	pendingDHCPMu sync.Mutex

	// Host enrichment queue: background goroutines append NetBIOS names / ARP MACs
	// for existing Hosts rows; UI thread processes via WM_HOST_ENRICH.
	pendingEnriches []enrichEvent
	pendingEnrichMu sync.Mutex

	// pendingResolveHosts carries the results of background hostname→IP
	// resolution back to the UI thread via WM_RESOLVE_HOST.
	pendingResolveHosts   []resolveHostResult
	pendingResolveHostsMu sync.Mutex

	// hostRegistry accumulates data about every host seen across all scans
	// and broadcast events. Written and read only on the UI thread.
	hostRegistry map[string]*hostEntry
)

// ensureHostEntry returns the hostEntry for ip, creating it if needed.
func ensureHostEntry(ip string) *hostEntry {
	if hostRegistry == nil {
		hostRegistry = make(map[string]*hostEntry)
	}
	e, ok := hostRegistry[ip]
	if !ok {
		e = &hostEntry{IP: ip, FirstSeen: time.Now()}
		hostRegistry[ip] = e
	}
	return e
}

// allHostIPs returns all known IPs from the registry, sorted numerically.
func allHostIPs() []string {
	ips := make([]string, 0, len(hostRegistry))
	for ip := range hostRegistry {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		ai := net.ParseIP(ips[i]).To4()
		aj := net.ParseIP(ips[j]).To4()
		if ai == nil || aj == nil {
			return ips[i] < ips[j]
		}
		for k := 0; k < 4; k++ {
			if ai[k] != aj[k] {
				return ai[k] < aj[k]
			}
		}
		return false
	})
	return ips
}

// enrichEvent carries a NetBIOS name and/or MAC for an existing Hosts row.
type enrichEvent struct {
	ip      string
	netbios string
	mac     net.HardwareAddr
}

// hostEntry is the persistent record for a host seen across any source.
type hostEntry struct {
	IP           string
	FirstSeen    time.Time
	LastSeen     time.Time
	Result       scan.Result      // latest scan data (zero-value for broadcast-only hosts)
	HasResult    bool              // true once a scan result has been recorded
	DHCPEvents   []scan.DHCPEvent // all DHCP packets observed for this IP
	ExtraServices []scan.ServiceInfo // broadcast services not yet in Result.Services
	// ProbeResults accumulates on-demand probe results for the session.
	// Persists across host-detail dialog close/reopen until the host is forgotten.
	ProbeResults []scan.ProbeResult
}

type bcastEntry struct {
	ip  string
	svc scan.ServiceInfo
}

// resolveHostResult carries the outcome of a background hostname→IP lookup
// back to the UI thread via WM_RESOLVE_HOST.
type resolveHostResult struct {
	hostname string            // original hostname the user typed
	ips      []string          // resolved addresses (empty on failure)
	ptrNames map[string]string // IP → PTR hostname; may be absent for some IPs
	err      string            // non-empty on lookup failure
}

// startBroadcastListener delegates mDNS/SSDP/WSD listening to the service.
// The service probes multicast support, streams back events, and reports
// listener status via BcastReady messages routed to WM_LISTENER_STATUS.
func startBroadcastListener(hwnd HWND) {
	if bcastServiceActive {
		return
	}
	if startBroadcastListenerViaService(appConfig.Scan.BroadcastListen) {
		bcastServiceActive = true
	}
}

func stopBroadcastListener() {
	if !bcastServiceActive {
		return
	}
	stopBroadcastListenerViaService()
	bcastServiceActive = false
}

// kickNetBIOSProbe asks the service to query the NetBIOS name for ip.
// The result arrives as a WM_HOST_ENRICH enrichment event.
func kickNetBIOSProbe(ip string) {
	sendNetBIOSViaService(ip)
}

// startARPPoll asks the service to begin periodic ARP-table reads.
// Results stream back as WM_HOST_ENRICH enrichment events.
func startARPPoll(_ HWND) {
	startARPPollViaService()
}

func stopARPPoll() {
	stopARPPollViaService()
}

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

const (
	toolbarH  = 38 // legacy constant (kept for dialogs that reference it)
	optionsBarH = 32 // global options bar at very top (Elevate Sensor + Proxy Mode)
	elevBarH    = optionsBarH // alias kept so WM_SIZE calculations compile unchanged
	scanBarH  = 36 // scan controls bar (shown only on Hosts tab)
	tabCtrlH  = 26 // height of the tab row
)

// ---------------------------------------------------------------------------
// WndProc
// ---------------------------------------------------------------------------

var wndProcCallback = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_DPICHANGED:
		// wParam HIWORD = new DPI. lParam = suggested window rect at new DPI.
		newDPI := uint32(hiword(wParam))
		if newDPI == 0 {
			newDPI = 96
		}
		currentDPI = newDPI
		// Recreate the font at the new DPI and push it to all children.
		if appFont != 0 {
			deleteObject(uintptr(appFont))
		}
		appFont = createUIFont(currentDPI)
		setFontAllChildren(HWND(hwnd), appFont)
		// Move the window to the rect Windows suggests (avoids text blurriness).
		rect := (*RECT)(unsafe.Pointer(lParam)) //nolint:govet
		setWindowPos(HWND(hwnd), 0, rect.Left, rect.Top,
			rect.Right-rect.Left, rect.Bottom-rect.Top,
			SWP_NOZORDER|SWP_NOACTIVATE)
		return 0

	case WM_CTLCOLORSTATIC:
		// Empty-state overlay labels get gray text on the white listview background.
		if isEmptyStateOverlay(HWND(lParam)) {
			return applyEmptyStateColor(wParam)
		}
		// Any other STATIC on the main window (e.g. "Target:" label) should
		// blend with the COLOR_WINDOW background, not get the default
		// COLOR_BTNFACE gray that defWindowProc would return.
		setBkMode(wParam, TRANSPARENT)
		return uintptr(getSysColorBrush(COLOR_WINDOW))

	case WM_SERVICE_UP:
		// Update the service-state part of the status bar.
		setStatusPart(statusPartService, statusForService())
		if serviceElevated {
			enableWindow(hwndServiceBtn, false)
			// Start passive DHCP capture in the elevated service.
			startDHCPCapture(HWND(hwnd))
			// Listener now includes DHCP via the elevated service.
			setStatusPart(statusPartListener, "Listening (mDNS · SSDP · WSD · DHCP)")
		}
		// Start broadcast listener via the newly connected service (if not proxy mode).
		if !proxyEnabled {
			startBroadcastListener(HWND(hwnd))
		}
		updateNetworkTab()
		return 0

	case WM_SERVICE_DOWN:
		// Update the service-state part of the status bar.
		setStatusPart(statusPartService, statusForService())
		// Broadcast listener ran inside the service — reset state so it will
		// restart automatically when a new service connection is established.
		bcastServiceActive = false
		if !proxyEnabled {
			setStatusPart(statusPartListener, "")
		}
		// If the service dropped while a scan was in progress, reset scan state
		// so the UI doesn't remain stuck showing "Scanning…" with a Stop button.
		if isScanning {
			scanMu.Lock()
			scanCancel = nil
			scanMu.Unlock()
			isScanning = false
			setWindowText(hwndScan, "Scan")
			setWindowText(hwndScanStatus, "Service disconnected")
		}
		return 0

	case WM_LISTENER_STATUS:
		pendingListenerMsgsMu.Lock()
		errMsg := ""
		if int(wParam) < len(pendingListenerMsgs) {
			errMsg = pendingListenerMsgs[int(wParam)]
		}
		pendingListenerMsgsMu.Unlock()
		if errMsg != "" {
			setStatusPart(statusPartListener, "Not listening — bind error: "+errMsg)
		} else {
			setStatusPart(statusPartListener, "Listening (mDNS · SSDP · WSD)")
		}
		return 0

	case WM_HOST_REFRESH:
		// Posted by UI code after mutating hostRegistry (e.g. forget host).
		// No payload — just rebuild the hosts listview from allScanResults.
		applyActiveFilter()
		return 0

	case WM_DHCP_EVENT:
		pendingDHCPMu.Lock()
		var evt scan.DHCPEvent
		if int(wParam) < len(pendingDHCP) {
			evt = pendingDHCP[int(wParam)]
		}
		pendingDHCPMu.Unlock()
		// Persist every DHCP event so repopulateDHCP can replay them with a filter.
		dhcpAllEvents = append(dhcpAllEvents, evt)
		// Respect any active search filter: skip rendering if the event doesn't match.
		if f := strings.ToLower(tabSearchFilter[5]); f == "" || dhcpEventMatchesFilter(evt, f) {
			listViewAddDHCPRow(hwndListDHCP, evt)
		}
		if bcastDHCP == 0 {
			showWindow(hwndDHCPPlaceholder, SW_HIDE)
		}
		bcastDHCP++
		// Cross-enrich the Hosts tab: if the DHCP IP matches a scanned row,
		// fill in hostname (opt 12) and/or MAC (chaddr) if currently blank.
		enrichIP := evt.OfferedIP
		if enrichIP == "" || enrichIP == "0.0.0.0" {
			enrichIP = evt.ClientIP
		}
		if enrichIP != "" && enrichIP != "0.0.0.0" {
			// Registry: store DHCP event regardless of whether IP is in Hosts tab.
			en := ensureHostEntry(enrichIP)
			en.LastSeen = time.Now()
			en.DHCPEvents = append(en.DHCPEvents, evt)
			if _, inHosts := ipRowMap[enrichIP]; inHosts {
				var parsedMAC net.HardwareAddr
				if evt.ClientMAC != "" {
					parsedMAC, _ = net.ParseMAC(evt.ClientMAC)
				}
				if evt.Hostname != "" || parsedMAC != nil {
					pendingEnrichMu.Lock()
					idx := len(pendingEnriches)
					pendingEnriches = append(pendingEnriches, enrichEvent{
						ip:      enrichIP,
						netbios: evt.Hostname,
						mac:     parsedMAC,
					})
					pendingEnrichMu.Unlock()
					postMessage(HWND(hwnd), WM_HOST_ENRICH, uintptr(idx), 0)
				}
				if evt.Hostname == "" {
					kickNetBIOSProbe(enrichIP)
				}
			}
		}
		return 0

	case WM_CREATE:
		// proxyEnabled is initialised before the window is created (in Run());
		// it defaults to true when a SOCKS5 address is saved in settings.
		createControls(HWND(hwnd))
		// Restore persisted column state (widths, visibility, sort indicators).
		if stateDirPath != "" && len(appState.Columns) > 0 {
			restoreAllColumnStates(appState.Columns)
		}
		// Restore last active view by stable name.
		if stateDirPath != "" && appState.ActiveView != "" {
			if idx, ok := viewToTabIndex[appState.ActiveView]; ok && idx > 0 {
				sendMessage(hwndTabCtrl, TCM_SETCURSEL, uintptr(idx), 0)
				activateTab(HWND(hwnd), idx)
			}
		}
		// 30-second timer for broadcast host decay colours and "Last Seen" update.
		setTimer(HWND(hwnd), IDT_DECAY, 30000, 0)
		if noConfigFile {
			postMessage(HWND(hwnd), WM_FIRST_RUN, 0, 0)
		}
		if proxyEnabled {
			setStatusPart(statusPartListener, "Not listening (proxy mode)")
		}
		// Broadcast listener is started in WM_SERVICE_UP once the service connects.
		// Start the sensor service immediately (user-level, no UAC).
		go startService(HWND(hwnd))
		return 0

	case WM_SIZE:
		resizeControls(HWND(hwnd), lParam)
		return 0

	case WM_NOTIFY:
		// lParam points to Windows-managed memory; the GC will not move it.
		// go vet flags uintptr→unsafe.Pointer but this is a known false positive
		// for syscall.NewCallback parameters that carry Windows system pointers.
		hdr := (*NMHDR)(unsafe.Pointer(lParam)) //nolint:govet
		if hdr.IdFrom == IDC_TABS && hdr.Code == TCN_SELCHANGE {
			tab := int32(sendMessage(hwndTabCtrl, TCM_GETCURSEL, 0, 0))
			activeTab = int(tab)
			activateTab(HWND(hwnd), tab)
		}
		// Double-click on host list → host detail dialog.
		if hdr.IdFrom == IDC_LIST && hdr.Code == NM_DBLCLK {
			row := int32(sendMessage(hwndList, LVM_GETNEXTITEM, ^uintptr(0), LVNI_SELECTED))
			if row >= 0 {
				ip := listViewGetCellText(hwndList, row, colIP)
				if ip != "" {
					showHostDetailDialog(HWND(hwnd), ip)
				}
			}
			return 0
		}
		// Double-click on mDNS / SSDP / WSD lists → host detail dialog (col 0 = IP).
		if (hdr.IdFrom == IDC_LIST_MDNS || hdr.IdFrom == IDC_LIST_SSDP || hdr.IdFrom == IDC_LIST_WSD) &&
			hdr.Code == NM_DBLCLK {
			var hwndSrc HWND
			switch hdr.IdFrom {
			case IDC_LIST_MDNS:
				hwndSrc = hwndListMDNS
			case IDC_LIST_SSDP:
				hwndSrc = hwndListSSDP
			case IDC_LIST_WSD:
				hwndSrc = hwndListWSD
			}
			row := int32(sendMessage(hwndSrc, LVM_GETNEXTITEM, ^uintptr(0), LVNI_SELECTED))
			if row >= 0 {
				ip := listViewGetCellText(hwndSrc, row, 0)
				if ip != "" {
					showHostDetailDialog(HWND(hwnd), ip)
				}
			}
			return 0
		}
		// Double-click on DHCP list → host detail dialog.
		// Prefer Offered IP (col 6), fall back to Client IP (col 4).
		if hdr.IdFrom == IDC_LIST_DHCP && hdr.Code == NM_DBLCLK {
			row := int32(sendMessage(hwndListDHCP, LVM_GETNEXTITEM, ^uintptr(0), LVNI_SELECTED))
			if row >= 0 {
				ip := listViewGetCellText(hwndListDHCP, row, 6) // Offered IP
				if ip == "" || ip == "—" {
					ip = listViewGetCellText(hwndListDHCP, row, 4) // Client IP
				}
				if ip != "" && ip != "—" {
					showHostDetailDialog(HWND(hwnd), ip)
				}
			}
			return 0
		}
		// Right-click on any managed listview header → column context menu.
		// Handles tabs where header NM_RCLICK is reflected to the main window
		// rather than being intercepted by the listview's subclass WndProc.
		if hdr.Code == NM_RCLICK {
			nm := (*NMMOUSE)(unsafe.Pointer(lParam)) //nolint:govet
			lvHwnd := getParent(HWND(hdr.HwndFrom))
			if s, ok := lvManagedStates[lvHwnd]; ok && s.colVis != nil {
				showColumnHeaderMenu(HWND(hwnd), lvHwnd, s, int32(nm.DwItemSpec), getCursorPos())
				return 0
			}
		}
		// Right-click on host list → context menu.
		if hdr.IdFrom == IDC_LIST && hdr.Code == NM_RCLICK {
			pt := getCursorPos()
			// Convert screen coords to list-view client coords for hit-test.
			cpt := screenToClient(hwndList, pt)
			htInfo := LVHITTESTINFO{Pt: cpt}
			row := int32(sendMessage(hwndList, LVM_HITTEST, 0, uintptr(unsafe.Pointer(&htInfo))))
			if row >= 0 {
				if r, ok := rowResultMap[row]; ok {
					showHostContextMenu(HWND(hwnd), r, pt.X, pt.Y)
				}
			}
			return 0
		}
		// Double-click on Services list → service detail dialog.
		if hdr.IdFrom == IDC_LIST_SERVICES && hdr.Code == NM_DBLCLK {
			row := int32(sendMessage(hwndListServices, LVM_GETNEXTITEM, ^uintptr(0), LVNI_SELECTED))
			if row >= 0 {
				if e, ok := svcTabRowEntry[row]; ok {
					showServiceDetailDialog(HWND(hwnd), e)
				}
			}
			return 0
		}
		// Right-click on mDNS / SSDP / WSD / DHCP / Services lists → copy menu.
		if (hdr.IdFrom == IDC_LIST_MDNS || hdr.IdFrom == IDC_LIST_SSDP ||
			hdr.IdFrom == IDC_LIST_WSD || hdr.IdFrom == IDC_LIST_DHCP ||
			hdr.IdFrom == IDC_LIST_SERVICES) && hdr.Code == NM_RCLICK {
			hwndSrc, numCols, headers := listViewInfoFor(hdr.IdFrom)
			if hwndSrc == 0 {
				return 0
			}
			pt := getCursorPos()
			htInfo := LVHITTESTINFO{Pt: screenToClient(hwndSrc, pt)}
			sendMessage(hwndSrc, LVM_HITTEST, 0, uintptr(unsafe.Pointer(&htInfo)))
			// Use selected rows; fall back to the hovered row if nothing is selected.
			rows := listViewGetSelectedRows(hwndSrc)
			if len(rows) == 0 && htInfo.IItem >= 0 {
				rows = []int32{htInfo.IItem}
			}
			menu := createPopupMenu()
			if len(rows) > 0 {
				appendCopyAsSubmenu(menu)
			}
			hasRaw := hdr.IdFrom != IDC_LIST_DHCP
			if hasRaw && htInfo.IItem >= 0 {
				if len(rows) > 0 {
					appendMenu(menu, MF_SEPARATOR, 0, "")
				}
				appendMenu(menu, MF_STRING, IDM_BCAST_COPY_RAW, "Copy raw data")
			}
			cmd := trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, pt.X, pt.Y, HWND(hwnd))
			destroyMenu(menu)
			if !handleCopyAsCmd(HWND(hwnd), hwndSrc, cmd, rows, numCols, headers, nil) {
				switch cmd {
				case IDM_BCAST_COPY_RAW:
					switch hdr.IdFrom {
					case IDC_LIST_MDNS:
						copyToClipboard(HWND(hwnd), mdnsRawClipboardText(hwndSrc, rows))
					case IDC_LIST_WSD:
						seen := map[string]bool{}
						var parts []string
						for _, r := range rows {
							ip := listViewGetCellText(hwndSrc, r, 0)
							if !seen[ip] {
								seen[ip] = true
								parts = append(parts, getWSDRawText(ip))
							}
						}
						copyToClipboard(HWND(hwnd), strings.Join(parts, "\n---\n"))
					case IDC_LIST_SSDP:
						seen := map[string]bool{}
						var parts []string
						for _, r := range rows {
							ip := listViewGetCellText(hwndSrc, r, 0)
							if !seen[ip] {
								seen[ip] = true
								parts = append(parts, getSSDPRawText(ip))
							}
						}
						copyToClipboard(HWND(hwnd), strings.Join(parts, "\n---\n"))
					}
				}
			}
			return 0
		}
		// Ctrl+A / Ctrl+C in any ListView.
		if hdr.Code == LVN_KEYDOWN {
			kd := (*NMLVKEYDOWN)(unsafe.Pointer(lParam))
			if getKeyState(VK_CONTROL) < 0 {
				switch kd.WVKey {
				case VK_KEY_A:
					listViewSelectAll(HWND(hdr.HwndFrom))
					return 0
				case VK_KEY_C:
					hw, nc, hdrs := listViewInfoFor(hdr.IdFrom)
					if hw != 0 {
						rows := listViewGetSelectedRows(hw)
						handleCopyAsCmd(HWND(hwnd), hw, IDM_COPY_AS_TSV, rows, nc, hdrs, nil)
					}
					return 0
				case VK_KEY_F:
					showFindBar(HWND(hwnd))
					return 0
				}
			}
		}
		// Custom draw: alternating row backgrounds, dim dead rows, colour ●/✕ status dot.
		if hdr.IdFrom == IDC_LIST && hdr.Code == NM_CUSTOMDRAW {
			cd := (*NMLVCUSTOMDRAW)(unsafe.Pointer(lParam)) //nolint:govet
			switch cd.DwDrawStage {
			case CDDS_PREPAINT:
				return CDRF_NOTIFYITEMDRAW
			case CDDS_ITEMPREPAINT:
				row := int32(cd.DwItemSpec)
				cd.ClrTextBk = lvRowBg(row)
				// Request per-subitem notifications to colour the status column.
				return CDRF_NOTIFYITEMDRAW | CDRF_NEWFONT
			case CDDS_SUBITEM | CDDS_ITEMPREPAINT:
				// For the status column (col 0) Win32 ignores LVCFMT_CENTER, so we
				// draw the symbol centred ourselves and suppress default rendering.
				if int32(cd.ISubItem) == colStatus {
					row := int32(cd.DwItemSpec)
					// Choose symbol and colour.
					text, color := "…", uint32(0x00AAAAAA)
					if r, ok := rowResultMap[row]; ok {
						if r.Alive {
							text, color = "●", 0x0028A028
						} else {
							text, color = "✕", 0x001E1EC8
						}
					}
					// Alternating row background (match CDDS_ITEMPREPAINT logic).
					bg := createSolidBrush(lvRowBg(row))
					rc := cd.Rc
					fillRect(cd.Hdc, &rc, bg)
					deleteObject(uintptr(bg))
					setBkMode(cd.Hdc, TRANSPARENT)
					setTextColor(cd.Hdc, color)
					drawText(cd.Hdc, text, &rc, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX)
					return CDRF_SKIPDEFAULT
				}
				return CDRF_NEWFONT
			}
		}
		// Custom draw: broadcast tab decay colours (mDNS / SSDP / WSD).
		if (hdr.IdFrom == IDC_LIST_MDNS || hdr.IdFrom == IDC_LIST_SSDP || hdr.IdFrom == IDC_LIST_WSD) &&
			hdr.Code == NM_CUSTOMDRAW {
			cd := (*NMLVCUSTOMDRAW)(unsafe.Pointer(lParam)) //nolint:govet
			switch cd.DwDrawStage {
			case CDDS_PREPAINT:
				return CDRF_NOTIFYITEMDRAW
			case CDDS_ITEMPREPAINT:
				hwndSrc, _, _ := listViewInfoFor(hdr.IdFrom)
				row := int32(cd.DwItemSpec)
				ip := listViewGetCellText(hwndSrc, row, 0)
				cd.ClrTextBk = bcastDecayBg(ip, row)
				return CDRF_NEWFONT
			}
		}
		return 0

	case WM_TIMER:
		if wParam == IDT_DECAY {
			refreshBcastLastSeenCols()
		}
		return 0

	case WM_COMMAND:
		switch loword(wParam) {
		case IDC_SERVICE_BTN:
			// Spawn elevated service via UAC. Existing service is stopped first.
			go elevateService(HWND(hwnd))
		case IDC_PROXY_CHECK:
			nowChecked := sendMessage(hwndProxyCheck, BM_GETCHECK, 0, 0) == BST_CHECKED
			if nowChecked {
				// Test connectivity to the proxy before enabling.
				setWindowText(hwndScanStatus, "Testing proxy connection…")
				enableWindow(hwndProxyCheck, false)
				proxyAddr := appConfig.Scan.SOCKSProxy
				if !testProxyViaService(proxyAddr) {
					// Service not running — fail immediately.
					pendingProxyErrMu.Lock()
					idx := len(pendingProxyErrors)
					pendingProxyErrors = append(pendingProxyErrors, "sensor service is not running")
					pendingProxyErrMu.Unlock()
					postMessage(HWND(hwnd), WM_PROXY_FAIL, uintptr(idx), 0)
				}
			} else {
				applyProxyMode(HWND(hwnd), false)
			}
		case IDC_DETECT:
			detectSubnet(HWND(hwnd))
		case IDC_ACTIVE_ONLY:
			activeOnlyFilter = sendMessage(hwndActiveOnly, BM_GETCHECK, 0, 0) == BST_CHECKED
			applyActiveFilter()
		case IDC_SCAN:
			if isScanning {
				stopScan()
				// Reset UI immediately — don't wait for WM_SCAN_COMPLETE,
				// which may be delayed (especially for service scans).
				isScanning = false
				setWindowText(hwndScan, "Scan")
		setWindowText(hwndScanStatus, "Stopped")
			} else {
				startScan(HWND(hwnd))
			}
		case IDC_SEARCH_CLOSE:
			hideFindBar()
		case IDC_SEARCH_EDIT:
			if hiword(wParam) == EN_CHANGE {
				tab := int32(sendMessage(hwndTabCtrl, TCM_GETCURSEL, 0, 0))
				if tab >= 0 && tab < int32(len(tabSearchFilter)) {
					tabSearchFilter[tab] = getWindowText(hwndSearchEdit)
					applyTabFilter()
				}
			}
		case IDM_FILE_EXIT:
			stopScan()
			postQuitMessage(0)
		case IDM_FILE_EXPORT_JSON:
			exportAllHosts(HWND(hwnd), "json")
		case IDM_FILE_EXPORT_CSV:
			exportAllHosts(HWND(hwnd), "csv")
		case IDM_FILE_EXPORT_SCAN_JSON:
			exportResults(HWND(hwnd), "json")
		case IDM_FILE_EXPORT_SCAN_CSV:
			exportResults(HWND(hwnd), "csv")
		case IDM_OPT_SETTINGS:
			showSettingsDialog(HWND(hwnd))
		case IDM_OPT_DATABASES:
			showDatabasesDialog(HWND(hwnd))
		case IDM_HOSTS_VIEW_HOST:
			showPickHostDialog(HWND(hwnd))
		case IDM_SERVICES_VIEW_ALL:
			showAllServicesDialog(HWND(hwnd))
		case IDM_HELP_FAQ:
			showFAQDialog(HWND(hwnd))
		case IDM_HELP_CONN_HANDLERS:
			showConnHandlersDialog(HWND(hwnd))
		case IDM_HELP_VERSION:
			showVersionDialog(HWND(hwnd))
		case IDM_HELP_ABOUT:
			showAboutDialog(HWND(hwnd))
		case IDM_HELP_CRASHLOG:
			path := crashLogPath()
			if _, err := os.Stat(path); os.IsNotExist(err) {
				messageBox(HWND(hwnd), "No crash log found.\n\nIf the app closes unexpectedly, a log will be written to:\n"+path, "Crash Log", 0)
			} else {
				shellExecute(HWND(hwnd), "open", "notepad.exe", path, "", SW_SHOW)
			}
		}
		return 0

	case WM_FIRST_RUN:
		// No config file was found at startup.  Ask where (if anywhere) to
		// save one, then write the current defaults there.  Settings can be
		// adjusted afterwards via Options → Settings.
		appDataPath := config.ConfigPath()
		exePath := config.ExeLocalPath()
		savePath := showConfigLocationDialog(HWND(hwnd), appDataPath, exePath)
		if savePath != "" {
			_ = config.SaveTo(appConfig, savePath)
		}
		return 0

	case WM_PROXY_VALID:
		// Proxy connectivity test succeeded — apply proxy mode.
		enableWindow(hwndProxyCheck, true)
		applyProxyMode(HWND(hwnd), true)
		return 0

	case WM_PROXY_FAIL:
		// Proxy connectivity test failed — uncheck and show error.
		pendingProxyErrMu.Lock()
		errMsg := ""
		if int(wParam) < len(pendingProxyErrors) {
			errMsg = pendingProxyErrors[int(wParam)]
		}
		pendingProxyErrMu.Unlock()
		enableWindow(hwndProxyCheck, true)
		sendMessage(hwndProxyCheck, BM_SETCHECK, BST_UNCHECKED, 0)
		setWindowText(hwndScanStatus, "Ready to scan")
		messageBox(HWND(hwnd), "Cannot reach proxy:\n"+errMsg, "Proxy Mode", MB_ICONERROR)
		return 0

	case WM_HOST_RESCAN:
		// Triggered by the Host detail dialog's "Scan" button. The dialog has
		// already written the target IP into hwndTarget. Run a targeted rescan
		// without clearing the Scanner listview.
		rescanSingleHost(HWND(hwnd), getWindowText(hwndTarget))
		return 0

	case WM_BCAST_SVC:
		pendingBcastMu.Lock()
		var e bcastEntry
		if int(wParam) < len(pendingBcast) {
			e = pendingBcast[int(wParam)]
		}
		pendingBcastMu.Unlock()
		if e.ip != "" {
			switch e.svc.Source {
			case "ssdp":
				listViewAddSSDPRow(hwndListSSDP, e.ip, e.svc)
				if bcastSSDP == 0 {
					showWindow(hwndSSDPPlaceholder, SW_HIDE)
				}
				bcastSSDP++
			case "wsd":
				listViewAddWSDRow(hwndListWSD, e.ip, e.svc)
				if bcastWSD == 0 {
					showWindow(hwndWSDPlaceholder, SW_HIDE)
				}
				bcastWSD++
			default:
				listViewAddMDNSRow(hwndListMDNS, e.ip, e.svc)
				if bcastMDNS == 0 {
					showWindow(hwndMDNSPlaceholder, SW_HIDE)
				}
				bcastMDNS++
			}
			bcastCount++
			updateNetworkTab()
			// Registry: append service to the host's ExtraServices list.
			en := ensureHostEntry(e.ip)
			en.LastSeen = time.Now()
			en.ExtraServices = append(en.ExtraServices, e.svc)
		}
		return 0

	case WM_SCAN_RESULT:
		// Accept results from the current scan or from a host-dialog rescan.
		// Stale results from superseded scans are discarded.
		scanGen := uint64(lParam)
		isHostRescan := scanGen == hostRescanScanID
		if !isHostRescan && scanGen != scanGeneration {
			return 0
		}
		pendingMu.Lock()
		idx := int(wParam)
		if idx >= len(pendingResults) {
			pendingMu.Unlock()
			return 0
		}
		r := pendingResults[idx]
		pendingMu.Unlock()

		ipStr := r.IP.String()
		// Keep the full result set so applyActiveFilter can restore dead rows.
		allScanResults[ipStr] = r
		// Always update the registry with the latest scan data.
		{
			en := ensureHostEntry(ipStr)
			en.LastSeen = time.Now()
			en.Result = r
			en.HasResult = true
		}
		if row, found := ipRowMap[ipStr]; found {
			listViewUpdateRow(hwndList, row, r)
			rowResultMap[row] = r
			if r.Alive {
				if !isHostRescan {
					liveCount++
				}
				if !listHasHosts {
					listHasHosts = true
					showWindow(hwndListPlaceholder, SW_HIDE)
				}
				if !isHostRescan {
					setWindowText(hwndScanStatus, fmt.Sprintf("Scanning\u2026 \u00b7 %d found", liveCount))
				}
			} else if activeOnlyFilter {
				// Filter is active: immediately remove dead row from the display.
				listViewDeleteRowAndFixMaps(row)
			}
		} else if r.Alive {
			// Broadcast-only or out-of-range host.
			row := listViewInsertPendingRow(hwndList, ipStr)
			ipRowMap[ipStr] = row
			listViewUpdateRow(hwndList, row, r)
			rowResultMap[row] = r
			if !isHostRescan {
				liveCount++
			}
			if !listHasHosts {
				listHasHosts = true
				showWindow(hwndListPlaceholder, SW_HIDE)
			}
			if !isHostRescan {
				setWindowText(hwndScanStatus, fmt.Sprintf("Scanning\u2026 \u00b7 %d found", liveCount))
			}
			// Broadcast-only hosts skip per-host probing; request enrichment.
			if r.Hostname == "" && r.NetBIOS == "" {
				kickNetBIOSProbe(ipStr)
			}
		}

		// Feed PortServices into the Services tab.
		if len(r.PortServices) > 0 {
			servicesTabAddResult(r)
			if len(svcTabData) > 0 {
				showWindow(hwndServicesPlaceholder, SW_HIDE)
			}
		}

		// Mirror any services to the appropriate broadcast tab.
		for _, svc := range r.Services {
			switch svc.Source {
			case "ssdp":
				listViewAddSSDPRow(hwndListSSDP, ipStr, svc)
				if bcastSSDP == 0 {
					showWindow(hwndSSDPPlaceholder, SW_HIDE)
				}
				bcastSSDP++
			case "wsd":
				listViewAddWSDRow(hwndListWSD, ipStr, svc)
				if bcastWSD == 0 {
					showWindow(hwndWSDPlaceholder, SW_HIDE)
				}
				bcastWSD++
			default:
				listViewAddMDNSRow(hwndListMDNS, ipStr, svc)
				if bcastMDNS == 0 {
					showWindow(hwndMDNSPlaceholder, SW_HIDE)
				}
				bcastMDNS++
			}
		}
		return 0

	case WM_SCAN_COMPLETE:
		// Discard completions from a superseded scan (rapid Stop → Scan race).
		if uint64(wParam) != scanGeneration {
			return 0
		}
		scanMu.Lock()
		scanCancel = nil
		scanMu.Unlock()
		scanDuration := time.Since(scanStartTime)
		scanEverCompleted = true
		isScanning = false
		setWindowText(hwndScan, "Scan")
		setWindowText(hwndScanStatus, fmt.Sprintf("%d hosts \u00b7 %.1fs", liveCount, scanDuration.Seconds()))
		if !listHasHosts {
			setWindowText(hwndListPlaceholder, "No hosts found — try widening the target range")
			showWindow(hwndListPlaceholder, SW_SHOW)
		}
		// Refresh health tab text.
		pendingMu.Lock()
		stats := lastStats
		pendingMu.Unlock()
		updateHealthTab(stats, scanDuration)
		startARPPoll(HWND(hwnd))
		return 0

	case WM_HOST_ENRICH:
		pendingEnrichMu.Lock()
		var e enrichEvent
		if int(wParam) < len(pendingEnriches) {
			e = pendingEnriches[int(wParam)]
		}
		pendingEnrichMu.Unlock()
		if e.ip == "" {
			return 0
		}
		row, ok := ipRowMap[e.ip]
		if !ok {
			return 0
		}
		// Also update the registry.
		en := ensureHostEntry(e.ip)
		en.LastSeen = time.Now()
		if e.netbios != "" {
			cur := listViewGetCellText(hwndList, row, colHost)
			if cur == "\u2014" || cur == "" {
				setSubItem(hwndList, row, colHost, e.netbios+" (NetBIOS)")
				if r, ok2 := rowResultMap[row]; ok2 {
					r.NetBIOS = e.netbios
					rowResultMap[row] = r
				}
			}
			if en.Result.NetBIOS == "" {
				en.Result.NetBIOS = e.netbios
			}
		}
		if e.mac != nil {
			cur := listViewGetCellText(hwndList, row, colMAC)
			if cur == "\u2014" || cur == "" {
				setSubItem(hwndList, row, colMAC, e.mac.String())
				if vendor := scan.LookupVendor(e.mac); vendor != "" {
					if vc := listViewGetCellText(hwndList, row, colVendor); vc == "\u2014" || vc == "" {
						setSubItem(hwndList, row, colVendor, vendor)
					}
				}
				if r, ok2 := rowResultMap[row]; ok2 {
					r.MAC = e.mac
					if r.Vendor == "" {
						r.Vendor = scan.LookupVendor(e.mac)
					}
					rowResultMap[row] = r
				}
			}
			if en.Result.MAC == nil {
				en.Result.MAC = e.mac
				if en.Result.Vendor == "" {
					en.Result.Vendor = scan.LookupVendor(e.mac)
				}
			}
		}
		return 0

	case WM_DESTROY:
		// Persist UI state before tearing down.
		if stateDirPath != "" {
			var ws config.WindowState
			if wp, ok := getWindowPlacement(HWND(hwnd)); ok {
				r := wp.RcNormalPosition
				winState := "normal"
				if wp.ShowCmd == SW_SHOWMAXIMIZED {
					winState = "maximized"
				}
				ws = config.WindowState{
					X:      int(r.Left),
					Y:      int(r.Top),
					Width:  int(r.Right - r.Left),
					Height: int(r.Bottom - r.Top),
					State:  winState,
				}
			}
			activeView := ViewHosts
			if activeTab >= 0 && activeTab < len(tabIndexToView) {
				activeView = tabIndexToView[activeTab]
			}
			config.SaveState(stateDirPath, config.State{
				Window:     ws,
				ActiveView: activeView,
				Columns:    snapshotAllColumnStates(),
			})
		}
		killTimer(HWND(hwnd), IDT_DECAY)
		stopScan()
		stopService()
		stopBroadcastListener()
		stopARPPoll()
		postQuitMessage(0)
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

// ---------------------------------------------------------------------------
// Control creation
// ---------------------------------------------------------------------------

// activateTab switches the content area to tab index tab. It shows the correct
// pane (and placeholder), hides all others, and toggles the scan bar visibility.
// It also updates the Ctrl+F find bar state for the new tab.
//
// Call this whenever the active tab changes — both from the TCN_SELCHANGE
// notification and when restoring a saved tab on startup.
func activateTab(hwnd HWND, tab int32) {
	// Hide all panes first.
	showWindow(hwndList, SW_HIDE)
	showWindow(hwndListPlaceholder, SW_HIDE)
	showWindow(hwndListMDNS, SW_HIDE)
	showWindow(hwndMDNSPlaceholder, SW_HIDE)
	showWindow(hwndListSSDP, SW_HIDE)
	showWindow(hwndSSDPPlaceholder, SW_HIDE)
	showWindow(hwndListWSD, SW_HIDE)
	showWindow(hwndWSDPlaceholder, SW_HIDE)
	showWindow(hwndListDHCP, SW_HIDE)
	showWindow(hwndDHCPPlaceholder, SW_HIDE)
	showWindow(hwndListNetwork, SW_HIDE)
	showWindow(hwndListHealth, SW_HIDE)
	showWindow(hwndHealthPlaceholder, SW_HIDE)
	showWindow(hwndListServices, SW_HIDE)
	showWindow(hwndServicesPlaceholder, SW_HIDE)
	// Show/hide scan bar and reposition Hosts listview accordingly.
	// On Hosts tab the scan bar is visible and the list sits below it;
	// on all other tabs the list fills from just below the tab strip.
	if tab == 0 {
		showWindow(hwndTargetLabel, SW_SHOW)
		showWindow(hwndTarget, SW_SHOW)
		showWindow(hwndDetect, SW_SHOW)
		showWindow(hwndScan, SW_SHOW)
		showWindow(hwndActiveOnly, SW_SHOW)
		showWindow(hwndScanStatus, SW_SHOW)

		// Ensure Hosts list is repositioned to account for scan bar.
		r := getClientRect(hwndMain)
		statusR := getClientRect(hwndStatus)
		statusH := statusR.Bottom - statusR.Top
		hostsTop := scale(elevBarH + tabCtrlH + scanBarH)
		listH := (r.Bottom - r.Top) - hostsTop - statusH
		if listH < 0 {
			listH = 0
		}
		moveWindow(hwndList, 0, hostsTop, r.Right-r.Left, listH)
		moveWindow(hwndListPlaceholder, 0, hostsTop+(listH-scale(20))/2, r.Right-r.Left, scale(20))
		showWindow(hwndList, SW_SHOW)
		if !isScanning && !listHasHosts {
			showWindow(hwndListPlaceholder, SW_SHOW)
		}
	} else {
		showWindow(hwndTargetLabel, SW_HIDE)
		showWindow(hwndTarget, SW_HIDE)
		showWindow(hwndDetect, SW_HIDE)
		showWindow(hwndScan, SW_HIDE)
		showWindow(hwndActiveOnly, SW_HIDE)
		showWindow(hwndScanStatus, SW_HIDE)
		switch tab {
		case 1:
			showWindow(hwndListServices, SW_SHOW)
			if len(svcTabData) == 0 {
				showWindow(hwndServicesPlaceholder, SW_SHOW)
			}
		case 2:
			showWindow(hwndListMDNS, SW_SHOW)
			if bcastMDNS == 0 || proxyEnabled {
				showWindow(hwndMDNSPlaceholder, SW_SHOW)
			}
		case 3:
			showWindow(hwndListSSDP, SW_SHOW)
			if bcastSSDP == 0 || proxyEnabled {
				showWindow(hwndSSDPPlaceholder, SW_SHOW)
			}
		case 4:
			showWindow(hwndListWSD, SW_SHOW)
			if bcastWSD == 0 || proxyEnabled {
				showWindow(hwndWSDPlaceholder, SW_SHOW)
			}
		case 5:
			showWindow(hwndListDHCP, SW_SHOW)
			if bcastDHCP == 0 || proxyEnabled {
				showWindow(hwndDHCPPlaceholder, SW_SHOW)
			}
		case 6:
			showWindow(hwndListNetwork, SW_SHOW)
		case 7:
			showWindow(hwndListHealth, SW_SHOW)
			if !scanEverCompleted {
				showWindow(hwndHealthPlaceholder, SW_SHOW)
			}
		}
	}
	// Update find bar for the new tab: reposition, reload its text,
	// or hide it if the new tab doesn't support filtering.
	// Tabs 6 (Network) and 7 (Scan Report) are text areas; no filtering.
	if isWindowVisible(hwndSearchEdit) {
		if tab == 6 || tab == 7 {
			showWindow(hwndSearchEdit, SW_HIDE)
			showWindow(hwndSearchClose, SW_HIDE)
		} else {
			positionFindBar(hwnd)
			setWindowText(hwndSearchEdit, tabSearchFilter[tab])
		}
	}
}

func createControls(hwnd HWND) {
	inst := getModuleHandle()
	elevated := isElevated()

	// Fetch the actual DPI for this window now that the HWND exists.
	// This handles the case where the app starts on a non-96-DPI monitor.
	if dpi := getDpiForWindow(hwnd); dpi > 0 {
		currentDPI = dpi
	}

	// ---- global options bar (top strip) ----
	// "Elevate Sensor" button on the left.
	hwndServiceBtn = makePushButton(hwnd, "Elevate Sensor", IDC_SERVICE_BTN,
		scale(8), scale(3), scale(160), scale(26))
	if elevated {
		enableWindow(hwndServiceBtn, false)
	}
	// "Proxy Mode" checkbox next to service button; grayed if no proxy is configured.
	hwndProxyCheck = makeCheckBox(hwnd, "Proxy Mode", IDC_PROXY_CHECK,
		scale(180), scale(5), scale(120), scale(22))
	if appConfig.Scan.SOCKSProxy == "" {
		enableWindow(hwndProxyCheck, false)
	} else if proxyEnabled {
		sendMessage(hwndProxyCheck, BM_SETCHECK, BST_CHECKED, 0)
	}

	// ---- tab control ----
	hwndTabCtrl, _ = createWindowEx(0, WC_TABCONTROL, "",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|TCS_FLATBUTTONS,
		0, scale(elevBarH), scale(1160), scale(tabCtrlH), hwnd, IDC_TABS, inst)
	insertTab(hwndTabCtrl, 0, "Scanner")
	insertTab(hwndTabCtrl, 1, "Services")
	insertTab(hwndTabCtrl, 2, "mDNS")
	insertTab(hwndTabCtrl, 3, "SSDP")
	insertTab(hwndTabCtrl, 4, "WSD")
	insertTab(hwndTabCtrl, 5, "DHCP")
	insertTab(hwndTabCtrl, 6, "Network")
	insertTab(hwndTabCtrl, 7, "Scan Report")

	// Scan bar sits below the tab strip; only visible when Hosts tab is active.
	// Layout (right-anchored): [Target label][Target input …][⟲][Scan status][Active only][Scan/Stop]
	scanBarY := scale(elevBarH + tabCtrlH)
	hwndTargetLabel, _ = createWindowEx(0, "STATIC", "Target:", WS_CHILD|WS_VISIBLE, scale(8), scanBarY+scale(8), scale(48), scale(20), hwnd, 0, inst)
	hwndTarget, _ = createWindowEx(WS_EX_CLIENTEDGE, "EDIT", initialTarget,
		WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL|WS_TABSTOP,
		scale(58), scanBarY+scale(6), scale(460), scale(22), hwnd, IDC_TARGET, inst)
	hwndDetect = makePushButton(hwnd, "\u27f2", IDC_DETECT,
		scale(524), scanBarY+scale(5), scale(34), scale(24))
	hwndScanStatus, _ = createWindowEx(WS_EX_STATICEDGE, "STATIC", "Ready to scan",
		WS_CHILD|WS_VISIBLE|SS_CENTER,
		scale(566), scanBarY+scale(6), scale(160), scale(22), hwnd, 0, inst)
	hwndActiveOnly = makeCheckBox(hwnd, "Active only", IDC_ACTIVE_ONLY,
		scale(734), scanBarY+scale(6), scale(110), scale(22))
	hwndScan = makePushButton(hwnd, "Scan", IDC_SCAN,
		scale(852), scanBarY+scale(5), scale(100), scale(24))

	// Hosts listview starts below the scan bar.
	hostsTop := scale(elevBarH + tabCtrlH + scanBarH)
	// All other panes start just below the tab strip (no scan bar).
	otherTop := scale(elevBarH + tabCtrlH)

	// ---- hosts listview (visible) ----
	hwndList, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VISIBLE|WS_CLIPSIBLINGS|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		0, hostsTop, 1160, 600, hwnd, IDC_LIST, inst)
	sendMessage(hwndList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP|LVS_EX_MARQUEESELECT)
	subclassListViewManaged(hwndList, hostsColTitles[:], colVisible[:], colDefaultLogicalWidths[:],
		func(_ HWND, col int32, asc bool) { applyHostsSort(col, asc) }, nil)
	headerHwnd = HWND(sendMessage(hwndList, LVM_GETHEADER, 0, 0))
	// Columns come from hostsColTitles + colDefaultLogicalWidths (single source of truth).
	for i, title := range hostsColTitles {
		if i == int(colLatency) || i == int(colPorts) {
			listViewAddColumnFmt(hwndList, int32(i), title, scale(colDefaultLogicalWidths[i]), LVCFMT_RIGHT)
		} else {
			listViewAddColumn(hwndList, int32(i), title, scale(colDefaultLogicalWidths[i]))
		}
	}

	// ---- empty-state placeholder (sits on top of hwndList when no hosts) ----
	hwndListPlaceholder = createEmptyStateOverlay(hwnd, "Enter a target above and click Scan",
		0, hostsTop+200, 1160, scale(20))
	showWindow(hwndListPlaceholder, SW_SHOW)

	// ---- mDNS listview (hidden initially) ----
	hwndListMDNS, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_CLIPSIBLINGS|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		0, otherTop, 1160, 600, hwnd, IDC_LIST_MDNS, inst)
	sendMessage(hwndListMDNS, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP|LVS_EX_MARQUEESELECT)
	subclassListViewManaged(hwndListMDNS, mdnsColTitles, mdnsColVis, mdnsDefWidths, applyMDNSSort, nil)
	for i, title := range mdnsColTitles {
		listViewAddColumn(hwndListMDNS, int32(i), title, scale(mdnsDefWidths[i]))
	}
	hwndMDNSPlaceholder = createEmptyStateOverlay(hwnd, func() string {
		if proxyEnabled {
			return "Not available in proxy mode  (mDNS is link-local multicast, not routable over SOCKS5)"
		}
		return "Listening — no mDNS traffic detected yet"
	}(), 0, otherTop+200, 1160, scale(20))

	// ---- SSDP listview (hidden initially) ----
	hwndListSSDP, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_CLIPSIBLINGS|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		0, otherTop, 1160, 600, hwnd, IDC_LIST_SSDP, inst)
	sendMessage(hwndListSSDP, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP|LVS_EX_MARQUEESELECT)
	subclassListViewManaged(hwndListSSDP, ssdpColTitles, ssdpColVis, ssdpDefWidths, applySSDPSort, nil)
	for i, title := range ssdpColTitles {
		listViewAddColumn(hwndListSSDP, int32(i), title, scale(ssdpDefWidths[i]))
	}
	hwndSSDPPlaceholder = createEmptyStateOverlay(hwnd, func() string {
		if proxyEnabled {
			return "Not available in proxy mode  (SSDP is link-local multicast, not routable over SOCKS5)"
		}
		return "Listening — no SSDP traffic detected yet"
	}(), 0, otherTop+200, 1160, scale(20))

	// ---- WS-Discovery listview (hidden initially) ----
	hwndListWSD, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_CLIPSIBLINGS|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		0, otherTop, 1160, 600, hwnd, IDC_LIST_WSD, inst)
	sendMessage(hwndListWSD, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP|LVS_EX_MARQUEESELECT)
	subclassListViewManaged(hwndListWSD, wsdColTitles, wsdColVis, wsdDefWidths, applyWSDSort, nil)
	for i, title := range wsdColTitles {
		listViewAddColumn(hwndListWSD, int32(i), title, scale(wsdDefWidths[i]))
	}
	hwndWSDPlaceholder = createEmptyStateOverlay(hwnd, func() string {
		if proxyEnabled {
			return "Not available in proxy mode  (WS-Discovery is link-local multicast, not routable over SOCKS5)"
		}
		return "Listening — no WS-Discovery traffic detected yet"
	}(), 0, otherTop+200, 1160, scale(20))

	// ---- DHCP listview (hidden initially) ----
	hwndListDHCP, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_CLIPSIBLINGS|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		0, otherTop, 1160, 600, hwnd, IDC_LIST_DHCP, inst)
	sendMessage(hwndListDHCP, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP|LVS_EX_MARQUEESELECT)
	subclassListViewManaged(hwndListDHCP, dhcpColTitles, dhcpColVis, dhcpDefWidths, applyDHCPSort, nil)
	for i, title := range dhcpColTitles {
		listViewAddColumn(hwndListDHCP, int32(i), title, scale(dhcpDefWidths[i]))
	}
	hwndDHCPPlaceholder = createEmptyStateOverlay(hwnd, func() string {
		if proxyEnabled {
			return "Not available in proxy mode  (DHCP capture requires local network interface access)"
		}
		return "Listening — no DHCP traffic detected yet (requires elevation)"
	}(), 0, otherTop+200, 1160, scale(20))

	// ---- network text area (hidden initially) ----
	networkInitialText := "Waiting for broadcast traffic…"
	if proxyEnabled {
		networkInitialText = "Not available in proxy mode  (network-layer traffic cannot be captured over SOCKS5)"
	}
	hwndListNetwork, _ = createWindowEx(
		WS_EX_CLIENTEDGE, "EDIT", networkInitialText,
		WS_CHILD|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
		0, otherTop, 1160, 600, hwnd, IDC_LIST_NETWORK, inst)

	// ---- scan report text area (hidden initially) ----
	hwndListHealth, _ = createWindowEx(
		WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
		0, otherTop, 1160, 600, hwnd, 0, inst)
	hwndHealthPlaceholder = createEmptyStateOverlay(hwnd, "Run a scan to populate this report",
		0, otherTop+200, 1160, scale(20))

	// ---- Services listview (hidden initially) ----
	hwndListServices, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_CLIPSIBLINGS|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		0, otherTop, 1160, 600, hwnd, IDC_LIST_SERVICES, inst)
	sendMessage(hwndListServices, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP|LVS_EX_MARQUEESELECT)
	subclassListViewManaged(hwndListServices, svcTabColTitles, svcTabColVis, svcTabDefWidths, nil, nil)
	for i, title := range svcTabColTitles {
		if i == 4 { // Port: right-align
			listViewAddColumnFmt(hwndListServices, int32(i), title, scale(svcTabDefWidths[i]), LVCFMT_RIGHT)
		} else {
			listViewAddColumn(hwndListServices, int32(i), title, scale(svcTabDefWidths[i]))
		}
	}
	hwndServicesPlaceholder = createEmptyStateOverlay(hwnd,
		fmt.Sprintf("Run a scan with Banner Grab enabled to populate this tab  (>%d%% confidence threshold)", appConfig.Scan.ServiceMinConfidence),
		0, otherTop+200, 1160, scale(20))

	// ---- status bar — 2 parts: Listener state | Service state ----
	hwndStatus = createStatusWindow(hwnd, IDC_STATUS, "")
	setStatusParts(scale(900)) // will be recalculated on first WM_SIZE
	listenerText := "Listener starting\u2026"
	if proxyEnabled {
		listenerText = "Not listening (proxy mode)"
	}
	setStatusPart(statusPartListener, listenerText)
	setStatusPart(statusPartService, statusForService())

	// Apply Segoe UI to every child control (labels, buttons, edits, listviews, tabs).
	// Use the actual window DPI (set above) so the font is correct on all monitors.
	appFont = createUIFont(currentDPI)
	setFontAllChildren(hwnd, appFont)

	// Apply Consolas to the two text-report panes so aligned columns line up.
	monoFont := createMonoFont()
	sendMessage(hwndListNetwork, WM_SETFONT, uintptr(monoFont), 1)
	sendMessage(hwndListHealth, WM_SETFONT, uintptr(monoFont), 1)

	// Find bar: created last so appFont is already set.
	createFindBar(hwnd)
}

// ---------------------------------------------------------------------------
// Ctrl+F find bar
// ---------------------------------------------------------------------------

// createFindBar creates the Ctrl+F search EDIT and dismiss button as direct
// children of parent.  Called once at the end of createControls.
func createFindBar(parent HWND) {
	inst := getModuleHandle()
	hwndSearchEdit, _ = createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|ES_AUTOHSCROLL|WS_TABSTOP,
		0, 0, scale(220), scale(24), parent, HMENU(IDC_SEARCH_EDIT), inst)
	cueText := utf16("Search\u2026")
	sendMessage(hwndSearchEdit, EM_SETCUEBANNER, 1, uintptr(unsafe.Pointer(cueText)))
	hwndSearchClose, _ = createWindowEx(0, "BUTTON", "\u00d7",
		WS_CHILD|WS_TABSTOP|BS_FLAT,
		0, 0, scale(26), scale(24), parent, HMENU(IDC_SEARCH_CLOSE), inst)
	sendMessage(hwndSearchEdit, WM_SETFONT, uintptr(appFont), 1)
	sendMessage(hwndSearchClose, WM_SETFONT, uintptr(appFont), 1)
	// Subclass the edit to intercept Escape.
	searchEditOrigProc = setWindowLongPtr(hwndSearchEdit, GWLP_WNDPROC, uintptr(searchEditSubclassCb))
}

// showFindBar makes the find bar visible for the currently active tab
// (tabs 0–4 only) and focuses the search edit.  Safe to call when already
// visible — just re-focuses.
func showFindBar(parent HWND) {
	tab := int32(sendMessage(hwndTabCtrl, TCM_GETCURSEL, 0, 0))
	if tab >= 6 {
		return // Network and Scan Report tabs are text areas — no filter
	}
	positionFindBar(parent)
	setWindowText(hwndSearchEdit, tabSearchFilter[tab])
	sendMessage(hwndSearchEdit, EM_SETSEL, 0, ^uintptr(0)) // select all
	showWindow(hwndSearchEdit, SW_SHOW)
	showWindow(hwndSearchClose, SW_SHOW)
	// Ensure the find bar floats on top of sibling ListViews.
	const hwndTop = 0 // HWND_TOP
	setWindowPos(hwndSearchEdit, hwndTop, 0, 0, 0, 0, SWP_NOMOVE|SWP_NOSIZE|SWP_NOACTIVATE)
	setWindowPos(hwndSearchClose, hwndTop, 0, 0, 0, 0, SWP_NOMOVE|SWP_NOSIZE|SWP_NOACTIVATE)
	setFocus(hwndSearchEdit)
}

// hideFindBar hides the find bar and clears the current tab's filter.
func hideFindBar() {
	showWindow(hwndSearchEdit, SW_HIDE)
	showWindow(hwndSearchClose, SW_HIDE)
	// Repaint the pane that was behind the bar to clear any ghost pixels left
	// by the now-hidden controls.
	if pane := activeContentPane(); pane != 0 {
		invalidateRect(pane, nil, false)
	}
	tab := int32(sendMessage(hwndTabCtrl, TCM_GETCURSEL, 0, 0))
	if tab >= 0 && tab < 6 && tabSearchFilter[tab] != "" {
		tabSearchFilter[tab] = ""
		applyTabFilter()
	}
}

// activeContentPane returns the HWND of the listview (or text pane) that is
// currently active based on the selected tab.
func activeContentPane() HWND {
	tab := int32(sendMessage(hwndTabCtrl, TCM_GETCURSEL, 0, 0))
	switch tab {
	case 0:
		return hwndList
	case 1:
		return hwndListServices
	case 2:
		return hwndListMDNS
	case 3:
		return hwndListSSDP
	case 4:
		return hwndListWSD
	case 5:
		return hwndListDHCP
	case 6:
		return hwndListNetwork
	case 7:
		return hwndListHealth
	}
	return 0
}

// positionFindBar moves the search edit and close button to the top-right
// corner of the currently active pane.
func positionFindBar(parent HWND) {
	r := getClientRect(parent)
	editW := scale(220)
	btnW := scale(26)
	gap := scale(4)
	tab := int32(sendMessage(hwndTabCtrl, TCM_GETCURSEL, 0, 0))
	var paneTop int32
	if tab == 0 {
		paneTop = scale(elevBarH + tabCtrlH + scanBarH)
	} else {
		paneTop = scale(elevBarH + tabCtrlH)
	}
	y := paneTop + gap
	x := r.Right - editW - btnW - gap*3
	moveWindow(hwndSearchEdit, x, y, editW, scale(24))
	moveWindow(hwndSearchClose, x+editW+gap, y, btnW, scale(24))
}

// applyTabFilter re-filters the active tab's listview using tabSearchFilter.
func applyTabFilter() {
	tab := int32(sendMessage(hwndTabCtrl, TCM_GETCURSEL, 0, 0))
	switch tab {
	case 0:
		applyActiveFilter()
	case 1:
		repopulateServicesTab(tabSearchFilter[1])
	case 2:
		repopulateMDNS(hwndListMDNS, tabSearchFilter[2])
	case 3:
		repopulateSSDP(hwndListSSDP, tabSearchFilter[3])
	case 4:
		repopulateWSD(hwndListWSD, tabSearchFilter[4])
	case 5:
		repopulateDHCP(hwndListDHCP, tabSearchFilter[5])
	}
}

// repopulateDHCP rebuilds the DHCP listview from dhcpAllEvents, applying filter.
func repopulateDHCP(hwnd HWND, filter string) {
	filter = strings.ToLower(filter)
	sendMessage(hwnd, LVM_DELETEALLITEMS, 0, 0)
	for _, evt := range dhcpAllEvents {
		if filter == "" || dhcpEventMatchesFilter(evt, filter) {
			listViewAddDHCPRow(hwnd, evt)
		}
	}
}

// dhcpEventMatchesFilter reports whether any field of evt contains filter.
func dhcpEventMatchesFilter(evt scan.DHCPEvent, filter string) bool {
	return strings.Contains(strings.ToLower(evt.ClientMAC), filter) ||
		strings.Contains(strings.ToLower(evt.Hostname), filter) ||
		strings.Contains(strings.ToLower(evt.ClientIP), filter) ||
		strings.Contains(strings.ToLower(evt.OfferedIP), filter) ||
		strings.Contains(strings.ToLower(evt.ServerIP), filter) ||
		strings.Contains(strings.ToLower(evt.Type.String()), filter)
}

// hostsResultMatchesFilter reports whether any visible field of r contains filter.
func hostsResultMatchesFilter(r scan.Result, filter string) bool {
	if strings.Contains(strings.ToLower(r.IP.String()), filter) {
		return true
	}
	if strings.Contains(strings.ToLower(r.Hostname), filter) {
		return true
	}
	if strings.Contains(strings.ToLower(r.NetBIOS), filter) {
		return true
	}
	if r.MAC != nil && strings.Contains(strings.ToLower(r.MAC.String()), filter) {
		return true
	}
	return strings.Contains(strings.ToLower(r.Vendor), filter) ||
		strings.Contains(strings.ToLower(string(r.OS)), filter)
}

// ---------------------------------------------------------------------------
// Layout — resize all panes to fill the client area
// ---------------------------------------------------------------------------

func resizeControls(hwnd HWND, lParam uintptr) {
	width := loword(lParam)
	height := hiword(lParam)

	// Status bar resizes itself (SB_SIMPLE or multi-part).
	sendMessage(hwndStatus, WM_SIZE, 0, lParam)
	statusR := getClientRect(hwndStatus)
	statusH := statusR.Bottom - statusR.Top
	// 2 parts: Listener state (fills) | Service state (200px fixed right).
	setStatusParts(width)

	// Global options bar: Elevate Sensor | Proxy Mode.
	moveWindow(hwndServiceBtn, scale(8), scale(3), scale(160), scale(26))
	moveWindow(hwndProxyCheck, scale(180), scale(5), scale(120), scale(22))
	moveWindow(hwndTabCtrl, 0, scale(elevBarH), width, scale(tabCtrlH))

	// Scan bar (right-anchored): [Target stretches][⟲][Scan status 160px][Active only][Scan]
	scanBarY := scale(elevBarH + tabCtrlH)
	scanX := width - scale(108)
	activeX := scanX - scale(116)
	statusX := activeX - scale(168)
	detectX := statusX - scale(42) // 34px button + 8px gap from status
	targetW := detectX - scale(4) - scale(58)
	if targetW < scale(80) {
		targetW = scale(80)
	}
	moveWindow(hwndTarget, scale(58), scanBarY+scale(6), targetW, scale(22))
	moveWindow(hwndDetect, scale(58)+targetW+scale(4), scanBarY+scale(5), scale(34), scale(24))
	moveWindow(hwndScanStatus, statusX, scanBarY+scale(6), scale(160), scale(22))
	moveWindow(hwndActiveOnly, activeX, scanBarY+scale(6), scale(110), scale(22))
	moveWindow(hwndScan, scanX, scanBarY+scale(5), scale(100), scale(24))

	// Hosts tab: list fills remaining height above the status bar.
	hostsTop := scale(elevBarH + tabCtrlH + scanBarH)
	hostsH := height - hostsTop - statusH
	if hostsH < 0 {
		hostsH = 0
	}
	moveWindow(hwndList, 0, hostsTop, width, hostsH)
	moveWindow(hwndListPlaceholder, 0, hostsTop+(hostsH-scale(20))/2, width, scale(20))

	// All other panes fill from just below the tab strip above the status bar.
	otherTop := scale(elevBarH + tabCtrlH)
	otherH := height - otherTop - statusH
	if otherH < 0 {
		otherH = 0
	}
	moveWindow(hwndListMDNS, 0, otherTop, width, otherH)
	moveWindow(hwndMDNSPlaceholder, 0, otherTop+(otherH-scale(20))/2, width, scale(20))
	moveWindow(hwndListSSDP, 0, otherTop, width, otherH)
	moveWindow(hwndSSDPPlaceholder, 0, otherTop+(otherH-scale(20))/2, width, scale(20))
	moveWindow(hwndListWSD, 0, otherTop, width, otherH)
	moveWindow(hwndWSDPlaceholder, 0, otherTop+(otherH-scale(20))/2, width, scale(20))
	moveWindow(hwndListDHCP, 0, otherTop, width, otherH)
	moveWindow(hwndDHCPPlaceholder, 0, otherTop+(otherH-scale(20))/2, width, scale(20))
	moveWindow(hwndListNetwork, 0, otherTop, width, otherH)
	moveWindow(hwndListHealth, 0, otherTop, width, otherH)
	moveWindow(hwndHealthPlaceholder, 0, otherTop+(otherH-scale(20))/2, width, scale(20))
	moveWindow(hwndListServices, 0, otherTop, width, otherH)
	moveWindow(hwndServicesPlaceholder, 0, otherTop+(otherH-scale(20))/2, width, scale(20))

	// Keep the find bar pinned to the top-right of the active pane.
	if isWindowVisible(hwndSearchEdit) {
		positionFindBar(hwnd)
	}
}

// ---------------------------------------------------------------------------
// Scan start / stop
// ---------------------------------------------------------------------------

// listViewDeleteRowAndFixMaps removes a row from hwndList and repairs ipRowMap
// and rowResultMap so all indices above the deleted row are decremented.
func listViewDeleteRowAndFixMaps(row int32) {
	sendMessage(hwndList, LVM_DELETEITEM, uintptr(row), 0)

	newIPMap := make(map[string]int32, len(ipRowMap)-1)
	for ip, r := range ipRowMap {
		switch {
		case r < row:
			newIPMap[ip] = r
		case r > row:
			newIPMap[ip] = r - 1
		// r == row: omit (deleted)
		}
	}
	ipRowMap = newIPMap

	newResMap := make(map[int32]scan.Result, len(rowResultMap))
	for r, res := range rowResultMap {
		switch {
		case r < row:
			newResMap[r] = res
		case r > row:
			newResMap[r-1] = res
		// r == row: omit (deleted)
		}
	}
	rowResultMap = newResMap
}

// applyActiveFilter rebuilds hwndList from allScanResults, applying both the
// "Active only" checkbox filter and the Ctrl+F text search filter.
// Pending IPs (pre-populated but not yet scanned) are also text-filtered.
func applyActiveFilter() {
	hostFilter := strings.ToLower(tabSearchFilter[0])
	results := make([]scan.Result, 0, len(allScanResults))
	for _, r := range allScanResults {
		if !activeOnlyFilter || r.Alive {
			if hostFilter == "" || hostsResultMatchesFilter(r, hostFilter) {
				results = append(results, r)
			}
		}
	}
	// Sort by IP to preserve natural order.
	sort.SliceStable(results, func(i, j int) bool {
		return compareHostResult(results[i], results[j], colIP) < 0
	})

	// Pending IPs: pre-populated rows not yet in allScanResults.
	resultIPs := make(map[string]bool, len(results))
	for _, r := range results {
		resultIPs[r.IP.String()] = true
	}
	pendingIPs := make([]string, 0)
	for ip := range ipRowMap {
		if !resultIPs[ip] && allScanResults[ip].IP == nil {
			// Apply text filter to pending rows (IP only — no other data yet).
			if hostFilter == "" || strings.Contains(strings.ToLower(ip), hostFilter) {
				pendingIPs = append(pendingIPs, ip)
			}
		}
	}
	sort.Strings(pendingIPs)

	// Rebuild the ListView.
	sendMessage(hwndList, LVM_DELETEALLITEMS, 0, 0)
	ipRowMap = make(map[string]int32, len(results)+len(pendingIPs))
	rowResultMap = make(map[int32]scan.Result, len(results))

	for _, r := range results {
		ip := r.IP.String()
		row := listViewInsertPendingRow(hwndList, ip)
		ipRowMap[ip] = row
		listViewUpdateRow(hwndList, row, r)
		rowResultMap[row] = r
	}
	for _, ip := range pendingIPs {
		row := listViewInsertPendingRow(hwndList, ip)
		ipRowMap[ip] = row
	}
}

func startScan(hwnd HWND) {
	scanMu.Lock()
	if scanCancel != nil {
		scanMu.Unlock()
		return // already running
	}
	scanMu.Unlock()

	target := getWindowText(hwndTarget)
	if target == "" {
		messageBox(hwnd, "Enter a target IP or CIDR.", "NetScope", 0)
		return
	}

	// WAN safety: warn if the target is not an RFC1918 / private range.
	if !scan.IsPrivate(target) {
		r := messageBox(hwnd,
			"Target \""+target+"\" is not a private/RFC1918 address.\n\n"+
				"Scanning hosts you do not own may violate laws or terms of service.\n\n"+
				"Proceed anyway?",
			"WAN Target Warning",
			MB_YESNO|MB_ICONWARNING)
		if r != IDYES {
			return
		}
	}

	appCfg, _, _ := config.Load()
	scanCfg := appCfg.ToScanConfig()
	// Disable per-scan mDNS/SSDP; background listener handles those continuously.
	scanCfg.BroadcastListen = 0
	// Honour runtime proxy toggle: clear the proxy address if mode is disabled.
	if !proxyEnabled {
		scanCfg.SOCKSProxy = ""
	}

	// Expand target first so we can pre-populate the list.
	hosts, err := scan.ExpandTarget(target)
	if err != nil {
		messageBox(hwnd, "Invalid target: "+err.Error(), "NetScope", 0)
		return
	}

	scanMu.Lock()
	if scanCancel != nil { // re-check after the dialogs above
		scanMu.Unlock()
		return
	}
	_, cancel := context.WithCancel(context.Background())
	scanCancel = cancel
	scanMu.Unlock()

	// Bump the generation counter so stale WM_SCAN_RESULT / WM_SCAN_COMPLETE
	// messages from a previous goroutine are discarded.
	scanGeneration++
	gen := scanGeneration

	// Reset display state.
	liveCount = 0
	// Reset the hosts listview sort to unsorted (state lives in the managed subclass).
	if s, ok := lvManagedStates[hwndList]; ok {
		s.sortCol = -1
		s.sortAsc = true
		lvUpdateSortIndicators(hwndList, hostsColTitles[:], -1, true)
	}
	pendingMu.Lock()
	pendingResults = pendingResults[:0]
	pendingMu.Unlock()

	sendMessage(hwndList, LVM_DELETEALLITEMS, 0, 0)
	ipRowMap = make(map[string]int32, len(hosts))
	rowResultMap = make(map[int32]scan.Result, len(hosts))
	allScanResults = make(map[string]scan.Result, len(hosts))
	// Update confidence threshold from current config and reset services tab.
	if appConfig.Scan.ServiceMinConfidence > 0 {
		svcTabMinConf = uint8(appConfig.Scan.ServiceMinConfidence)
	} else {
		svcTabMinConf = 60
	}
	clearServicesTab()
	showWindow(hwndServicesPlaceholder, SW_SHOW)

	// Pre-populate every IP with a "Pending" row so they appear in order.
	for _, ip := range hosts {
		ipStr := ip.String()
		row := listViewInsertPendingRow(hwndList, ipStr)
		ipRowMap[ipStr] = row
	}

	isScanning = true
	listHasHosts = false
	scanStartTime = time.Now()
	setWindowText(hwndScan, "Stop")
	showWindow(hwndListPlaceholder, SW_HIDE)
	setWindowText(hwndScanStatus, "Scanning\u2026")

	// Route all scans through the persistent sensor service.
	if serviceRunning() {
		sendScanViaService(hwnd, target, scanCfg, gen)
		return
	}

	// Fallback: service not ready yet; run scan in-process.
	ctx, cancel2 := context.WithCancel(context.Background())
	scanMu.Lock()
	scanCancel = cancel2
	scanMu.Unlock()
	go func() {
		defer func() {
			if p := recover(); p != nil {
				writeCrashLog(hwnd, p)
				postMessage(hwnd, WM_SCAN_COMPLETE, uintptr(gen), 0)
			}
		}()
		sc := scan.NewScanner(scanCfg)
		ch, err := sc.Scan(ctx, target)
		if err != nil {
			postMessage(hwnd, WM_SCAN_COMPLETE, uintptr(gen), 0)
			return
		}
		for r := range ch {
			pendingMu.Lock()
			idx := len(pendingResults)
			pendingResults = append(pendingResults, r)
			pendingMu.Unlock()
			postMessage(hwnd, WM_SCAN_RESULT, uintptr(idx), uintptr(gen))
		}
		pendingMu.Lock()
		lastStats = sc.Stats
		pendingMu.Unlock()
		postMessage(hwnd, WM_SCAN_COMPLETE, uintptr(gen), 0)
	}()
}

// hostRescanScanID is a sentinel ScanID used exclusively for targeted rescans
// launched from the Host detail dialog. It is safely distinct from scanGeneration
// (which starts at 0 and increments by 1), so WM_SCAN_COMPLETE messages carrying
// this ID are discarded by the existing generation guard and do not disturb the
// main scan UI state.
const hostRescanScanID uint64 = ^uint64(0)

// rescanSingleHost sends a targeted scan for ip through the service (or the
// in-process fallback) without clearing or resetting the Scanner listview.
// Results arrive via the normal WM_SCAN_RESULT path tagged with hostRescanScanID;
// liveCount and the scan status bar are left untouched.
// Called from the UI thread only (via WM_HOST_RESCAN).
func rescanSingleHost(hwnd HWND, ip string) {
	if ip == "" {
		return
	}
	appCfg, _, _ := config.Load()
	scanCfg := appCfg.ToScanConfig()
	scanCfg.BroadcastListen = 0
	if !proxyEnabled {
		scanCfg.SOCKSProxy = ""
	}

	if serviceRunning() {
		sendScanViaService(hwnd, ip, scanCfg, hostRescanScanID)
		return
	}

	// Fallback: in-process scan goroutine.
	go func() {
		defer func() {
			if p := recover(); p != nil {
				writeCrashLog(hwnd, p)
			}
		}()
		sc := scan.NewScanner(scanCfg)
		ch, err := sc.Scan(context.Background(), ip)
		if err != nil {
			return
		}
		for r := range ch {
			pendingMu.Lock()
			idx := len(pendingResults)
			pendingResults = append(pendingResults, r)
			pendingMu.Unlock()
			postMessage(hwnd, WM_SCAN_RESULT, uintptr(idx), uintptr(hostRescanScanID))
		}
	}()
}

// detectSubnet fills the target box with the detected local subnet.
// If a single private subnet is found, it is filled silently.
// If multiple are found, a popup menu lets the user pick one.
// Called from the UI thread only.
func detectSubnet(hwnd HWND) {
	subnets := scan.DetectLocalSubnets()
	switch len(subnets) {
	case 0:
		messageBox(hwnd, "No private IPv4 interface detected.\n\nConnect to a network and try again.",
			"Detect Local Subnet", 0)
	case 1:
		setWindowText(hwndTarget, subnets[0])
	default:
		// Multiple interfaces — offer a popup menu.
		menu := createPopupMenu()
		for i, s := range subnets {
			appendMenu(menu, MF_STRING, uintptr(IDM_DETECT_BASE+i), s)
		}
		pt := getClientPtBelowControl(hwndDetect)
		cmd := trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, pt.X, pt.Y, hwnd)
		destroyMenu(menu)
		if cmd >= IDM_DETECT_BASE && int(cmd-IDM_DETECT_BASE) < len(subnets) {
			setWindowText(hwndTarget, subnets[cmd-IDM_DETECT_BASE])
		}
	}
}

// getClientPtBelowControl returns the screen position just below a control,
// suitable for placing a popup menu flush with the button.
func getClientPtBelowControl(ctrl HWND) POINT {
	r := getWindowRect(ctrl)
	return POINT{X: r.Left, Y: r.Bottom}
}

func stopScan() {
	stopServiceScan() // send stop command to service if running
	scanMu.Lock()
	defer scanMu.Unlock()
	if scanCancel != nil {
		scanCancel()
		scanCancel = nil
	}
}

// applyProxyMode toggles proxy mode on or off at runtime (session-only;
// does not write to the config file).  Called from the UI thread only.
func applyProxyMode(hwnd HWND, enable bool) {
	proxyEnabled = enable
	if enable {
		stopBroadcastListener()
		setStatusPart(statusPartListener, "Not listening (proxy mode)")
	} else {
		startBroadcastListener(hwnd)
	}
	// Refresh placeholder text for broadcast tabs that are currently visible.
	proxyMsg := "Not available in proxy mode"
	setWindowText(hwndMDNSPlaceholder, func() string {
		if enable {
			return proxyMsg + "  (mDNS is link-local multicast, not routable over SOCKS5)"
		}
		return "Listening \u2014 no mDNS traffic detected yet"
	}())
	setWindowText(hwndSSDPPlaceholder, func() string {
		if enable {
			return proxyMsg + "  (SSDP is link-local multicast, not routable over SOCKS5)"
		}
		return "Listening \u2014 no SSDP traffic detected yet"
	}())
	setWindowText(hwndWSDPlaceholder, func() string {
		if enable {
			return proxyMsg + "  (WS-Discovery is link-local multicast, not routable over SOCKS5)"
		}
		return "Listening \u2014 no WS-Discovery traffic detected yet"
	}())
	setWindowText(hwndDHCPPlaceholder, func() string {
		if enable {
			return proxyMsg + "  (DHCP capture requires local network interface access)"
		}
		return "Listening \u2014 no DHCP traffic detected yet (requires elevation)"
	}())
	setWindowText(hwndListNetwork, func() string {
		if enable {
			return proxyMsg + "  (network-layer traffic cannot be captured over SOCKS5)"
		}
		return "Waiting for broadcast traffic\u2026"
	}())
	// Force broadcast-tab placeholders visible if proxy is now on and a tab is active.
	tab := int32(sendMessage(hwndTabCtrl, TCM_GETCURSEL, 0, 0))
	if enable && tab >= 1 && tab <= 4 {
		switch tab {
		case 1:
			showWindow(hwndMDNSPlaceholder, SW_SHOW)
		case 2:
			showWindow(hwndSSDPPlaceholder, SW_SHOW)
		case 3:
			showWindow(hwndWSDPlaceholder, SW_SHOW)
		case 4:
			showWindow(hwndDHCPPlaceholder, SW_SHOW)
		}
	}
}



// hostEntryToResult converts a hostEntry to a scan.Result for export,
// merging ExtraServices that are not already present in Result.Services.
func hostEntryToResult(en *hostEntry) scan.Result {
	r := en.Result
	if r.IP == nil {
		r.IP = net.ParseIP(en.IP)
	}
	for _, svc := range en.ExtraServices {
		found := false
		for _, s := range r.Services {
			if s.Source == svc.Source && s.Name == svc.Name && s.Type == svc.Type {
				found = true
				break
			}
		}
		if !found {
			r.Services = append(r.Services, svc)
		}
	}
	return r
}

// exportAllHosts saves every known host from the session's hostRegistry to a
// JSON or CSV file via a Save dialog. This is the "Export All Hosts" action.
func exportAllHosts(hwnd HWND, format string) {
	if len(hostRegistry) == 0 {
		messageBox(hwnd, "No hosts to export. Run a scan first.", "Export", 0)
		return
	}

	ips := allHostIPs()
	results := make([]scan.Result, 0, len(ips))
	for _, ip := range ips {
		en := hostRegistry[ip]
		results = append(results, hostEntryToResult(en))
	}

	doExport(hwnd, results, format)
}

// exportResults saves the results from the most recently completed scan
// (allScanResults) to a JSON or CSV file via a Save dialog.
func exportResults(hwnd HWND, format string) {
	if len(allScanResults) == 0 {
		messageBox(hwnd, "No scan results to export. Run a scan first.", "Export", 0)
		return
	}

	results := make([]scan.Result, 0, len(allScanResults))
	for _, r := range allScanResults {
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool {
		ai := results[i].IP.To4()
		aj := results[j].IP.To4()
		if ai == nil || aj == nil {
			return results[i].IP.String() < results[j].IP.String()
		}
		for k := 0; k < 4; k++ {
			if ai[k] != aj[k] {
				return ai[k] < aj[k]
			}
		}
		return false
	})

	doExport(hwnd, results, format)
}

// doExport writes results to a user-chosen file in the given format.
func doExport(hwnd HWND, results []scan.Result, format string) {
	var title, defExt, filter string
	if format == "json" {
		title = "Export as JSON"
		defExt = "json"
		filter = "JSON files|*.json|All files|*.*|"
	} else {
		title = "Export as CSV"
		defExt = "csv"
		filter = "CSV files|*.csv|All files|*.*|"
	}

	path := getSaveFileName(hwnd, title, defExt, filter)
	if path == "" {
		return // user cancelled
	}

	f, err := os.Create(path)
	if err != nil {
		messageBox(hwnd, "Could not create file:\n"+err.Error(), "Export Error", 0)
		return
	}
	defer f.Close()

	if format == "json" {
		err = scan.WriteJSON(f, results)
	} else {
		err = scan.WriteCSV(f, results)
	}
	if err != nil {
		messageBox(hwnd, "Export failed:\n"+err.Error(), "Export Error", 0)
		return
	}
	messageBox(hwnd, "Exported "+fmt.Sprintf("%d", len(results))+" hosts to:\n"+path, "Export Complete", 0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// setStatusParts sets the right-edge pixel positions for the 2-part status bar.
// windowWidth is the current client width; the Service part is a fixed 200px from
// the right, and the Listener part fills the remainder.
func setStatusParts(windowWidth int32) {
	serviceW := scale(200)
	if windowWidth < serviceW*2 {
		windowWidth = serviceW * 2
	}
	right := [2]int32{windowWidth - serviceW, -1}
	sendMessage(hwndStatus, SB_SETPARTS, 2, uintptr(unsafe.Pointer(&right[0])))
}

// setStatusPart sets the text of one status bar part (0=Listener, 1=Service).
func setStatusPart(part uintptr, s string) {
	p, _ := syscall.UTF16PtrFromString(s)
	sendMessage(hwndStatus, SB_SETTEXT, part, uintptr(unsafe.Pointer(p)))
}

// updateNetworkTab refreshes the Network tab with live broadcast stats.
// Called on the UI thread whenever a broadcast entry arrives or service state changes.
func updateNetworkTab() {
	text := fmt.Sprintf(
		"NetScope — Live Network Activity\r\n"+
			"══════════════════════════════════════════\r\n\r\n"+
			"  Sensor                 : %s\r\n\r\n"+  
			"  Broadcast listeners    : mDNS + SSDP (running since app start)\r\n"+
			"  mDNS services seen     : %d\r\n"+
			"  SSDP devices seen      : %d\r\n"+
			"  Total broadcast events : %d\r\n\r\n"+
			"══════════════════════════════════════════\r\n"+
			"Notes:\r\n"+
			"  • mDNS and SSDP rows are listed in detail on their respective tabs.\r\n"+
			"  • Counts accumulate continuously; they are not reset between scans.\r\n"+
			"  • Elevating the service enables ARP + ICMP for richer scan results.\r\n",
		statusForService(),
		bcastMDNS,
		bcastSSDP,
		bcastCount,
	)
	setWindowText(hwndListNetwork, text)
}

// updateHealthTab fills the Scan Report tab with stats from the last scan.
func updateHealthTab(stats scan.ScanStats, duration time.Duration) {
	showWindow(hwndHealthPlaceholder, SW_HIDE)
	arpLine := "None detected."
	if stats.ARPAnomalies > 0 {
		arpLine = fmt.Sprintf("%d — same IP seen with different MACs (possible duplicate IP or ARP spoofing). Investigate with 'arp -a'.", stats.ARPAnomalies)
	}

	text := fmt.Sprintf(
		"NetScope — Scan Report\r\n"+
			"══════════════════════════════════════════\r\n\r\n"+
			"  Scan duration           : %.1f s\r\n"+
			"  Hosts found             : %d\r\n"+
			"  Packets sent            : %d\r\n"+
			"  Replies received        : %d\r\n"+
			"  Timeouts                : %d\r\n"+
			"  Average latency         : %.2f ms\r\n\r\n"+
			"  Hosts without PTR       : %d\r\n"+
			"  ARP anomalies           : %s\r\n\r\n"+
			"══════════════════════════════════════════\r\n"+
			"Notes:\r\n"+
			"  • Hosts without PTR: many networks have no reverse DNS. This is\r\n"+
			"    normal and does not indicate a problem with the host.\r\n"+
			"  • ARP anomalies are genuinely unusual and worth investigating.\r\n",
		duration.Seconds(),
		liveCount,
		stats.PacketsSent,
		stats.RepliesReceived,
		stats.Timeouts,
		stats.AvgLatencyMS(),
		stats.DNSFailures,
		arpLine,
	)
	setWindowText(hwndListHealth, text)
}

// ---------------------------------------------------------------------------
// Right-click context menu for a host in the list
// ---------------------------------------------------------------------------

// portOpen returns true if port is in r.OpenPorts.
func portOpen(r scan.Result, port int) bool {
	for _, p := range r.OpenPorts {
		if p == port {
			return true
		}
	}
	return false
}

// menuItem appends a string item, greyed when !enabled.
func menuItem(menu HMENU, id uintptr, label string, enabled bool) {
	flags := uint32(MF_STRING)
	if !enabled {
		flags |= MF_GRAYED
	}
	appendMenu(menu, flags, id, label)
}

// openProtocol launches a connection to ip using the named protocol.
// If a custom command template is configured (appConfig.Scan.ProtocolHandlers),
// that is used; otherwise the OS default handler is invoked.
// %s in the custom command is replaced by the IP address.
func openProtocol(hwnd HWND, ip string, protocol string) {
	custom := appConfig.Scan.ProtocolHandlers[protocol]
	if custom != "" {
		cmd := strings.ReplaceAll(custom, "%s", ip)
		parts := strings.SplitN(cmd, " ", 2)
		exe := parts[0]
		args := ""
		if len(parts) > 1 {
			args = parts[1]
		}
		shellExecute(hwnd, "open", exe, args, "", SW_SHOW)
		return
	}
	switch protocol {
	case "http":
		shellExecute(hwnd, "open", "http://"+ip, "", "", SW_SHOW)
	case "https":
		shellExecute(hwnd, "open", "https://"+ip, "", "", SW_SHOW)
	case "ssh":
		shellExecute(hwnd, "open", "ssh://"+ip, "", "", SW_SHOW)
	case "rdp":
		shellExecute(hwnd, "open", "mstsc.exe", "/v:"+ip, "", SW_SHOW)
	case "ftp":
		shellExecute(hwnd, "open", "ftp://"+ip, "", "", SW_SHOW)
	case "telnet":
		shellExecute(hwnd, "open", "telnet://"+ip, "", "", SW_SHOW)
	case "smb":
		shellExecute(hwnd, "open", `\\`+ip, "", "", SW_SHOW)
	}
}

// copyToClipboard places text on the Windows clipboard as CF_UNICODETEXT.
func copyToClipboard(hwnd HWND, text string) {
	utf16, err := syscall.UTF16FromString(text)
	if err != nil {
		return
	}
	// Allocate global memory: len(utf16) * 2 bytes (each uint16 = 2 bytes).
	const GMEM_MOVEABLE = 0x0002
	const CF_UNICODETEXT = 13
	hMem, _, _ := procGlobalAlloc.Call(GMEM_MOVEABLE, uintptr(len(utf16)*2))
	if hMem == 0 {
		return
	}
	ptr, _, _ := procGlobalLock.Call(hMem)
	if ptr == 0 {
		return
	}
	procRtlMoveMemory.Call(ptr, uintptr(unsafe.Pointer(&utf16[0])), uintptr(len(utf16)*2))
	procGlobalUnlock.Call(hMem)

	procOpenClipboard.Call(uintptr(hwnd))
	procEmptyClipboard.Call()
	procSetClipboardData.Call(CF_UNICODETEXT, hMem)
	procCloseClipboard.Call()
}

// appendCopyAsSubmenu appends a "Copy as…" MF_POPUP submenu carrying
// IDM_COPY_AS_TSV / IDM_COPY_AS_CSV / IDM_COPY_AS_JSON to menu.
// The returned HMENU is owned by menu and must not be destroyed separately.
func appendCopyAsSubmenu(menu HMENU) {
	hSub := createPopupMenu()
	appendMenu(hSub, MF_STRING, IDM_COPY_AS_TSV,  "Tab Delimited")
	appendMenu(hSub, MF_STRING, IDM_COPY_AS_CSV,  "CSV")
	appendMenu(hSub, MF_STRING, IDM_COPY_AS_JSON, "JSON")
	appendMenu(menu, MF_POPUP, uintptr(hSub), "Copy as\u2026")
}

// showHostContextMenu builds and tracks a context menu for the given Result at
// screen coordinates (x, y).
// listViewInfoFor returns the HWND, column count, and canonical header strings
// for the list-view identified by its control ID. Returns zero HWND if unknown.
func listViewInfoFor(idFrom uintptr) (hw HWND, numCols int32, headers []string) {
	switch idFrom {
	case IDC_LIST:
		return hwndList, int32(len(hostsColTitles)), hostsColTitles[:]
	case IDC_LIST_MDNS:
		return hwndListMDNS, int32(len(mdnsColTitles)), mdnsColTitles
	case IDC_LIST_SSDP:
		return hwndListSSDP, int32(len(ssdpColTitles)), ssdpColTitles
	case IDC_LIST_WSD:
		return hwndListWSD, int32(len(wsdColTitles)), wsdColTitles
	case IDC_LIST_DHCP:
		return hwndListDHCP, int32(len(dhcpColTitles)), dhcpColTitles
	case IDC_LIST_SERVICES:
		return hwndListServices, int32(len(svcTabColTitles)), svcTabColTitles
	}
	return 0, 0, nil
}

func showHostContextMenu(parent HWND, r scan.Result, x, y int32) {
	ip := r.IP.String()
	selCount := len(listViewGetSelectedRows(hwndList))

	menu := createPopupMenu()
	defer destroyMenu(menu)

	if selCount > 1 {
		// Multi-selection: only bulk-applicable items.
		appendCopyAsSubmenu(menu)
		cmd := trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, x, y, parent)
		rows := listViewGetSelectedRows(hwndList)
		handleCopyAsCmd(parent, hwndList, cmd, rows, 10, hostsColTitles[:], hostsColKeys)
		return
	}

	// ── Connect submenu ──────────────────────────────────────────────────────
	hConn := createPopupMenu()
	menuItem(hConn, IDM_CTX_OPEN_HTTP,   "HTTP (port 80)",   portOpen(r, 80))
	menuItem(hConn, IDM_CTX_OPEN_HTTPS,  "HTTPS (port 443)", portOpen(r, 443))
	appendMenu(hConn, MF_SEPARATOR, 0, "")
	menuItem(hConn, IDM_CTX_OPEN_SSH,    "SSH (port 22)",    portOpen(r, 22))
	menuItem(hConn, IDM_CTX_OPEN_RDP,    "RDP (port 3389)",  portOpen(r, 3389))
	appendMenu(hConn, MF_SEPARATOR, 0, "")
	menuItem(hConn, IDM_CTX_OPEN_FTP,    "FTP (port 21)",    portOpen(r, 21))
	menuItem(hConn, IDM_CTX_OPEN_TELNET, "Telnet (port 23)", portOpen(r, 23))
	menuItem(hConn, IDM_CTX_OPEN_SMB,    "File Share / SMB (port 445)", portOpen(r, 445))

	appendMenu(menu, MF_POPUP, uintptr(hConn), "Connect")
	appendMenu(menu, MF_SEPARATOR, 0, "")

	// ── Ping ─────────────────────────────────────────────────────────────────
	menuItem(menu, IDM_CTX_PING,      "Ping once",     true)
	menuItem(menu, IDM_CTX_PING_CONT, "Ping -t (continuous)", true)
	appendMenu(menu, MF_SEPARATOR, 0, "")

	// ── Copy ─────────────────────────────────────────────────────────────────
	menuItem(menu, IDM_CTX_COPY_IP, "Copy IP", r.IP != nil)
	appendCopyAsSubmenu(menu) // copies all selected rows in chosen format
	appendMenu(menu, MF_SEPARATOR, 0, "")
	menuItem(menu, IDM_CTX_VIEW_DETAILS, "View details\u2026", true)

	cmd := trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, x, y, parent)
	rows := listViewGetSelectedRows(hwndList)
	if handleCopyAsCmd(parent, hwndList, cmd, rows, 10, hostsColTitles[:], hostsColKeys) {
		return
	}
	switch cmd {
	case IDM_CTX_OPEN_HTTP:
		openProtocol(parent, ip, "http")
	case IDM_CTX_OPEN_HTTPS:
		openProtocol(parent, ip, "https")
	case IDM_CTX_OPEN_SSH:
		openProtocol(parent, ip, "ssh")
	case IDM_CTX_OPEN_RDP:
		openProtocol(parent, ip, "rdp")
	case IDM_CTX_OPEN_FTP:
		openProtocol(parent, ip, "ftp")
	case IDM_CTX_OPEN_TELNET:
		openProtocol(parent, ip, "telnet")
	case IDM_CTX_OPEN_SMB:
		openProtocol(parent, ip, "smb")
	case IDM_CTX_PING:
		shellExecute(parent, "open", "cmd.exe",
			"/c ping "+ip+" && pause", "", SW_SHOW)
	case IDM_CTX_PING_CONT:
		shellExecute(parent, "open", "cmd.exe",
			"/k ping -t "+ip, "", SW_SHOW)
	case IDM_CTX_COPY_IP:
		copyToClipboard(parent, ip)
	case IDM_CTX_VIEW_DETAILS:
		showHostDetailDialog(parent, ip)
	}
}

