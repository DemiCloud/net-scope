//go:build windows

package guiwin

import (
	"context"
	"fmt"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"github.com/demicloud/net-sweep/internal/config"
	"github.com/demicloud/net-sweep/internal/sweep"
)

// ---------------------------------------------------------------------------
// Global UI handles / resources
// ---------------------------------------------------------------------------

var (
	appFont           HFONT // Segoe UI 9pt — shared by main window and all dialogs
	hwndMain          HWND
	hwndTarget        HWND
	hwndScan          HWND
	hwndStop          HWND
	hwndList          HWND
	hwndListBroadcast HWND
	hwndListHealth    HWND // read-only text area for health stats
	hwndTabCtrl       HWND
	hwndStatus        HWND
)

// ---------------------------------------------------------------------------
// Scan state
// ---------------------------------------------------------------------------

var (
	scanCancel context.CancelFunc
	scanMu     sync.Mutex

	// Cross-thread result queue: scan goroutine appends, UI thread reads.
	pendingResults []sweep.Result
	pendingMu      sync.Mutex
	liveCount      int
	lastStats      sweep.ScanStats // populated after scan completes

	// ipRowMap maps IP string → row index in hwndList.
	// Written on the UI thread (startScan), read on the UI thread (WM_SCAN_RESULT).
	ipRowMap    map[string]int32
	// rowResultMap maps ListView row index → scan Result, for right-click menus.
	rowResultMap map[int32]sweep.Result
)

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

const (
	toolbarH = 38
	tabCtrlH = 26 // height of the tab row
)

// ---------------------------------------------------------------------------
// WndProc
// ---------------------------------------------------------------------------

var wndProcCallback = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createControls(HWND(hwnd))
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
			showWindow(hwndList, SW_HIDE)
			showWindow(hwndListBroadcast, SW_HIDE)
			showWindow(hwndListHealth, SW_HIDE)
			switch tab {
			case 0:
				showWindow(hwndList, SW_SHOW)
			case 1:
				showWindow(hwndListBroadcast, SW_SHOW)
			case 2:
				showWindow(hwndListHealth, SW_SHOW)
			}
		}
		// Right-click on host list → context menu.
		if hdr.IdFrom == IDC_LIST && hdr.Code == NM_RCLICK {
			pt := getCursorPos()
			// Convert screen coords to list-view client coords for hit-test.
			cpt := POINT{X: pt.X, Y: pt.Y}
			procScreenToClient.Call(uintptr(hwndList), uintptr(unsafe.Pointer(&cpt)))
			htInfo := LVHITTESTINFO{Pt: cpt}
			row := int32(sendMessage(hwndList, LVM_HITTEST, 0, uintptr(unsafe.Pointer(&htInfo))))
			if row >= 0 {
				if r, ok := rowResultMap[row]; ok {
					showHostContextMenu(HWND(hwnd), r, pt.X, pt.Y)
				}
			}
			return 0
		}
		// Custom draw: alternating row background + green dot for alive rows.
		if hdr.IdFrom == IDC_LIST && hdr.Code == NM_CUSTOMDRAW {
			cd := (*NMLVCUSTOMDRAW)(unsafe.Pointer(lParam)) //nolint:govet
			switch cd.DwDrawStage {
			case CDDS_PREPAINT:
				return CDRF_NOTIFYITEMDRAW
			case CDDS_ITEMPREPAINT:
				row := int(cd.DwItemSpec)
				if row%2 == 0 {
					cd.ClrTextBk = 0x00FFFFFF // white
				} else {
					cd.ClrTextBk = 0x00F5F5F5 // very light gray
				}
				return CDRF_NEWFONT
			}
		}
		return 0

	case WM_COMMAND:
		switch loword(wParam) {
		case IDC_SCAN:
			startScan(HWND(hwnd))
		case IDC_STOP:
			stopScan()
		case IDM_FILE_EXIT:
			stopScan()
			postQuitMessage(0)
		case IDM_FILE_EXPORT_JSON:
			exportResults(HWND(hwnd), "json")
		case IDM_FILE_EXPORT_CSV:
			exportResults(HWND(hwnd), "csv")
		case IDM_OPT_SETTINGS:
			showSettingsDialog(HWND(hwnd))
		case IDM_HELP_FAQ:
			showFAQDialog(HWND(hwnd))
		case IDM_HELP_VERSION:
			showVersionDialog(HWND(hwnd))
		case IDM_HELP_ABOUT:
			messageBox(HWND(hwnd),
				"net-sweep\nFast LAN scanner.\n\nhttps://github.com/demicloud/net-sweep",
				"About net-sweep", 0)
		case IDM_HELP_CRASHLOG:
			path := crashLogPath()
			if _, err := os.Stat(path); os.IsNotExist(err) {
				messageBox(HWND(hwnd), "No crash log found.\n\nIf the app closes unexpectedly, a log will be written to:\n"+path, "Crash Log", 0)
			} else {
				shellExecute(HWND(hwnd), "open", "notepad.exe", path, "", SW_SHOW)
			}
		}
		return 0

	case WM_SCAN_RESULT:
		pendingMu.Lock()
		r := pendingResults[int(wParam)]
		pendingMu.Unlock()

		ipStr := r.IP.String()
		if row, found := ipRowMap[ipStr]; found {
			listViewUpdateRow(hwndList, row, r)
			rowResultMap[row] = r
			if r.Alive {
				liveCount++
				setStatus(fmt.Sprintf("Found %d host(s)…", liveCount))
			}
		} else if r.Alive {
			// Broadcast-only or out-of-range host.
			row := listViewInsertPendingRow(hwndList, ipStr)
			ipRowMap[ipStr] = row
			listViewUpdateRow(hwndList, row, r)
			rowResultMap[row] = r
			liveCount++
			setStatus(fmt.Sprintf("Found %d host(s)…", liveCount))
		}

		// Mirror any services to the Broadcast tab.
		for _, svc := range r.Services {
			listViewAddBroadcastRow(hwndListBroadcast, ipStr, svc)
		}
		return 0

	case WM_SCAN_COMPLETE:
		scanMu.Lock()
		scanCancel = nil
		scanMu.Unlock()
		enableWindow(hwndScan, true)
		enableWindow(hwndStop, false)
		setStatus(fmt.Sprintf("Done — %d host(s) found.", liveCount))
		// Refresh health tab text.
		pendingMu.Lock()
		stats := lastStats
		pendingMu.Unlock()
		updateHealthTab(stats)
		return 0

	case WM_DESTROY:
		stopScan()
		postQuitMessage(0)
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

// ---------------------------------------------------------------------------
// Control creation
// ---------------------------------------------------------------------------

func createControls(hwnd HWND) {
	inst := getModuleHandle()

	// ---- toolbar ----
	// [Target label] [target input ────────────────────────────────] [Scan] [Stop]
	createCtrl("STATIC", "Target:", WS_CHILD|WS_VISIBLE, 8, 10, 48, 20, hwnd, 0, inst)
	hwndTarget, _ = createWindowEx(0, "EDIT", initialTarget,
		WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL|WS_TABSTOP,
		58, 8, 680, 22, hwnd, IDC_TARGET, inst)

	hwndScan, _ = createWindowEx(0, "BUTTON", "Scan",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP, 748, 7, 80, 24, hwnd, IDC_SCAN, inst)
	hwndStop, _ = createWindowEx(0, "BUTTON", "Stop",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP, 836, 7, 80, 24, hwnd, IDC_STOP, inst)
	enableWindow(hwndStop, false)

	// ---- tab control ----
	hwndTabCtrl, _ = createWindowEx(0, WC_TABCONTROL, "",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		0, toolbarH, 1160, tabCtrlH, hwnd, IDC_TABS, inst)
	insertTab(hwndTabCtrl, 0, "Hosts")
	insertTab(hwndTabCtrl, 1, "Broadcast")
	insertTab(hwndTabCtrl, 2, "Health")

	listTop := int32(toolbarH + tabCtrlH)

	// ---- hosts listview (visible) ----
	hwndList, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_BORDER|LVS_REPORT|LVS_SHOWSELALWAYS,
		0, listTop, 1160, 600, hwnd, IDC_LIST, inst)
	sendMessage(hwndList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES|LVS_EX_DOUBLEBUFFER)

	listViewAddColumn(hwndList, colStatus,   "●",          40)
	listViewAddColumn(hwndList, colIP,       "IP Address", 120)
	listViewAddColumn(hwndList, colHost,     "Hostname",   160)
	listViewAddColumn(hwndList, colMAC,      "MAC",        145)
	listViewAddColumn(hwndList, colVendor,   "Vendor",     140)
	listViewAddColumn(hwndList, colOS,       "OS",          90)
	listViewAddColumn(hwndList, colLatency,  "Latency",     70)
	listViewAddColumn(hwndList, colPorts,    "Ports",       110)
	listViewAddColumn(hwndList, colBanner,   "Banners / SNMP", 300)
	listViewAddColumn(hwndList, colServices, "Services",    200)

	// ---- broadcast listview (hidden initially) ----
	hwndListBroadcast, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VSCROLL|WS_BORDER|LVS_REPORT|LVS_SHOWSELALWAYS, // no WS_VISIBLE
		0, listTop, 1160, 600, hwnd, IDC_LIST_BCAST, inst)
	sendMessage(hwndListBroadcast, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES|LVS_EX_DOUBLEBUFFER)

	listViewAddColumn(hwndListBroadcast, 0, "IP", 120)
	listViewAddColumn(hwndListBroadcast, 1, "Source", 70)
	listViewAddColumn(hwndListBroadcast, 2, "Name", 220)
	listViewAddColumn(hwndListBroadcast, 3, "Type", 220)
	listViewAddColumn(hwndListBroadcast, 4, "Details", 500)

	// ---- health text area (hidden initially) ----
	hwndListHealth, _ = createWindowEx(
		WS_EX_CLIENTEDGE, "EDIT", healthPlaceholder,
		WS_CHILD|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
		0, listTop, 1160, 600, hwnd, 0, inst)

	// ---- status bar ----
	hwndStatus = createStatusWindow(hwnd, IDC_STATUS, "Ready — enter a target and click Scan")

	// Apply Segoe UI to every child control (labels, buttons, edits, listviews, tabs).
	appFont = createUIFont()
	setFontAllChildren(hwnd, appFont)
}

// createCtrl is a shorthand for plain child controls (STATIC, BUTTON).
func createCtrl(class, title string, style uint32, x, y, w, h int32, parent HWND, id uintptr, inst HINSTANCE) HWND {
	hwnd, _ := createWindowEx(0, class, title, style, x, y, w, h, parent, HMENU(id), inst)
	return hwnd
}

// ---------------------------------------------------------------------------
// Layout — resize all panes to fill the client area
// ---------------------------------------------------------------------------

func resizeControls(hwnd HWND, lParam uintptr) {
	width := loword(lParam)
	height := hiword(lParam)

	// Status bar resizes itself.
	sendMessage(hwndStatus, WM_SIZE, 0, lParam)
	statusR := getClientRect(hwndStatus)
	statusH := statusR.Bottom - statusR.Top

	moveWindow(hwndTabCtrl, 0, toolbarH, width, tabCtrlH)

	listTop := int32(toolbarH + tabCtrlH)
	listH := height - listTop - statusH
	if listH < 0 {
		listH = 0
	}
	moveWindow(hwndList, 0, listTop, width, listH)
	moveWindow(hwndListBroadcast, 0, listTop, width, listH)
	moveWindow(hwndListHealth, 0, listTop, width, listH)
}

// ---------------------------------------------------------------------------
// Scan start / stop
// ---------------------------------------------------------------------------

func startScan(hwnd HWND) {
	scanMu.Lock()
	if scanCancel != nil {
		scanMu.Unlock()
		return // already running
	}
	scanMu.Unlock()

	target := getWindowText(hwndTarget)
	if target == "" {
		messageBox(hwnd, "Enter a target IP or CIDR.", "net-sweep", 0)
		return
	}

	// WAN safety: warn if the target is not an RFC1918 / private range.
	if !sweep.IsPrivate(target) {
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

	// Prompt for elevation if needed — raw ARP sockets require admin on Windows.
	if !isElevated() {
		r := messageBox(hwnd,
			"net-sweep is not running as Administrator.\n"+
				"MAC addresses and vendor lookup require elevated privileges.\n\n"+
				"Relaunch as Administrator now?\n\n"+
				"(Choose No to scan anyway — hosts will be discovered but MACs will be missing.)",
			"Administrator Privileges Recommended",
			MB_YESNO|MB_ICONWARNING)
		if r == IDYES {
			if exe, err := os.Executable(); err == nil {
				shellExecute(0, "runas", exe, target, "", SW_SHOW)
			}
			postQuitMessage(0)
			return
		}
		// No → continue scan without elevation
	}

	// Expand target first so we can pre-populate the list.
	hosts, err := sweep.ExpandTarget(target)
	if err != nil {
		messageBox(hwnd, "Invalid target: "+err.Error(), "net-sweep", 0)
		return
	}

	scanMu.Lock()
	if scanCancel != nil { // re-check after the dialogs above
		scanMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	scanCancel = cancel
	scanMu.Unlock()

	// Reset display state.
	liveCount = 0
	pendingMu.Lock()
	pendingResults = pendingResults[:0]
	pendingMu.Unlock()

	sendMessage(hwndList, LVM_DELETEALLITEMS, 0, 0)
	sendMessage(hwndListBroadcast, LVM_DELETEALLITEMS, 0, 0)
	ipRowMap = make(map[string]int32, len(hosts))
	rowResultMap = make(map[int32]sweep.Result, len(hosts))

	// Pre-populate every IP with a "Pending" row so they appear in order.
	for _, ip := range hosts {
		ipStr := ip.String()
		row := listViewInsertPendingRow(hwndList, ipStr)
		ipRowMap[ipStr] = row
	}

	enableWindow(hwndScan, false)
	enableWindow(hwndStop, true)
	setStatus(fmt.Sprintf("Scanning %s… (%d hosts)", target, len(hosts)))

	appCfg, _, _ := config.Load()
	scanCfg := appCfg.ToSweepConfig()

	go func() {
		sc := sweep.NewScanner(scanCfg)
		ch, err := sc.Scan(ctx, target)
		if err != nil {
			postMessage(hwnd, WM_SCAN_COMPLETE, 0, 0)
			return
		}
		for r := range ch {
			pendingMu.Lock()
			idx := len(pendingResults)
			pendingResults = append(pendingResults, r)
			pendingMu.Unlock()
			postMessage(hwnd, WM_SCAN_RESULT, uintptr(idx), 0)
		}
		// Store stats pointer for the completion handler.
		pendingMu.Lock()
		lastStats = sc.Stats
		pendingMu.Unlock()
		postMessage(hwnd, WM_SCAN_COMPLETE, 0, 0)
	}()
}

func stopScan() {
	scanMu.Lock()
	defer scanMu.Unlock()
	if scanCancel != nil {
		scanCancel()
		scanCancel = nil
	}
}

// exportResults saves the current results to a JSON or CSV file via a Save dialog.
func exportResults(hwnd HWND, format string) {
	pendingMu.Lock()
	results := make([]sweep.Result, 0, len(pendingResults))
	for _, r := range pendingResults {
		if r.Alive {
			results = append(results, r)
		}
	}
	pendingMu.Unlock()

	if len(results) == 0 {
		messageBox(hwnd, "No results to export. Run a scan first.", "Export", 0)
		return
	}

	var title, defExt, filter, path string
	if format == "json" {
		title = "Export as JSON"
		defExt = "json"
		filter = "JSON files|*.json|All files|*.*|"
	} else {
		title = "Export as CSV"
		defExt = "csv"
		filter = "CSV files|*.csv|All files|*.*|"
	}

	path = getSaveFileName(hwnd, title, defExt, filter)
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
		err = sweep.WriteJSON(f, results)
	} else {
		err = sweep.WriteCSV(f, results)
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

const healthPlaceholder = "Run a scan to populate health statistics."

func setStatus(s string) {
	p, _ := syscall.UTF16PtrFromString(s)
	sendMessage(hwndStatus, SB_SETTEXT, 0, uintptr(unsafe.Pointer(p)))
}

// updateHealthTab fills the Health text area with stats from the last scan.
func updateHealthTab(stats sweep.ScanStats) {
	text := fmt.Sprintf(
		"net-sweep — Scan Health Report\r\n"+
			"══════════════════════════════════════════\r\n\r\n"+
			"  Packets sent         : %d\r\n"+
			"  Replies received     : %d\r\n"+
			"  Timeouts             : %d\r\n"+
			"  Average latency      : %.2f ms\r\n\r\n"+
			"  ARP cache anomalies  : %d\r\n"+
			"  DNS lookup failures  : %d\r\n\r\n"+
			"══════════════════════════════════════════\r\n"+
			"Notes:\r\n"+
			"  • ARP anomalies indicate an IP seen with different MACs\r\n"+
			"    in the ARP cache vs. the scan — possible duplicate IP or\r\n"+
			"    partial network change. Investigate with 'arp -a'.\r\n"+
			"  • DNS failures are normal on flat home/SMB networks that\r\n"+
			"    lack reverse PTR records.\r\n",
		stats.PacketsSent,
		stats.RepliesReceived,
		stats.Timeouts,
		stats.AvgLatencyMS(),
		stats.ARPAnomalies,
		stats.DNSFailures,
	)
	setWindowText(hwndListHealth, text)
}

// ---------------------------------------------------------------------------
// Right-click context menu for a host in the list
// ---------------------------------------------------------------------------

// portOpen returns true if port is in r.OpenPorts.
func portOpen(r sweep.Result, port int) bool {
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

// showHostContextMenu builds and tracks a context menu for the given Result at
// screen coordinates (x, y).
func showHostContextMenu(parent HWND, r sweep.Result, x, y int32) {
	ip := r.IP.String()

	menu := createPopupMenu()
	defer destroyMenu(menu)

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

	cmd := trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, x, y, parent)
	switch cmd {
	case IDM_CTX_OPEN_HTTP:
		shellExecute(parent, "open", "http://"+ip, "", "", SW_SHOW)
	case IDM_CTX_OPEN_HTTPS:
		shellExecute(parent, "open", "https://"+ip, "", "", SW_SHOW)
	case IDM_CTX_OPEN_SSH:
		shellExecute(parent, "open", "ssh://"+ip, "", "", SW_SHOW)
	case IDM_CTX_OPEN_RDP:
		shellExecute(parent, "open", "mstsc.exe", "/v:"+ip, "", SW_SHOW)
	case IDM_CTX_OPEN_FTP:
		shellExecute(parent, "open", "ftp://"+ip, "", "", SW_SHOW)
	case IDM_CTX_OPEN_TELNET:
		shellExecute(parent, "open", "telnet://"+ip, "", "", SW_SHOW)
	case IDM_CTX_OPEN_SMB:
		shellExecute(parent, "open", `\\`+ip, "", "", SW_SHOW)
	case IDM_CTX_PING:
		shellExecute(parent, "open", "cmd.exe",
			"/c ping "+ip+" && pause", "", SW_SHOW)
	case IDM_CTX_PING_CONT:
		shellExecute(parent, "open", "cmd.exe",
			"/k ping -t "+ip, "", SW_SHOW)
	}
}

