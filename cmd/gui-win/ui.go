//go:build windows

package guiwin

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/demicloud/net-sweep/internal/config"
	"github.com/demicloud/net-sweep/internal/sweep"
)

// ---------------------------------------------------------------------------
// Global UI handles / resources
// ---------------------------------------------------------------------------

var (
	appFont        HFONT // Segoe UI 9pt — shared by main window and all dialogs
	hwndMain       HWND
	// Elevation bar (top strip)
	hwndElevLabel  HWND // "Running as: User" / "Running as: Administrator"
	hwndElevButton HWND // "Relaunch as Administrator" (hidden when already elevated)
	// Scan bar (shown only when Hosts tab is active)
	hwndTarget     HWND
	hwndScan       HWND
	hwndStop       HWND
	hwndAdminCheck HWND // "Admin / ARP" checkbox
	// Content panes
	hwndList       HWND
	hwndListMDNS   HWND // mDNS tab
	hwndListSSDP   HWND // SSDP tab
	hwndListDHCP   HWND // DHCP tab (placeholder — elevation notice when not elevated)
	hwndListHealth HWND // Health tab
	hwndTabCtrl    HWND
	hwndStatus     HWND
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
// Background broadcast listener state
// ---------------------------------------------------------------------------

var (
	bcastCancel    context.CancelFunc
	bcastMu        sync.Mutex
	bcastCount     int // total services received since app start
	pendingBcast   []bcastEntry
	pendingBcastMu sync.Mutex
)

type bcastEntry struct {
	ip  string
	svc sweep.ServiceInfo
}

func startBroadcastListener() {
	bcastMu.Lock()
	defer bcastMu.Unlock()
	if bcastCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	bcastCancel = cancel
	go func() {
		bl, err := time.ParseDuration(appConfig.Scan.BroadcastListen)
		if err != nil || bl <= 0 {
			bl = 3 * time.Second
		}
		sweep.ListenBroadcast(ctx, bl, func(ip string, svc sweep.ServiceInfo) {
			pendingBcastMu.Lock()
			idx := len(pendingBcast)
			pendingBcast = append(pendingBcast, bcastEntry{ip, svc})
			pendingBcastMu.Unlock()
			postMessage(hwndMain, WM_BCAST_SVC, uintptr(idx), 0)
		})
	}()
}

func stopBroadcastListener() {
	bcastMu.Lock()
	defer bcastMu.Unlock()
	if bcastCancel != nil {
		bcastCancel()
		bcastCancel = nil
	}
}

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

const (
	toolbarH = 38 // legacy constant (kept for dialogs that reference it)
	elevBarH = 32 // elevation status strip at very top
	scanBarH = 36 // scan controls bar (shown only on Hosts tab)
	tabCtrlH = 26 // height of the tab row
)

// ---------------------------------------------------------------------------
// WndProc
// ---------------------------------------------------------------------------

var wndProcCallback = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createControls(HWND(hwnd))
		if noConfigFile {
			postMessage(HWND(hwnd), WM_FIRST_RUN, 0, 0)
		}
		startBroadcastListener()
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
			// Hide all panes first.
			showWindow(hwndList, SW_HIDE)
			showWindow(hwndListMDNS, SW_HIDE)
			showWindow(hwndListSSDP, SW_HIDE)
			showWindow(hwndListDHCP, SW_HIDE)
			showWindow(hwndListHealth, SW_HIDE)
			// Show/hide scan bar and reposition Hosts listview accordingly.
			// On Hosts tab the scan bar is visible and the list sits below it;
			// on all other tabs the list fills from just below the tab strip.
			if tab == 0 {
				showWindow(hwndTarget, SW_SHOW)
				showWindow(hwndScan, SW_SHOW)
				showWindow(hwndStop, SW_SHOW)
				showWindow(hwndAdminCheck, SW_SHOW)
				// Ensure Hosts list is repositioned to account for scan bar.
				r := getClientRect(hwndMain)
				statusR := getClientRect(hwndStatus)
				statusH := statusR.Bottom - statusR.Top
				hostsTop := int32(elevBarH + tabCtrlH + scanBarH)
				listH := (r.Bottom - r.Top) - hostsTop - statusH
				if listH < 0 {
					listH = 0
				}
				moveWindow(hwndList, 0, hostsTop, r.Right-r.Left, listH)
				showWindow(hwndList, SW_SHOW)
			} else {
				showWindow(hwndTarget, SW_HIDE)
				showWindow(hwndScan, SW_HIDE)
				showWindow(hwndStop, SW_HIDE)
				showWindow(hwndAdminCheck, SW_HIDE)
				switch tab {
				case 1:
					showWindow(hwndListMDNS, SW_SHOW)
				case 2:
					showWindow(hwndListSSDP, SW_SHOW)
				case 3:
					showWindow(hwndListDHCP, SW_SHOW)
				case 4:
					showWindow(hwndListHealth, SW_SHOW)
				}
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
		// Right-click on mDNS list → copy menu.
		if (hdr.IdFrom == IDC_LIST_MDNS || hdr.IdFrom == IDC_LIST_SSDP) && hdr.Code == NM_RCLICK {
			hwndSrc := hwndListMDNS
			numCols := int32(8)
			if hdr.IdFrom == IDC_LIST_SSDP {
				hwndSrc = hwndListSSDP
				numCols = 5
			}
			pt := getCursorPos()
			cpt := POINT{X: pt.X, Y: pt.Y}
			procScreenToClient.Call(uintptr(hwndSrc), uintptr(unsafe.Pointer(&cpt)))
			htInfo := LVHITTESTINFO{Pt: cpt}
			row := int32(sendMessage(hwndSrc, LVM_HITTEST, 0, uintptr(unsafe.Pointer(&htInfo))))
			if row >= 0 {
				menu := createPopupMenu()
				appendMenu(menu, MF_STRING, IDM_BCAST_COPY_IP, "Copy IP")
				appendMenu(menu, MF_STRING, IDM_BCAST_COPY_ROW, "Copy full row (tab-separated)")
				cmd := trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, pt.X, pt.Y, HWND(hwnd))
				destroyMenu(menu)
				switch cmd {
				case IDM_BCAST_COPY_IP:
					copyToClipboard(HWND(hwnd), listViewGetCellText(hwndSrc, row, 0))
				case IDM_BCAST_COPY_ROW:
					copyToClipboard(HWND(hwnd), listViewGetRowTSV(hwndSrc, row, numCols))
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
		case IDC_ELEV_BUTTON:
			// Relaunch the same binary with "runas" to get an elevated instance.
			exe, err := os.Executable()
			if err == nil {
				target := getWindowText(hwndTarget)
				args := "--gui"
				if target != "" {
					args = target
				}
				shellExecute(HWND(hwnd), "runas", exe, args, "", SW_SHOWNORMAL)
			}
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

	case WM_BCAST_SVC:
		pendingBcastMu.Lock()
		var e bcastEntry
		if int(wParam) < len(pendingBcast) {
			e = pendingBcast[int(wParam)]
		}
		pendingBcastMu.Unlock()
		if e.ip != "" {
			if e.svc.Source == "ssdp" {
				listViewAddSSDPRow(hwndListSSDP, e.ip, e.svc)
			} else {
				listViewAddMDNSRow(hwndListMDNS, e.ip, e.svc)
			}
			bcastCount++
			setStatusPart(1, fmt.Sprintf("Broadcast: %d service(s)", bcastCount))
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
				setStatusPart(0, fmt.Sprintf("Hosts: found %d", liveCount))
			}
		} else if r.Alive {
			// Broadcast-only or out-of-range host.
			row := listViewInsertPendingRow(hwndList, ipStr)
			ipRowMap[ipStr] = row
			listViewUpdateRow(hwndList, row, r)
			rowResultMap[row] = r
			liveCount++
			setStatusPart(0, fmt.Sprintf("Hosts: found %d", liveCount))
		}

		// Mirror any services to the appropriate broadcast tab.
		for _, svc := range r.Services {
			if svc.Source == "ssdp" {
				listViewAddSSDPRow(hwndListSSDP, ipStr, svc)
			} else {
				listViewAddMDNSRow(hwndListMDNS, ipStr, svc)
			}
		}
		return 0

	case WM_SCAN_COMPLETE:
		scanMu.Lock()
		scanCancel = nil
		scanMu.Unlock()
		enableWindow(hwndScan, true)
		enableWindow(hwndStop, false)
		setStatusPart(0, fmt.Sprintf("Hosts: %d found", liveCount))
		setStatusPart(2, "Scan complete")
		// Refresh health tab text.
		pendingMu.Lock()
		stats := lastStats
		pendingMu.Unlock()
		updateHealthTab(stats)
		return 0

	case WM_DESTROY:
		stopScan()
		stopBroadcastListener()
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
	elevated := isElevated()

	// ---- elevation status bar (top strip) ----
	// Shows current privilege level; offers relaunch button when not elevated.
	elevLabel := "⚠  Running as: User  —  Some features (ARP, ICMP, DHCP) require elevation."
	if elevated {
		elevLabel = "✔  Running as: Administrator  —  All features available."
	}
	hwndElevLabel, _ = createWindowEx(0, "STATIC", elevLabel,
		WS_CHILD|WS_VISIBLE|SS_LEFT|SS_CENTERIMAGE,
		8, 0, 900, elevBarH, hwnd, IDC_ELEV_LABEL, inst)
	if !elevated {
		hwndElevButton, _ = createWindowEx(0, "BUTTON", "Relaunch as Administrator",
			WS_CHILD|WS_VISIBLE|WS_TABSTOP,
			916, 3, 220, 26, hwnd, IDC_ELEV_BUTTON, inst)
	}

	// ---- tab control ----
	hwndTabCtrl, _ = createWindowEx(0, WC_TABCONTROL, "",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		0, elevBarH, 1160, tabCtrlH, hwnd, IDC_TABS, inst)
	insertTab(hwndTabCtrl, 0, "Hosts")
	insertTab(hwndTabCtrl, 1, "mDNS")
	insertTab(hwndTabCtrl, 2, "SSDP")
	insertTab(hwndTabCtrl, 3, "DHCP")
	insertTab(hwndTabCtrl, 4, "Health")

	// Scan bar sits below the tab strip; only visible when Hosts tab is active.
	scanBarY := int32(elevBarH + tabCtrlH)
	// [Target label] [target input ──────────────] [Scan] [Stop] [☐ Admin / ARP]
	createCtrl("STATIC", "Target:", WS_CHILD|WS_VISIBLE, 8, scanBarY+8, 48, 20, hwnd, 0, inst)
	hwndTarget, _ = createWindowEx(0, "EDIT", initialTarget,
		WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL|WS_TABSTOP,
		58, scanBarY+6, 620, 22, hwnd, IDC_TARGET, inst)
	hwndScan, _ = createWindowEx(0, "BUTTON", "Scan",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP, 688, scanBarY+5, 80, 24, hwnd, IDC_SCAN, inst)
	hwndStop, _ = createWindowEx(0, "BUTTON", "Stop",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP, 776, scanBarY+5, 80, 24, hwnd, IDC_STOP, inst)
	enableWindow(hwndStop, false)
	hwndAdminCheck, _ = createWindowEx(0, "BUTTON", "Admin / ARP",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX,
		868, scanBarY+7, 120, 20, hwnd, IDC_ADMIN, inst)
	if elevated {
		sendMessage(hwndAdminCheck, BM_SETCHECK, BST_CHECKED, 0)
	}

	// Hosts listview starts below the scan bar.
	hostsTop := int32(elevBarH + tabCtrlH + scanBarH)
	// All other panes start just below the tab strip (no scan bar).
	otherTop := int32(elevBarH + tabCtrlH)

	// ---- hosts listview (visible) ----
	hwndList, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_BORDER|LVS_REPORT|LVS_SHOWSELALWAYS,
		0, hostsTop, 1160, 600, hwnd, IDC_LIST, inst)
	sendMessage(hwndList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES|LVS_EX_DOUBLEBUFFER)
	listViewAddColumn(hwndList, colStatus,   "●",             40)
	listViewAddColumn(hwndList, colIP,       "IP Address",   120)
	listViewAddColumn(hwndList, colHost,     "Hostname",     160)
	listViewAddColumn(hwndList, colMAC,      "MAC",          145)
	listViewAddColumn(hwndList, colVendor,   "Vendor",       140)
	listViewAddColumn(hwndList, colOS,       "OS",            90)
	listViewAddColumn(hwndList, colLatency,  "Latency",       70)
	listViewAddColumn(hwndList, colPorts,    "Ports",        110)
	listViewAddColumn(hwndList, colBanner,   "Banners / SNMP", 300)
	listViewAddColumn(hwndList, colServices, "Services",     200)

	// ---- mDNS listview (hidden initially) ----
	hwndListMDNS, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VSCROLL|WS_BORDER|LVS_REPORT|LVS_SHOWSELALWAYS,
		0, otherTop, 1160, 600, hwnd, IDC_LIST_MDNS, inst)
	sendMessage(hwndListMDNS, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES|LVS_EX_DOUBLEBUFFER)
	listViewAddColumn(hwndListMDNS, 0, "IP",            120)
	listViewAddColumn(hwndListMDNS, 1, "Name",          200)
	listViewAddColumn(hwndListMDNS, 2, "Service Type",  180)
	listViewAddColumn(hwndListMDNS, 3, "Friendly Name", 170)
	listViewAddColumn(hwndListMDNS, 4, "Model",         140)
	listViewAddColumn(hwndListMDNS, 5, "Ver",            55)
	listViewAddColumn(hwndListMDNS, 6, "Status",         60)
	listViewAddColumn(hwndListMDNS, 7, "Extra",          220)

	// ---- SSDP listview (hidden initially) ----
	hwndListSSDP, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VSCROLL|WS_BORDER|LVS_REPORT|LVS_SHOWSELALWAYS,
		0, otherTop, 1160, 600, hwnd, IDC_LIST_SSDP, inst)
	sendMessage(hwndListSSDP, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES|LVS_EX_DOUBLEBUFFER)
	listViewAddColumn(hwndListSSDP, 0, "IP",          120)
	listViewAddColumn(hwndListSSDP, 1, "Name",        220)
	listViewAddColumn(hwndListSSDP, 2, "Device Type", 250)
	listViewAddColumn(hwndListSSDP, 3, "Location",    260)
	listViewAddColumn(hwndListSSDP, 4, "Server",      250)

	// ---- DHCP pane (hidden initially) ----
	// When not elevated: shows an elevation notice. When elevated: ready for
	// future passive DHCP capture (requires raw socket on UDP 67/68).
	dhcpText := "⚠  DHCP passive capture requires Administrator privileges.\n\n" +
		"Click \"Relaunch as Administrator\" at the top of the window to enable this feature."
	if elevated {
		dhcpText = "DHCP passive capture is not yet implemented.\n\n" +
			"This tab will show DHCP requests and leases observed on the network."
	}
	hwndListDHCP, _ = createWindowEx(
		WS_EX_CLIENTEDGE, "EDIT", dhcpText,
		WS_CHILD|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
		0, otherTop, 1160, 600, hwnd, IDC_LIST_DHCP, inst)

	// ---- health text area (hidden initially) ----
	hwndListHealth, _ = createWindowEx(
		WS_EX_CLIENTEDGE, "EDIT", healthPlaceholder,
		WS_CHILD|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
		0, otherTop, 1160, 600, hwnd, 0, inst)

	// ---- status bar — 3 parts: Hosts | Broadcast | Scan state ----
	hwndStatus = createStatusWindow(hwnd, IDC_STATUS, "")
	// Parts: first two fixed-width, last part fills the remainder (-1).
	// We set widths after the window is shown (resizeControls will re-set them),
	// but initialise now so text is visible immediately.
	setStatusParts(400, 650)
	setStatusPart(0, "Ready")
	setStatusPart(1, "Broadcast: listening…")
	setStatusPart(2, "Enter a target and click Scan")

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

	// Status bar resizes itself; then recompute part boundaries.
	sendMessage(hwndStatus, WM_SIZE, 0, lParam)
	statusR := getClientRect(hwndStatus)
	statusH := statusR.Bottom - statusR.Top
	p1 := width / 3
	p2 := p1 * 2
	setStatusParts(p1, p2)

	// Elevation bar and tab strip always stretch to full width.
	moveWindow(hwndElevLabel, 8, 0, width-240, elevBarH)
	if hwndElevButton != 0 {
		moveWindow(hwndElevButton, width-236, 3, 228, 26)
	}
	moveWindow(hwndTabCtrl, 0, elevBarH, width, tabCtrlH)

	// Scan bar controls are repositioned to match current width (target field stretches).
	scanBarY := int32(elevBarH + tabCtrlH)
	moveWindow(hwndTarget, 58, scanBarY+6, width-548, 22)
	moveWindow(hwndScan, width-486, scanBarY+5, 80, 24)
	moveWindow(hwndStop, width-398, scanBarY+5, 80, 24)
	moveWindow(hwndAdminCheck, width-310, scanBarY+7, 120, 20)

	// Hosts tab: list sits below the scan bar.
	hostsTop := int32(elevBarH + tabCtrlH + scanBarH)
	hostsH := height - hostsTop - statusH
	if hostsH < 0 {
		hostsH = 0
	}
	moveWindow(hwndList, 0, hostsTop, width, hostsH)

	// All other panes fill from just below the tab strip.
	otherTop := int32(elevBarH + tabCtrlH)
	otherH := height - otherTop - statusH
	if otherH < 0 {
		otherH = 0
	}
	moveWindow(hwndListMDNS, 0, otherTop, width, otherH)
	moveWindow(hwndListSSDP, 0, otherTop, width, otherH)
	moveWindow(hwndListDHCP, 0, otherTop, width, otherH)
	moveWindow(hwndListHealth, 0, otherTop, width, otherH)
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

	// Read the Admin / ARP checkbox — tells us whether to use raw sockets.
	wantAdmin := sendMessage(hwndAdminCheck, BM_GETCHECK, 0, 0) == BST_CHECKED
	elevated := isElevated()

	appCfg, _, _ := config.Load()
	scanCfg := appCfg.ToSweepConfig()
	// The GUI has a persistent background broadcast listener (startBroadcastListener);
	// disable the per-scan mDNS/SSDP goroutines to avoid a 5-second wait.
	scanCfg.BroadcastListen = 0

	if !wantAdmin {
		// Non-admin mode: TCP connect as liveness probe; no raw sockets needed.
		scanCfg.Interface = ""
		scanCfg.TCPFirst = true
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
	// Do NOT clear hwndListBroadcast — the background listener populates it
	// continuously; scan-discovered services are appended, not a fresh set.
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
	setStatusPart(2, statusForMode(wantAdmin, elevated))

	// If admin probes are requested but we're not elevated, delegate to an
	// elevated subprocess rather than relaunching the whole GUI.
	if wantAdmin && !elevated {
		startElevatedScan(hwnd, target, scanCfg)
		return
	}

	go func() {
		defer func() {
			if p := recover(); p != nil {
				writeCrashLog(hwnd, p)
				postMessage(hwnd, WM_SCAN_COMPLETE, 0, 0)
			}
		}()
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

// setStatusParts sets the right-edge pixel positions for the three status bar
// parts. Pass p1, p2 as the right edge of part 0 and part 1; part 2 fills
// the remainder (represented as -1).
func setStatusParts(p1, p2 int32) {
	parts := [3]int32{p1, p2, -1}
	sendMessage(hwndStatus, SB_SETPARTS, 3, uintptr(unsafe.Pointer(&parts[0])))
}

// setStatusPart sets the text of one status bar part (0=Hosts, 1=Broadcast, 2=State).
func setStatusPart(part uintptr, s string) {
	p, _ := syscall.UTF16PtrFromString(s)
	sendMessage(hwndStatus, SB_SETTEXT, part, uintptr(unsafe.Pointer(p)))
}

// setStatus is a convenience wrapper that updates the rightmost (state) part.
func setStatus(s string) { setStatusPart(2, s) }

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
	appendMenu(menu, MF_SEPARATOR, 0, "")

	// ── Copy ─────────────────────────────────────────────────────────────────
	hCopy := createPopupMenu()
	menuItem(hCopy, IDM_CTX_COPY_IP,   "IP address",       r.IP != nil)
	menuItem(hCopy, IDM_CTX_COPY_MAC,  "MAC address",      r.MAC != nil)
	menuItem(hCopy, IDM_CTX_COPY_HOST, "Hostname",         r.Hostname != "")
	menuItem(hCopy, IDM_CTX_COPY_ROW,  "Full row (tab-separated)", true)
	appendMenu(menu, MF_POPUP, uintptr(hCopy), "Copy")

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
	case IDM_CTX_COPY_IP:
		copyToClipboard(parent, ip)
	case IDM_CTX_COPY_MAC:
		if r.MAC != nil {
			copyToClipboard(parent, r.MAC.String())
		}
	case IDM_CTX_COPY_HOST:
		copyToClipboard(parent, r.Hostname)
	case IDM_CTX_COPY_ROW:
		ports := ""
		for i, p := range r.OpenPorts {
			if i > 0 {
				ports += ","
			}
			ports += fmt.Sprintf("%d", p)
		}
		mac := ""
		if r.MAC != nil {
			mac = r.MAC.String()
		}
		copyToClipboard(parent, strings.Join([]string{
			ip, r.Hostname, mac, r.Vendor, string(r.OS), ports,
		}, "\t"))
	}
}

