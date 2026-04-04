//go:build windows

package main

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

	// ipRowMap maps IP string → row index in hwndList.
	// Written on the UI thread (startScan), read on the UI thread (WM_SCAN_RESULT).
	ipRowMap map[string]int32
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
			if tab == 0 {
				showWindow(hwndList, SW_SHOW)
				showWindow(hwndListBroadcast, SW_HIDE)
			} else {
				showWindow(hwndList, SW_HIDE)
				showWindow(hwndListBroadcast, SW_SHOW)
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
		case IDM_OPT_SETTINGS:
			showSettingsDialog(HWND(hwnd))
		case IDM_HELP_FAQ:
			showFAQDialog(HWND(hwnd))
		case IDM_HELP_ABOUT:
			messageBox(HWND(hwnd),
				"net-sweep\nFast LAN scanner.\n\nhttps://github.com/demicloud/net-sweep",
				"About net-sweep", 0)
		}
		return 0

	case WM_SCAN_RESULT:
		pendingMu.Lock()
		r := pendingResults[int(wParam)]
		pendingMu.Unlock()

		ipStr := r.IP.String()
		if row, found := ipRowMap[ipStr]; found {
			listViewUpdateRow(hwndList, row, r)
			if r.Alive {
				liveCount++
				setStatus(fmt.Sprintf("Found %d host(s)…", liveCount))
			}
		} else if r.Alive {
			// Broadcast-only or out-of-range host.
			row := listViewInsertPendingRow(hwndList, ipStr)
			ipRowMap[ipStr] = row
			listViewUpdateRow(hwndList, row, r)
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

	listTop := int32(toolbarH + tabCtrlH)

	// ---- hosts listview (visible) ----
	hwndList, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_BORDER|LVS_REPORT|LVS_SHOWSELALWAYS,
		0, listTop, 1160, 600, hwnd, IDC_LIST, inst)
	sendMessage(hwndList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES|LVS_EX_DOUBLEBUFFER)

	listViewAddColumn(hwndList, 0, "Status", 55)
	listViewAddColumn(hwndList, 1, "IP Address", 120)
	listViewAddColumn(hwndList, 2, "Hostname", 160)
	listViewAddColumn(hwndList, 3, "MAC", 145)
	listViewAddColumn(hwndList, 4, "Vendor", 155)
	listViewAddColumn(hwndList, 5, "Ports", 110)
	listViewAddColumn(hwndList, 6, "SNMP / Model", 220)
	listViewAddColumn(hwndList, 7, "Services", 200)

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
		ch, err := sweep.NewScanner(scanCfg).Scan(ctx, target)
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func setStatus(s string) {
	p, _ := syscall.UTF16PtrFromString(s)
	sendMessage(hwndStatus, SB_SETTEXT, 0, uintptr(unsafe.Pointer(p)))
}
