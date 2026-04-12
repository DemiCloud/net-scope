//go:build windows

// dialog_connections.go — Active TCP/UDP Connections viewer dialog.
//
// Opened via Tools > Active Connections…
// Shows all open TCP and UDP sockets with PID and process name. Fetched from
// the sensor service via the "socket-snapshot" command (process names for
// system processes are more complete when the sensor is elevated).
//
// Layout:
//   ┌──────────────────────────────────────────────────────────────────────────┐
//   │  Filter…                                                                  │
//   ├──────────────────────────────────────────────────────────────────────────┤
//   │ Proto │ Local               │ Remote              │ State       │ PID │ Process │
//   │  …                                                                        │
//   ├──────────────────────────────────────────────────────────────────────────┤
//   │  [Refresh]                                                                │
//   └──────────────────────────────────────────────────────────────────────────┘

package guiwin

import (
	"fmt"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/demicloud/net-scope/internal/netinfo"
)

// ---------------------------------------------------------------------------
// Control IDs
// ---------------------------------------------------------------------------

const (
	idConnFilter   = 1700
	idConnList     = 1701
	idConnRefresh  = 1702

	idConnCopyLocal   = 1710
	idConnCopyRemote  = 1711
	idConnCopyProcess = 1712
	idConnCopyRow     = 1713
)

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

var (
	hwndConnDlg         HWND
	hwndConnList        HWND
	hwndConnFilter      HWND
	hwndConnLoadingHint HWND

	connAllRows    []netinfo.SocketEntry
	connFilterText string
)

var connColTitles = []string{"Proto", "Local", "Remote", "State", "PID", "Process"}

// ---------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------

var connWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createConnControls(HWND(hwnd))
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_COMMAND:
		switch loword(wParam) {
		case idConnFilter:
			if hiword(wParam) == EN_CHANGE {
				connFilterText = strings.ToLower(getWindowText(hwndConnFilter))
				connRepopulate()
			}
		case idConnRefresh:
			connDialogRefresh()
		}
		return 0

	case WM_SIZE:
		resizeConnControls(HWND(hwnd))
		return 0

	case WM_KEYDOWN:
		if wParam == VK_ESCAPE {
			closeConnectionsDialog()
		}
		return 0

	case WM_CLOSE:
		closeConnectionsDialog()
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

// ---------------------------------------------------------------------------
// Control creation / layout
// ---------------------------------------------------------------------------

const (
	connPad      int32 = 8
	connBtnH     int32 = 26
	connFilterH  int32 = 24
	connFilterGap int32 = 6
)

func createConnControls(hwnd HWND) {
	inst := getModuleHandle()
	r := getClientRect(hwnd)
	cW, cH := r.Right, r.Bottom

	filt, _ := createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,
		connPad, connPad, cW-connPad*2, connFilterH, hwnd, HMENU(idConnFilter), inst)
	cueText := utf16("Filter\u2026")
	sendMessage(filt, EM_SETCUEBANNER, 1, uintptr(unsafe.Pointer(cueText)))
	hwndConnFilter = filt

	listY := connPad + connFilterH + connFilterGap
	listH := connListHeight(cH)

	lv, _ := createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		connPad, listY, cW-connPad*2, listH, hwnd, HMENU(idConnList), inst)
	sendMessage(lv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP)

	widths := connColWidths(cW - connPad*2)
	subclassListViewManaged(lv, connColTitles, nil, nil, nil, func(hw HWND, row int32, pt POINT) {
		showConnContextMenu(getParent(hw), row, pt)
	})
	for i, title := range connColTitles {
		listViewAddColumn(lv, int32(i), title, widths[i])
	}
	hwndConnList = lv

	hintY := listY + listH/2 - 9
	hwndConnLoadingHint, _ = createWindowEx(0, "STATIC", "Loading\u2026",
		WS_CHILD|WS_VISIBLE|SS_CENTER,
		connPad, hintY, cW-connPad*2, 18, hwnd, 0, inst)

	btnY := cH - connPad - connBtnH
	makePushButton(hwnd, "Refresh", idConnRefresh, connPad, btnY, 80, connBtnH)
}

func resizeConnControls(hwnd HWND) {
	if hwndConnList == 0 {
		return
	}
	r := getClientRect(hwnd)
	cW, cH := r.Right, r.Bottom

	listY := connPad + connFilterH + connFilterGap
	listH := connListHeight(cH)

	setWindowPos(hwndConnFilter, 0, connPad, connPad, cW-connPad*2, connFilterH, SWP_NOZORDER|SWP_NOACTIVATE)
	setWindowPos(hwndConnList, 0, connPad, listY, cW-connPad*2, listH, SWP_NOZORDER|SWP_NOACTIVATE)

	widths := connColWidths(cW - connPad*2)
	for i, w := range widths {
		sendMessage(hwndConnList, LVM_SETCOLUMNWIDTH, uintptr(i), uintptr(uint32(w)))
	}

	hintY := listY + listH/2 - 9
	setWindowPos(hwndConnLoadingHint, 0, connPad, hintY, cW-connPad*2, 18, SWP_NOZORDER|SWP_NOACTIVATE)
}

func connListHeight(cH int32) int32 {
	h := cH - (connPad + connFilterH + connFilterGap) - connFilterGap - connBtnH - connPad
	if h < 40 {
		h = 40
	}
	return h
}

func connColWidths(total int32) []int32 {
	protoW := int32(50)
	stateW := int32(105)
	pidW := int32(55)
	localW := int32(165)
	remoteW := int32(165)
	processW := total - protoW - stateW - pidW - localW - remoteW - 4
	if processW < 80 {
		processW = 80
	}
	return []int32{protoW, localW, remoteW, stateW, pidW, processW}
}

// ---------------------------------------------------------------------------
// Context menu
// ---------------------------------------------------------------------------

func showConnContextMenu(parent HWND, row int32, pt POINT) {
	menu := createPopupMenu()
	defer destroyMenu(menu)

	hasSelection := row >= 0
	mf := menuFlagIfSelected(hasSelection)

	appendMenu(menu, mf(MF_STRING), idConnCopyLocal, "Copy Local")
	appendMenu(menu, mf(MF_STRING), idConnCopyRemote, "Copy Remote")
	appendMenu(menu, mf(MF_STRING), idConnCopyProcess, "Copy Process")
	appendMenu(menu, mf(MF_STRING), idConnCopyRow, "Copy Row")
	appendMenu(menu, MF_SEPARATOR, 0, "")
	appendCopyAsSubmenu(menu)

	cmd := trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, pt.X, pt.Y, parent)
	switch cmd {
	case idConnCopyLocal:
		copyToClipboard(parent, listViewSelectedText(hwndConnList, 1))
	case idConnCopyRemote:
		copyToClipboard(parent, listViewSelectedText(hwndConnList, 2))
	case idConnCopyProcess:
		copyToClipboard(parent, listViewSelectedText(hwndConnList, 5))
	case idConnCopyRow:
		if row >= 0 {
			copyToClipboard(parent, listViewGetRowTSV(hwndConnList, row, int32(len(connColTitles))))
		}
	default:
		rows := listViewGetSelectedRows(hwndConnList)
		handleCopyAsCmd(parent, hwndConnList, cmd, rows, int32(len(connColTitles)), connColTitles, nil)
	}
}

// ---------------------------------------------------------------------------
// Data population
// ---------------------------------------------------------------------------

// connDialogAddRow is called on the UI thread for each WM_SOCKET_SNAP_ENTRY.
func connDialogAddRow(e netinfo.SocketEntry) {
	connAllRows = append(connAllRows, e)
	if connFilterText != "" && !connEntryMatchesFilter(e, connFilterText) {
		return
	}
	connInsertRow(hwndConnList, e)
}

// connDialogLoadingDone is called on WM_SOCKET_SNAP_DONE.
func connDialogLoadingDone() {
	if hwndConnLoadingHint != 0 {
		showWindow(hwndConnLoadingHint, SW_HIDE)
	}
}

// connDialogRefresh clears the list and requests a new snapshot.
func connDialogRefresh() {
	if hwndConnList != 0 {
		sendMessage(hwndConnList, LVM_DELETEALLITEMS, 0, 0)
	}
	if hwndConnLoadingHint != 0 {
		showWindow(hwndConnLoadingHint, SW_SHOW)
	}
	connAllRows = nil
	requestSocketSnapshot()
}

func connRepopulate() {
	sendMessage(hwndConnList, LVM_DELETEALLITEMS, 0, 0)
	for _, e := range connAllRows {
		if connFilterText != "" && !connEntryMatchesFilter(e, connFilterText) {
			continue
		}
		connInsertRow(hwndConnList, e)
	}
}

func connInsertRow(lv HWND, e netinfo.SocketEntry) {
	local := connAddrStr(e.LocalAddr, e.LocalPort)
	remote := connAddrStr(e.RemoteAddr, e.RemotePort)
	pid := ""
	if e.PID != 0 {
		pid = fmt.Sprintf("%d", e.PID)
	}
	listViewAppendRow(lv, []string{e.Proto, local, remote, e.State, pid, e.Process})
}

func connAddrStr(addr string, port uint16) string {
	if addr == "" || port == 0 {
		return "\u2014" // em-dash for "not applicable"
	}
	// Wrap IPv6 addresses in brackets.
	if strings.ContainsRune(addr, ':') {
		return fmt.Sprintf("[%s]:%d", addr, port)
	}
	return fmt.Sprintf("%s:%d", addr, port)
}

func connEntryMatchesFilter(e netinfo.SocketEntry, f string) bool {
	local := strings.ToLower(connAddrStr(e.LocalAddr, e.LocalPort))
	remote := strings.ToLower(connAddrStr(e.RemoteAddr, e.RemotePort))
	return strings.Contains(strings.ToLower(e.Proto), f) ||
		strings.Contains(local, f) ||
		strings.Contains(remote, f) ||
		strings.Contains(strings.ToLower(e.State), f) ||
		strings.Contains(strings.ToLower(e.Process), f) ||
		strings.Contains(fmt.Sprintf("%d", e.PID), f)
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

// showConnectionsDialog opens (or focuses) the modeless Active Connections dialog.
func showConnectionsDialog(parent HWND) {
	if hwndConnDlg != 0 {
		setForegroundWindow(hwndConnDlg)
		return
	}

	connAllRows = nil
	connFilterText = ""

	registerDialogClass("NetScopeConnections", connWndProc)

	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetScopeConnections", "Active Connections",
		WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
		0, 0, 820, 480,
		parent, 0, getModuleHandle(),
	)
	if err != nil || dlg == 0 {
		return
	}
	centerWindowOver(dlg, parent)
	setFontAllChildren(dlg, appFont)
	showWindow(dlg, SW_SHOW)
	updateWindow(dlg)
	hwndConnDlg = dlg
	atomic.StoreUintptr(&hwndConnectionsDialogAtomic, uintptr(dlg))

	if !requestSocketSnapshot() {
		messageBox(dlg,
			"The sensor service is not running.\n\nStart or elevate the sensor from the toolbar, then use Refresh.",
			"Active Connections", MB_ICONINFORMATION)
	}
}

// closeConnectionsDialog tears down the Active Connections dialog.
func closeConnectionsDialog() {
	if hwndConnDlg == 0 {
		return
	}
	atomic.StoreUintptr(&hwndConnectionsDialogAtomic, 0)
	destroyWindow(hwndConnDlg)
	hwndConnDlg = 0
	hwndConnList = 0
	hwndConnFilter = 0
	hwndConnLoadingHint = 0
	connAllRows = nil
}
