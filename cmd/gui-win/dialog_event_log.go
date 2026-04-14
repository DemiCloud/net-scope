//go:build windows

// dialog_event_log.go — Network Event Log viewer dialog.
//
// Opened via Tools > Network Event Log…
// Queries the Windows Event Log for network-relevant entries via the sensor
// service ("eventlog-snapshot" command). Requires elevation to read the
// Security log (Firewall drops); the System log sources work without it.
//
// Layout:
//   ┌──────────────────────────────────────────────────────────┐
//   │  Filter…                                                  │
//   ├──────────────────────────────────────────────────────────┤
//   │  Time              │ Source              │ ID   │ Level  │ Summary
//   │  …                                                        │
//   ├──────────────────────────────────────────────────────────┤
//   │  [Refresh]                                                │
//   └──────────────────────────────────────────────────────────┘

package guiwin

import (
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
	idEvtLogSearch  = 1800
	idEvtLogList    = 1801
	idEvtLogRefresh = 1802

	// Right-click context menu IDs.
	idEvtLogCopyTime    = 1810
	idEvtLogCopySource  = 1811
	idEvtLogCopyID      = 1812
	idEvtLogCopySummary = 1813
	idEvtLogCopyRow     = 1814
)

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

var (
	hwndEvtLogDlg         HWND
	hwndEvtLogList        HWND
	hwndEvtLogSearchEdit  HWND
	hwndEvtLogLoadingHint HWND
	hwndEvtLogRefreshBtn  HWND

	evtLogAllRows    []netinfo.EventLogEntry
	evtLogFilterText string
	evtLogLoading    bool
)

var evtLogColTitles = []string{"Time", "Source", "Event ID", "Level", "Summary"}

// ---------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------

var evtLogWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createEvtLogControls(HWND(hwnd))
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_COMMAND:
		switch loword(wParam) {
		case idEvtLogSearch:
			if hiword(wParam) == EN_CHANGE {
				evtLogFilterText = strings.ToLower(getWindowText(hwndEvtLogSearchEdit))
				evtLogRepopulate()
			}
		case idEvtLogRefresh:
			evtLogDialogRefresh()
		}
		return 0

	case WM_SIZE:
		resizeEvtLogControls(HWND(hwnd))
		return 0

	case WM_KEYDOWN:
		if wParam == VK_ESCAPE {
			closeEvtLogDialog()
		}
		return 0

	case WM_CLOSE:
		closeEvtLogDialog()
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

// ---------------------------------------------------------------------------
// Control creation / layout
// ---------------------------------------------------------------------------

const (
	evtPad      int32 = 8
	evtBtnH     int32 = 26
	evtFilterH  int32 = 24
	evtFilterGap int32 = 6
)

func createEvtLogControls(hwnd HWND) {
	inst := getModuleHandle()
	r := getClientRect(hwnd)
	cW, cH := r.Right, r.Bottom

	// Filter / search edit.
	srch, _ := createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,
		evtPad, evtPad, cW-evtPad*2, evtFilterH,
		hwnd, HMENU(idEvtLogSearch), inst)
	cueText := utf16("Filter\u2026")
	sendMessage(srch, EM_SETCUEBANNER, 1, uintptr(unsafe.Pointer(cueText)))
	hwndEvtLogSearchEdit = srch

	// ListView.
	listY := evtPad + evtFilterH + evtFilterGap
	listH := cH - listY - evtPad*2 - evtBtnH - evtFilterGap

	lv, _ := createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		evtPad, listY, cW-evtPad*2, listH,
		hwnd, HMENU(idEvtLogList), inst)
	sendMessage(lv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP)
	subclassListViewManaged(lv, evtLogColTitles, nil, nil, nil,
		func(hw HWND, row int32, pt POINT) {
			showEvtLogContextMenu(getParent(hw), row, pt)
		})
	widths := evtLogColWidths(cW - evtPad*2)
	for i, title := range evtLogColTitles {
		listViewAddColumn(lv, int32(i), title, widths[i])
	}
	hwndEvtLogList = lv

	// "Loading…" hint overlay.
	hintY := listY + listH/2 - 9
	hwndEvtLogLoadingHint, _ = createWindowEx(0, "STATIC", "Loading\u2026",
		WS_CHILD|WS_VISIBLE|SS_CENTER,
		evtPad, hintY, cW-evtPad*2, 18, hwnd, 0, inst)

	// Refresh button.
	btnY := cH - evtPad - evtBtnH
	hwndEvtLogRefreshBtn = makePushButton(hwnd, "Refresh", idEvtLogRefresh, evtPad, btnY, 80, evtBtnH)
}

func resizeEvtLogControls(hwnd HWND) {
	if hwndEvtLogList == 0 {
		return
	}
	r := getClientRect(hwnd)
	cW, cH := r.Right, r.Bottom

	listY := evtPad + evtFilterH + evtFilterGap
	listH := cH - listY - evtPad*2 - evtBtnH - evtFilterGap
	btnY := cH - evtPad - evtBtnH
	hintY := listY + listH/2 - 9

	setWindowPos(hwndEvtLogSearchEdit, 0, evtPad, evtPad, cW-evtPad*2, evtFilterH, SWP_NOZORDER|SWP_NOACTIVATE)
	setWindowPos(hwndEvtLogList, 0, evtPad, listY, cW-evtPad*2, listH, SWP_NOZORDER|SWP_NOACTIVATE)
	setWindowPos(hwndEvtLogLoadingHint, 0, evtPad, hintY, cW-evtPad*2, 18, SWP_NOZORDER|SWP_NOACTIVATE)

	widths := evtLogColWidths(cW - evtPad*2)
	for i, w := range widths {
		sendMessage(hwndEvtLogList, LVM_SETCOLUMNWIDTH, uintptr(i), uintptr(uint32(w)))
	}

	// Keep the Refresh button pinned to the bottom-left.
	setWindowPos(hwndEvtLogRefreshBtn, 0, evtPad, btnY, 80, evtBtnH, SWP_NOZORDER|SWP_NOACTIVATE)
}

func evtLogColWidths(total int32) []int32 {
	timeW    := int32(145)
	sourceW  := int32(220)
	idW      := int32(65)
	levelW   := int32(80)
	summaryW := total - timeW - sourceW - idW - levelW - 4
	if summaryW < 100 {
		summaryW = 100
	}
	return []int32{timeW, sourceW, idW, levelW, summaryW}
}

// ---------------------------------------------------------------------------
// Context menu
// ---------------------------------------------------------------------------

func showEvtLogContextMenu(parent HWND, row int32, pt POINT) {
	menu := createPopupMenu()
	defer destroyMenu(menu)

	mf := func() uint32 {
		if row < 0 {
			return MF_STRING | MF_GRAYED
		}
		return MF_STRING
	}

	appendMenu(menu, mf(), idEvtLogCopyTime, "Copy Time")
	appendMenu(menu, mf(), idEvtLogCopySource, "Copy Source")
	appendMenu(menu, mf(), idEvtLogCopyID, "Copy Event ID")
	appendMenu(menu, mf(), idEvtLogCopySummary, "Copy Summary")
	appendMenu(menu, mf(), idEvtLogCopyRow, "Copy Row")
	appendMenu(menu, MF_SEPARATOR, 0, "")
	appendCopyAsSubmenu(menu)

	cmd := trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, pt.X, pt.Y, parent)
	switch cmd {
	case idEvtLogCopyTime:
		copyToClipboard(parent, listViewSelectedText(hwndEvtLogList, 0))
	case idEvtLogCopySource:
		copyToClipboard(parent, listViewSelectedText(hwndEvtLogList, 1))
	case idEvtLogCopyID:
		copyToClipboard(parent, listViewSelectedText(hwndEvtLogList, 2))
	case idEvtLogCopySummary:
		copyToClipboard(parent, listViewSelectedText(hwndEvtLogList, 4))
	case idEvtLogCopyRow:
		if row >= 0 {
			copyToClipboard(parent, listViewGetRowTSV(hwndEvtLogList, row, int32(len(evtLogColTitles))))
		}
	default:
		rows := listViewGetSelectedRows(hwndEvtLogList)
		handleCopyAsCmd(parent, hwndEvtLogList, cmd, rows, int32(len(evtLogColTitles)), evtLogColTitles, nil)
	}
}

// ---------------------------------------------------------------------------
// Data helpers
// ---------------------------------------------------------------------------

// evtLogEntryMatchesFilter returns true when entry matches the active filter.
func evtLogEntryMatchesFilter(e netinfo.EventLogEntry, f string) bool {
	if f == "" {
		return true
	}
	return strings.Contains(strings.ToLower(e.Time), f) ||
		strings.Contains(strings.ToLower(e.Source), f) ||
		strings.Contains(strings.ToLower(e.Log), f) ||
		strings.Contains(strings.ToLower(e.Level), f) ||
		strings.Contains(strings.ToLower(e.Summary), f) ||
		strings.Contains(evtLogIDStr(e.EventID), f)
}

func evtLogIDStr(id uint32) string {
	if id == 0 {
		return "0"
	}
	buf := [10]byte{}
	pos := len(buf)
	for id > 0 {
		pos--
		buf[pos] = byte('0' + id%10)
		id /= 10
	}
	return string(buf[pos:])
}

// evtLogRepopulate re-renders the list view from evtLogAllRows using the
// current filter. Called whenever the filter text changes.
func evtLogRepopulate() {
	if hwndEvtLogList == 0 {
		return
	}
	sendMessage(hwndEvtLogList, LVM_DELETEALLITEMS, 0, 0)
	for _, e := range evtLogAllRows {
		if evtLogEntryMatchesFilter(e, evtLogFilterText) {
			evtLogAppendRow(e)
		}
	}
}

// evtLogAppendRow adds a single entry to the list view (no filter check —
// callers must pre-filter before calling).
func evtLogAppendRow(e netinfo.EventLogEntry) {
	// Format the timestamp: strip the 'T' and timezone for display brevity.
	ts := e.Time
	if len(ts) >= 19 {
		ts = ts[:10] + " " + ts[11:19]
	}
	listViewAppendRow(hwndEvtLogList, []string{
		ts,
		e.Source,
		evtLogIDStr(e.EventID),
		e.Level,
		e.Summary,
	})
}

// ---------------------------------------------------------------------------
// Public callbacks (called from ui.go WndProc handlers)
// ---------------------------------------------------------------------------

// evtLogDialogAddRow is called from the main WndProc for WM_EVT_SNAP_ENTRY.
func evtLogDialogAddRow(e netinfo.EventLogEntry) {
	if hwndEvtLogList == 0 {
		return
	}
	evtLogAllRows = append(evtLogAllRows, e)
	if evtLogEntryMatchesFilter(e, evtLogFilterText) {
		evtLogAppendRow(e)
	}
}

// evtLogDialogLoadingDone is called from the main WndProc for WM_EVT_SNAP_DONE.
func evtLogDialogLoadingDone() {
	evtLogLoading = false
	showWindow(hwndEvtLogLoadingHint, SW_HIDE)

	count := int32(sendMessage(hwndEvtLogList, LVM_GETITEMCOUNT, 0, 0))
	if count == 0 {
		setWindowText(hwndEvtLogLoadingHint, "No network events found in the last 24 hours.")
		showWindow(hwndEvtLogLoadingHint, SW_SHOW)
	}
}

// ---------------------------------------------------------------------------
// Dialog lifecycle
// ---------------------------------------------------------------------------

// evtLogDialogRefresh clears the list and re-requests the snapshot.
func evtLogDialogRefresh() {
	if hwndEvtLogList == 0 || evtLogLoading {
		return
	}
	evtLogAllRows = evtLogAllRows[:0]
	sendMessage(hwndEvtLogList, LVM_DELETEALLITEMS, 0, 0)

	showWindow(hwndEvtLogLoadingHint, SW_SHOW)
	setWindowText(hwndEvtLogLoadingHint, "Loading\u2026")
	evtLogLoading = true

	if !requestEventLogSnapshot() {
		setWindowText(hwndEvtLogLoadingHint, "Sensor service is not running.")
		evtLogLoading = false
	}
}

// showEvtLogDialog opens (or focuses) the Network Event Log dialog.
func showEvtLogDialog(parent HWND) {
	if hwndEvtLogDlg != 0 {
		setForegroundWindow(hwndEvtLogDlg)
		return
	}

	registerDialogClass("NetScopeEvtLog", evtLogWndProc)

	// Reset per-session state.
	evtLogAllRows = evtLogAllRows[:0]
	evtLogFilterText = ""
	evtLogLoading = false

	hwnd, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetScopeEvtLog",
		"Network Event Log",
		WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
		0, 0, 900, 520,
		parent, 0, getModuleHandle(),
	)
	if err != nil {
		showError(parent, ErrCreateWindow, "Cannot open event log dialog", "NetScope")
		return
	}

	centerWindowOver(hwnd, parent)
	setFontAllChildren(hwnd, appFont)
	showWindow(hwnd, SW_SHOW)
	updateWindow(hwnd)

	hwndEvtLogDlg = hwnd
	atomic.StoreUintptr(&hwndEvtLogDialogAtomic, uintptr(hwnd))

	// Kick off the initial load.
	evtLogDialogRefresh()
}

// closeEvtLogDialog destroys the dialog and resets state.
func closeEvtLogDialog() {
	if hwndEvtLogDlg == 0 {
		return
	}
	atomic.StoreUintptr(&hwndEvtLogDialogAtomic, 0)
	destroyWindow(hwndEvtLogDlg)
	hwndEvtLogDlg = 0
	hwndEvtLogList = 0
	hwndEvtLogSearchEdit = 0
	hwndEvtLogLoadingHint = 0
	hwndEvtLogRefreshBtn = 0
}
