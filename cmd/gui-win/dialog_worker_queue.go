//go:build windows

// dialog_worker_queue.go — Worker Queue dialog.
//
// Opened via Tools > Worker Queue…
// Shows a live list of every host in the current scan, its state
// (queued → running → done / dead), and a summary count.
//
// The dialog is non-modal (modeless): it stays open while scanning continues.
// It receives updates via workerQueueUpsert, called from the WM_WORK_UPDATE
// handler in ui.go.  The dialog closes itself on WM_CLOSE.

package guiwin

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"github.com/demicloud/net-scope/internal/scan"
)

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const (
	idWQList  = 801
	idWQClose = 802
)

var (
	hwndWorkerQueueDlg  HWND
	hwndWQList          HWND
	hwndWQSummary       HWND
	hwndWQClose         HWND

	wqMu      sync.Mutex
	wqItems   map[string]scan.WorkItemState // ip → current state

	wqRowByIP map[string]int32
	wqIPByRow map[int32]string
	wqNextRow int32
)

var wqWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createWQControls(HWND(hwnd))
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_COMMAND:
		if loword(wParam) == idWQClose {
			closeWorkerQueueDialog()
		}
		return 0

	case WM_SIZE:
		resizeWQControls(HWND(hwnd))
		return 0

	case WM_CLOSE:
		closeWorkerQueueDialog()
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

// createWQControls builds the child controls inside the worker queue dialog.
func createWQControls(hwnd HWND) {
	wqRowByIP = make(map[string]int32)
	wqIPByRow = make(map[int32]string)
	wqNextRow = 0

	inst := getModuleHandle()
	r := getClientRect(hwnd)
	cW, cH := r.Right, r.Bottom
	const pad int32 = 8

	// Summary label (top).
	hwndWQSummary, _ = createWindowEx(0, "STATIC", "No scan in progress.",
		WS_CHILD|WS_VISIBLE|SS_LEFT,
		pad, pad, cW-pad*2, 18, hwnd, 0, inst)

	// ListView (fills remaining space above close button).
	const btnH int32 = 28
	const btnPad int32 = 10
	listY := pad + 22
	listH := cH - listY - btnPad - btnH - pad
	hwndWQList, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		pad, listY, cW-pad*2, listH, hwnd, HMENU(idWQList), inst)
	sendMessage(hwndWQList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER)
	subclassListViewManaged(hwndWQList, []string{"IP", "State"}, nil, nil, nil, nil)
	colIPW := (cW - pad*2) * 2 / 5
	listViewAddColumn(hwndWQList, 0, "IP", colIPW)
	listViewAddColumn(hwndWQList, 1, "State", cW-pad*2-colIPW-4)

	// Close button.
	btnY := cH - btnPad - btnH
	btnX := cW - pad - 80
	hwndWQClose = makePushButton(hwnd, "Close", idWQClose, btnX, btnY, 80, btnH)
}

// resizeWQControls repositions controls after the dialog is resized.
func resizeWQControls(hwnd HWND) {
	if hwndWQList == 0 {
		return
	}
	r := getClientRect(hwnd)
	cW, cH := r.Right, r.Bottom
	const pad int32 = 8
	const btnH int32 = 28
	const btnPad int32 = 10

	listY := pad + 22
	listH := cH - listY - btnPad - btnH - pad

	setWindowPos(hwndWQSummary, 0, pad, pad, cW-pad*2, 18, SWP_NOZORDER|SWP_NOACTIVATE)
	setWindowPos(hwndWQList, 0, pad, listY, cW-pad*2, listH, SWP_NOZORDER|SWP_NOACTIVATE)

	btnX := cW - pad - 80
	btnY := cH - btnPad - btnH
	if hwndWQClose != 0 {
		setWindowPos(hwndWQClose, 0, btnX, btnY, 80, btnH, SWP_NOZORDER|SWP_NOACTIVATE)
	}
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

// showWorkerQueueDialog opens (or focuses) the modeless Worker Queue dialog.
func showWorkerQueueDialog(parent HWND) {
	if hwndWorkerQueueDlg != 0 {
		setForegroundWindow(hwndWorkerQueueDlg)
		return
	}

	wqMu.Lock()
	wqItems = make(map[string]scan.WorkItemState)
	wqMu.Unlock()

	registerDialogClass("NetScopeWorkerQueue", wqWndProc)
	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetScopeWorkerQueue", "Worker Queue",
		WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
		0, 0, 520, 480,
		parent, 0, getModuleHandle(),
	)
	if err != nil || dlg == 0 {
		return
	}
	centerWindowOver(dlg, parent)
	setFontAllChildren(dlg, appFont)
	showWindow(dlg, SW_SHOW)
	updateWindow(dlg)
	hwndWorkerQueueDlg = dlg

	// Replay any items already received.
	wqMu.Lock()
	snapshot := make(map[string]scan.WorkItemState, len(wqItems))
	for ip, state := range wqItems {
		snapshot[ip] = state
	}
	wqMu.Unlock()
	for ip, state := range snapshot {
		workerQueueApply(scan.WorkItem{IP: ip, State: state})
	}
	wqUpdateSummary()
}

// closeWorkerQueueDialog closes the modeless dialog.
func closeWorkerQueueDialog() {
	if hwndWorkerQueueDlg != 0 {
		destroyWindow(hwndWorkerQueueDlg)
		hwndWorkerQueueDlg = 0
		hwndWQList = 0
		hwndWQSummary = 0
		hwndWQClose = 0
		wqRowByIP = nil
		wqIPByRow = nil
		wqNextRow = 0
	}
}

// workerQueueUpsert is called on the UI thread (from WM_WORK_UPDATE) to
// apply a single work-item state transition to both the in-memory map and
// the open dialog (if visible).
func workerQueueUpsert(wi scan.WorkItem) {
	wqMu.Lock()
	if wqItems == nil {
		wqItems = make(map[string]scan.WorkItemState)
	}
	wqItems[wi.IP] = wi.State
	wqMu.Unlock()

	if hwndWorkerQueueDlg != 0 {
		workerQueueApply(wi)
		wqUpdateSummary()
	}
}

// workerQueueApply inserts or updates a single row in hwndWQList.
// Must be called on the UI thread.
func workerQueueApply(wi scan.WorkItem) {
	if hwndWQList == 0 {
		return
	}

	row, exists := wqRowByIP[wi.IP]
	if !exists {
		// Insert a new row.
		p := utf16(wi.IP)
		item := LVITEM{Mask: LVIF_TEXT, IItem: 0x7fffffff, PszText: p}
		row = int32(sendMessage(hwndWQList, LVM_INSERTITEM, 0, uintptr(unsafe.Pointer(&item))))
		if row < 0 {
			return
		}
		wqRowByIP[wi.IP] = row
		wqIPByRow[row] = wi.IP
		wqNextRow++
	} else {
		// Update the IP column in case it shifted (shouldn't, but be safe).
		setSubItem(hwndWQList, row, 0, wi.IP)
	}
	setSubItem(hwndWQList, row, 1, wqStateLabel(wi.State))
}

// wqUpdateSummary refreshes the summary label.
func wqUpdateSummary() {
	if hwndWQSummary == 0 {
		return
	}
	wqMu.Lock()
	total := len(wqItems)
	var queued, running, done, dead int
	for _, st := range wqItems {
		switch st {
		case scan.WorkQueued:
			queued++
		case scan.WorkRunning:
			running++
		case scan.WorkDone:
			done++
		case scan.WorkDead:
			dead++
		}
	}
	wqMu.Unlock()

	label := fmt.Sprintf("%d total  ·  %d queued  ·  %d running  ·  %d done  ·  %d no response",
		total, queued, running, done, dead)
	setWindowText(hwndWQSummary, label)
}

// wqStateLabel returns the display string for a WorkItemState.
func wqStateLabel(s scan.WorkItemState) string {
	switch s {
	case scan.WorkQueued:
		return "Queued"
	case scan.WorkRunning:
		return "Running"
	case scan.WorkDone:
		return "Done"
	case scan.WorkDead:
		return "No response"
	default:
		return string(s)
	}
}


