//go:build windows

// dialog_worker_queue.go — Background Workers dialog.
//
// Opened via Tools > Background Workers…
// Shows all background goroutines managed by the sensor service in two sections:
//
//   Service Workers — long-running workers (broadcast listener, DHCP capture,
//     ARP poll, PTR resolver, port scanner).  Always visible; updated via
//     workerStatusUpsert called from the WM_WORKER_STATUS handler in ui.go.
//
//   Scan Queue — per-host probe state transitions during an active scan
//     (queued → running → done / no response).  Updated via workerQueueUpsert
//     called from the WM_WORK_UPDATE handler in ui.go.
//
// The dialog is modeless: it stays open while scanning continues.
// It closes itself on WM_CLOSE.

package guiwin

import (
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/demicloud/net-scope/internal/scan"
)

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const (
	idWQWorkerList = 800
	idWQList       = 801
)

var (
	hwndWorkerQueueDlg HWND
	hwndWQWorkerList   HWND // top section: named service workers
	hwndWQList         HWND // bottom section: per-host scan queue
	hwndWQSummary      HWND

	// Named worker state — persists across dialog open/close; UI thread only.
	wqWorkerMu     sync.Mutex
	wqWorkerStatus map[string]scan.WorkerStatus // name → latest status
	wqWorkerOrder  []string                      // stable insertion order for display

	// Per-host scan queue state — persists across dialog open/close.
	wqMu    sync.Mutex
	wqItems map[string]scan.WorkItemState // ip → current state

	// Expiry queue — IPs scheduled for removal; written by AfterFunc goroutines,
	// read by the WM_WORK_EXPIRE handler on the UI thread.
	pendingExpiriesMu sync.Mutex
	pendingExpiries   []string

	// Dialog-local row maps — valid only while the dialog window is open.
	wqWorkerRowByName map[string]int32
	wqRowByIP         map[string]int32
	wqIPByRow         map[int32]string
)

// wqExpireDelay is how long a finished (Done / No response) item stays visible
// in the Scan Queue before being removed automatically.
const wqExpireDelay = 10 * time.Second

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

const (
	wqPad         int32 = 8
	wqLblH        int32 = 16
	wqWorkerListH int32 = 130 // fixed height for the Service Workers list (~5 rows)
	wqSumH        int32 = 18
)

// wqScanListTop returns the y-coordinate where the Scan Queue list starts.
func wqScanListTop() int32 {
	return wqPad + wqLblH + 2 + wqWorkerListH + 8 + wqLblH + 2
}

// ---------------------------------------------------------------------------
// WndProc
// ---------------------------------------------------------------------------

var wqWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createWQControls(HWND(hwnd))
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_KEYDOWN:
		if wParam == VK_ESCAPE {
			closeWorkerQueueDialog()
		}
		return 0

	case WM_COMMAND:
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

// ---------------------------------------------------------------------------
// Control creation / layout
// ---------------------------------------------------------------------------

func createWQControls(hwnd HWND) {
	wqWorkerRowByName = make(map[string]int32)
	wqRowByIP = make(map[string]int32)
	wqIPByRow = make(map[int32]string)

	inst := getModuleHandle()
	r := getClientRect(hwnd)
	cW, cH := r.Right, r.Bottom

	// ── Service Workers section ────────────────────────────────────────────
	y := wqPad
	createWindowEx(0, "STATIC", "Service Workers",
		WS_CHILD|WS_VISIBLE|SS_LEFT,
		wqPad, y, cW-wqPad*2, wqLblH, hwnd, 0, inst)
	y += wqLblH + 2

	hwndWQWorkerList, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VISIBLE|WS_BORDER|LVS_REPORT|LVS_SHOWSELALWAYS,
		wqPad, y, cW-wqPad*2, wqWorkerListH, hwnd, HMENU(idWQWorkerList), inst)
	sendMessage(hwndWQWorkerList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER)
	colW := cW - wqPad*2
	listViewAddColumn(hwndWQWorkerList, 0, "Worker", colW*2/5)
	listViewAddColumn(hwndWQWorkerList, 1, "Status", colW-colW*2/5-4)
	y += wqWorkerListH + 8

	// ── Scan Queue section ─────────────────────────────────────────────────
	createWindowEx(0, "STATIC", "Scan Queue",
		WS_CHILD|WS_VISIBLE|SS_LEFT,
		wqPad, y, cW-wqPad*2, wqLblH, hwnd, 0, inst)
	y += wqLblH + 2

	sumY := cH - wqPad - wqSumH
	listH := sumY - 4 - y
	if listH < 40 {
		listH = 40
	}

	hwndWQList, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		wqPad, y, cW-wqPad*2, listH, hwnd, HMENU(idWQList), inst)
	sendMessage(hwndWQList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER)
	listViewAddColumn(hwndWQList, 0, "IP", colW*2/5)
	listViewAddColumn(hwndWQList, 1, "State", colW-colW*2/5-4)

	// Summary label.
	hwndWQSummary, _ = createWindowEx(0, "STATIC", "No scan in progress.",
		WS_CHILD|WS_VISIBLE|SS_LEFT,
		wqPad, sumY, cW-wqPad*2, wqSumH, hwnd, 0, inst)
}

func resizeWQControls(hwnd HWND) {
	if hwndWQWorkerList == 0 {
		return
	}
	r := getClientRect(hwnd)
	cW, cH := r.Right, r.Bottom

	scanTop := wqScanListTop()
	sumY := cH - wqPad - wqSumH
	listH := sumY - 4 - scanTop
	if listH < 40 {
		listH = 40
	}

	setWindowPos(hwndWQWorkerList, 0,
		wqPad, wqPad+wqLblH+2, cW-wqPad*2, wqWorkerListH, SWP_NOZORDER|SWP_NOACTIVATE)
	setWindowPos(hwndWQList, 0,
		wqPad, scanTop, cW-wqPad*2, listH, SWP_NOZORDER|SWP_NOACTIVATE)
	setWindowPos(hwndWQSummary, 0,
		wqPad, sumY, cW-wqPad*2, wqSumH, SWP_NOZORDER|SWP_NOACTIVATE)
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

// showWorkerQueueDialog opens (or focuses) the modeless Background Workers dialog.
func showWorkerQueueDialog(parent HWND) {
	if hwndWorkerQueueDlg != 0 {
		setForegroundWindow(hwndWorkerQueueDlg)
		return
	}

	registerDialogClass("NetScopeWorkerQueue", wqWndProc)
	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetScopeWorkerQueue", "Background Workers",
		WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
		0, 0, 520, 520,
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

	// Replay named worker statuses received before the dialog opened.
	wqWorkerMu.Lock()
	workerSnap := make([]scan.WorkerStatus, 0, len(wqWorkerOrder))
	for _, name := range wqWorkerOrder {
		workerSnap = append(workerSnap, wqWorkerStatus[name])
	}
	wqWorkerMu.Unlock()
	for _, ws := range workerSnap {
		workerStatusApply(ws)
	}

	// Replay per-host scan queue items received before the dialog opened.
	wqMu.Lock()
	itemSnap := make(map[string]scan.WorkItemState, len(wqItems))
	for ip, state := range wqItems {
		itemSnap[ip] = state
	}
	wqMu.Unlock()
	for ip, state := range itemSnap {
		workerQueueApply(scan.WorkItem{IP: ip, State: state})
	}
	wqUpdateSummary()
}

// closeWorkerQueueDialog destroys the modeless dialog.
func closeWorkerQueueDialog() {
	if hwndWorkerQueueDlg != 0 {
		destroyWindow(hwndWorkerQueueDlg)
		hwndWorkerQueueDlg = 0
		hwndWQWorkerList = 0
		hwndWQList = 0
		hwndWQSummary = 0
		wqWorkerRowByName = nil
		wqRowByIP = nil
		wqIPByRow = nil
	}
}

// ---------------------------------------------------------------------------
// Named worker updates  (WM_WORKER_STATUS → workerStatusUpsert)
// ---------------------------------------------------------------------------

// workerStatusUpsert is called on the UI thread from the WM_WORKER_STATUS
// handler in ui.go.  It persists the status and updates the dialog if open.
func workerStatusUpsert(ws scan.WorkerStatus) {
	wqWorkerMu.Lock()
	if wqWorkerStatus == nil {
		wqWorkerStatus = make(map[string]scan.WorkerStatus)
	}
	if _, exists := wqWorkerStatus[ws.Name]; !exists {
		wqWorkerOrder = append(wqWorkerOrder, ws.Name)
	}
	wqWorkerStatus[ws.Name] = ws
	wqWorkerMu.Unlock()

	if hwndWorkerQueueDlg != 0 {
		workerStatusApply(ws)
	}
}

// workerStatusApply inserts or updates a row in hwndWQWorkerList.
// Must be called on the UI thread with the dialog open.
func workerStatusApply(ws scan.WorkerStatus) {
	if hwndWQWorkerList == 0 {
		return
	}
	row, exists := wqWorkerRowByName[ws.Name]
	if !exists {
		p := utf16(ws.Name)
		item := LVITEM{Mask: LVIF_TEXT, IItem: 0x7fffffff, PszText: p}
		row = int32(sendMessage(hwndWQWorkerList, LVM_INSERTITEM, 0, uintptr(unsafe.Pointer(&item))))
		if row < 0 {
			return
		}
		wqWorkerRowByName[ws.Name] = row
	}
	stateStr := "Idle"
	if ws.Running {
		stateStr = "Running"
	}
	if ws.Detail != "" {
		stateStr = stateStr + " — " + ws.Detail
	}
	setSubItem(hwndWQWorkerList, row, 0, ws.Name)
	setSubItem(hwndWQWorkerList, row, 1, stateStr)
}

// ---------------------------------------------------------------------------
// Per-host scan queue updates  (WM_WORK_UPDATE → workerQueueUpsert)
// ---------------------------------------------------------------------------

// workerQueueUpsert is called on the UI thread from the WM_WORK_UPDATE handler.
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

	// Schedule automatic removal for terminal states.
	if wi.State == scan.WorkDone || wi.State == scan.WorkDead {
		ip := wi.IP
		time.AfterFunc(wqExpireDelay, func() {
			pendingExpiriesMu.Lock()
			idx := len(pendingExpiries)
			pendingExpiries = append(pendingExpiries, ip)
			pendingExpiriesMu.Unlock()
			postMessage(hwndMain, WM_WORK_EXPIRE, uintptr(idx), 0)
		})
	}
}

// workerQueueExpire removes a finished item from the scan queue.
// Called on the UI thread from the WM_WORK_EXPIRE handler.
func workerQueueExpire(ip string) {
	wqMu.Lock()
	st, present := wqItems[ip]
	if present && (st == scan.WorkDone || st == scan.WorkDead) {
		delete(wqItems, ip)
	} else {
		// State changed (e.g. re-queued by a new scan) — leave it alone.
		present = false
	}
	wqMu.Unlock()

	if !present {
		return
	}

	if hwndWorkerQueueDlg != 0 && hwndWQList != 0 {
		row, exists := wqRowByIP[ip]
		if exists {
			sendMessage(hwndWQList, LVM_DELETEITEM, uintptr(row), 0)
			delete(wqRowByIP, ip)
			delete(wqIPByRow, row)
			// Renumber rows that shifted up after the deletion.
			for otherIP, otherRow := range wqRowByIP {
				if otherRow > row {
					wqRowByIP[otherIP] = otherRow - 1
					wqIPByRow[otherRow-1] = otherIP
					delete(wqIPByRow, otherRow)
				}
			}
		}
	}

	wqUpdateSummary()
}

// workerQueueApply inserts or updates a single row in hwndWQList.
// Must be called on the UI thread.
func workerQueueApply(wi scan.WorkItem) {
	if hwndWQList == 0 {
		return
	}
	row, exists := wqRowByIP[wi.IP]
	if !exists {
		p := utf16(wi.IP)
		item := LVITEM{Mask: LVIF_TEXT, IItem: 0x7fffffff, PszText: p}
		row = int32(sendMessage(hwndWQList, LVM_INSERTITEM, 0, uintptr(unsafe.Pointer(&item))))
		if row < 0 {
			return
		}
		wqRowByIP[wi.IP] = row
		wqIPByRow[row] = wi.IP
	}
	setSubItem(hwndWQList, row, 0, wi.IP)
	setSubItem(hwndWQList, row, 1, wqStateLabel(wi.State))
}

// wqUpdateSummary refreshes the scan-queue summary label.
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

	var label string
	if total == 0 {
		label = "No scan in progress."
	} else {
		label = fmt.Sprintf("%d total  ·  %d queued  ·  %d running  ·  %d done  ·  %d no response",
			total, queued, running, done, dead)
	}
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


