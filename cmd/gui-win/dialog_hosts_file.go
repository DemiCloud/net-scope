//go:build windows

// dialog_hosts_file.go — System Hosts File editor dialog.
//
// Opened via Tools > Hosts File…
// Displays entries from the system hosts file (Windows: C:\Windows\System32\drivers\etc\hosts,
// Linux: /etc/hosts). Entries are fetched via the sensor service (hosts-snapshot command).
// Adding or removing entries requires an elevated sensor on most systems.
//
// Layout:
//   ┌──────────────────────────────────────────────────────────────┐
//   │  Filter…                                                      │
//   ├──────────────────────────────────────────────────────────────┤
//   │  IP Address         │ Hostnames                │ Comment      │
//   │  …                                                            │
//   ├──────────────────────────────────────────────────────────────┤
//   │  [Add Entry]                         [Refresh]               │
//   └──────────────────────────────────────────────────────────────┘

package guiwin

import (
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/demicloud/net-scope/internal/netinfo"
)

// ---------------------------------------------------------------------------
// Control IDs — hosts dialog
// ---------------------------------------------------------------------------

const (
	idHostsFilter  = 1800
	idHostsList    = 1801
	idHostsRefresh = 1802
	idHostsAdd     = 1803

	idHostsCopyIP       = 1810
	idHostsCopyHostname = 1811
	idHostsCopyRow      = 1812
	idHostsDeleteEntry  = 1813
)

// ---------------------------------------------------------------------------
// Control IDs — add-entry dialog
// ---------------------------------------------------------------------------

const (
	idAddHostIP       = 1820
	idAddHostNames    = 1821
	idAddHostOK       = 1822
	idAddHostCancel   = 1823
	idAddHostIPLabel  = 1824
	idAddHostHNLabel  = 1825
)

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

var (
	hwndHostsDlg         HWND
	hwndHostsList        HWND
	hwndHostsFilter      HWND
	hwndHostsLoadingHint HWND

	hostsAllRows    []netinfo.HostsEntry
	hostsFilterText string
)

var hostsFileColTitles = []string{"IP Address", "Hostnames", "Comment"}

var (
	hwndAddHostIP    HWND
	hwndAddHostNames HWND
)

// hostsAddResult holds the result of the add-entry dialog.
var hostsAddResult struct {
	ip        string
	hostnames []string
	ok        bool
}

// ---------------------------------------------------------------------------
// Hosts list window procedure
// ---------------------------------------------------------------------------

var hostsWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createHostsControls(HWND(hwnd))
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_COMMAND:
		switch loword(wParam) {
		case idHostsFilter:
			if hiword(wParam) == EN_CHANGE {
				hostsFilterText = strings.ToLower(getWindowText(hwndHostsFilter))
				hostsRepopulate()
			}
		case idHostsRefresh:
			houstsDialogRefresh()
		case idHostsAdd:
			showAddHostEntryDialog(HWND(hwnd))
		}
		return 0

	case WM_SIZE:
		resizeHostsControls(HWND(hwnd))
		return 0

	case WM_KEYDOWN:
		if wParam == VK_ESCAPE {
			closeHostsDialog()
		}
		return 0

	case WM_CLOSE:
		closeHostsDialog()
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

// ---------------------------------------------------------------------------
// Control creation / layout
// ---------------------------------------------------------------------------

const (
	hostsPad      int32 = 8
	hostsBtnH     int32 = 26
	hostsFilterH  int32 = 24
	hostsFilterGap int32 = 6
)

func createHostsControls(hwnd HWND) {
	inst := getModuleHandle()
	r := getClientRect(hwnd)
	cW, cH := r.Right, r.Bottom

	filt, _ := createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,
		hostsPad, hostsPad, cW-hostsPad*2, hostsFilterH, hwnd, HMENU(idHostsFilter), inst)
	cueText := utf16("Filter\u2026")
	sendMessage(filt, EM_SETCUEBANNER, 1, uintptr(unsafe.Pointer(cueText)))
	hwndHostsFilter = filt

	listY := hostsPad + hostsFilterH + hostsFilterGap
	listH := hostsListHeight(cH)

	lv, _ := createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		hostsPad, listY, cW-hostsPad*2, listH, hwnd, HMENU(idHostsList), inst)
	sendMessage(lv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP)

	widths := hostsColWidths(cW - hostsPad*2)
	subclassListViewManaged(lv, hostsFileColTitles, nil, nil, nil, func(hw HWND, row int32, pt POINT) {
		showHostsContextMenu(getParent(hw), row, pt)
	})
	for i, title := range hostsFileColTitles {
		listViewAddColumn(lv, int32(i), title, widths[i])
	}
	hwndHostsList = lv

	hintY := listY + listH/2 - 9
	hwndHostsLoadingHint, _ = createWindowEx(0, "STATIC", "Loading\u2026",
		WS_CHILD|WS_VISIBLE|SS_CENTER,
		hostsPad, hintY, cW-hostsPad*2, 18, hwnd, 0, inst)

	btnY := cH - hostsPad - hostsBtnH
	makePushButton(hwnd, "Add Entry\u2026", idHostsAdd, hostsPad, btnY, 90, hostsBtnH)
	makePushButton(hwnd, "Refresh", idHostsRefresh, cW-hostsPad-80, btnY, 80, hostsBtnH)
}

func resizeHostsControls(hwnd HWND) {
	if hwndHostsList == 0 {
		return
	}
	r := getClientRect(hwnd)
	cW, cH := r.Right, r.Bottom

	listY := hostsPad + hostsFilterH + hostsFilterGap
	listH := hostsListHeight(cH)

	setWindowPos(hwndHostsFilter, 0, hostsPad, hostsPad, cW-hostsPad*2, hostsFilterH, SWP_NOZORDER|SWP_NOACTIVATE)
	setWindowPos(hwndHostsList, 0, hostsPad, listY, cW-hostsPad*2, listH, SWP_NOZORDER|SWP_NOACTIVATE)

	widths := hostsColWidths(cW - hostsPad*2)
	for i, w := range widths {
		sendMessage(hwndHostsList, LVM_SETCOLUMNWIDTH, uintptr(i), uintptr(uint32(w)))
	}

	hintY := listY + listH/2 - 9
	setWindowPos(hwndHostsLoadingHint, 0, hostsPad, hintY, cW-hostsPad*2, 18, SWP_NOZORDER|SWP_NOACTIVATE)
}

func hostsListHeight(cH int32) int32 {
	h := cH - (hostsPad + hostsFilterH + hostsFilterGap) - hostsFilterGap - hostsBtnH - hostsPad
	if h < 40 {
		h = 40
	}
	return h
}

func hostsColWidths(total int32) []int32 {
	ipW := int32(130)
	commentW := int32(160)
	hnW := total - ipW - commentW - 4
	if hnW < 150 {
		hnW = 150
	}
	return []int32{ipW, hnW, commentW}
}

// ---------------------------------------------------------------------------
// Context menu
// ---------------------------------------------------------------------------

func showHostsContextMenu(parent HWND, row int32, pt POINT) {
	menu := createPopupMenu()
	defer destroyMenu(menu)

	hasSelection := row >= 0
	mf := menuFlagIfSelected(hasSelection)

	appendMenu(menu, mf(MF_STRING), idHostsCopyIP, "Copy IP")
	appendMenu(menu, mf(MF_STRING), idHostsCopyHostname, "Copy Hostnames")
	appendMenu(menu, mf(MF_STRING), idHostsCopyRow, "Copy Row")
	appendMenu(menu, MF_SEPARATOR, 0, "")
	appendCopyAsSubmenu(menu)
	appendMenu(menu, MF_SEPARATOR, 0, "")
	appendMenu(menu, mf(MF_STRING), idHostsDeleteEntry, "Delete Entry")

	cmd := trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, pt.X, pt.Y, parent)
	switch cmd {
	case idHostsCopyIP:
		copyToClipboard(parent, listViewSelectedText(hwndHostsList, 0))
	case idHostsCopyHostname:
		copyToClipboard(parent, listViewSelectedText(hwndHostsList, 1))
	case idHostsCopyRow:
		if row >= 0 {
			copyToClipboard(parent, listViewGetRowTSV(hwndHostsList, row, int32(len(hostsFileColTitles))))
		}
	case idHostsDeleteEntry:
		hostsDeleteSelected(parent)
	default:
		rows := listViewGetSelectedRows(hwndHostsList)
		handleCopyAsCmd(parent, hwndHostsList, cmd, rows, int32(len(hostsFileColTitles)), hostsFileColTitles, nil)
	}
}

// ---------------------------------------------------------------------------
// Delete helpers
// ---------------------------------------------------------------------------

// hostsEntryTarget builds the "IP\thostname1 hostname2..." key used by
// requestHostsDelete to identify a hosts file line.
func hostsEntryTarget(e netinfo.HostsEntry) string {
	return e.IP + "\t" + strings.Join(e.Hostnames, " ")
}

// hostsDeleteSelected deletes all selected list rows.
func hostsDeleteSelected(parent HWND) {
	if !serviceRunning() {
		showInfo(parent, "The sensor service is not running.\n\nStart the sensor from the toolbar and try again.", "Hosts File")
		return
	}
	rows := listViewGetSelectedRows(hwndHostsList)
	if len(rows) == 0 {
		return
	}
	noun := "entry"
	if len(rows) > 1 {
		noun = "entries"
	}
	if !confirmDestructive(parent,
		"Delete the selected hosts file "+noun+"?\n\nThis requires an elevated sensor; the operation may fail if the sensor is not running as administrator.",
		"Hosts File") {
		return
	}
	for _, r := range rows {
		// Reconstruct the target from the list display (fallback to looking
		// up in hostsAllRows for the exact hostnames list).
		ip := listViewGetCellText(hwndHostsList, r, 0)
		hn := listViewGetCellText(hwndHostsList, r, 1)
		target := ip + "\t" + hn
		// Prefer the original entry from hostsAllRows for accurate matching.
		for _, e := range hostsAllRows {
			if e.IP == ip && strings.Join(e.Hostnames, " ") == hn {
				target = hostsEntryTarget(e)
				break
			}
		}
		requestHostsDelete(target)
	}
}

// ---------------------------------------------------------------------------
// Data population
// ---------------------------------------------------------------------------

// hostsDialogAddRow is called on the UI thread for each WM_HOSTS_SNAP_ENTRY.
func hostsDialogAddRow(e netinfo.HostsEntry) {
	hostsAllRows = append(hostsAllRows, e)
	if hostsFilterText != "" && !hostsEntryMatchesFilter(e, hostsFilterText) {
		return
	}
	hostsInsertRow(hwndHostsList, e)
}

// houstsDialogLoadingDone is called on WM_HOSTS_SNAP_DONE.
func houstsDialogLoadingDone() {
	if hwndHostsLoadingHint != 0 {
		showWindow(hwndHostsLoadingHint, SW_HIDE)
	}
}

// houstsDialogRefresh clears the list and requests a new snapshot.
func houstsDialogRefresh() {
	if hwndHostsList != 0 {
		sendMessage(hwndHostsList, LVM_DELETEALLITEMS, 0, 0)
	}
	if hwndHostsLoadingHint != 0 {
		showWindow(hwndHostsLoadingHint, SW_SHOW)
	}
	hostsAllRows = nil
	requestHostsSnapshot()
}

func hostsRepopulate() {
	sendMessage(hwndHostsList, LVM_DELETEALLITEMS, 0, 0)
	for _, e := range hostsAllRows {
		if hostsFilterText != "" && !hostsEntryMatchesFilter(e, hostsFilterText) {
			continue
		}
		hostsInsertRow(hwndHostsList, e)
	}
}

func hostsInsertRow(lv HWND, e netinfo.HostsEntry) {
	listViewAppendRow(lv, []string{e.IP, strings.Join(e.Hostnames, " "), e.Comment})
}

func hostsEntryMatchesFilter(e netinfo.HostsEntry, f string) bool {
	return strings.Contains(strings.ToLower(e.IP), f) ||
		strings.Contains(strings.ToLower(strings.Join(e.Hostnames, " ")), f) ||
		strings.Contains(strings.ToLower(e.Comment), f)
}

// ---------------------------------------------------------------------------
// Add-entry dialog
// ---------------------------------------------------------------------------

var addHostWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createAddHostControls(HWND(hwnd))
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_COMMAND:
		switch loword(wParam) {
		case idAddHostOK:
			ip := strings.TrimSpace(getWindowText(hwndAddHostIP))
			parts := strings.Fields(getWindowText(hwndAddHostNames))
			if ip == "" || len(parts) == 0 {
				showInfo(HWND(hwnd), "Enter an IP address and at least one hostname.", "Add Entry")
				return 0
			}
			hostsAddResult.ip = ip
			hostsAddResult.hostnames = parts
			hostsAddResult.ok = true
			closeModal(HWND(hwnd))
		case idAddHostCancel:
			hostsAddResult.ok = false
			closeModal(HWND(hwnd))
		}
		return 0

	case WM_CLOSE:
		hostsAddResult.ok = false
		closeModal(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

func createAddHostControls(hwnd HWND) {
	inst := getModuleHandle()
	r := getClientRect(hwnd)
	cW := r.Right

	const pad int32 = 10
	const labelH int32 = 16
	const editH int32 = 22
	const gap int32 = 4
	const btnH int32 = 26
	const btnW int32 = 80

	y := pad

	// IP label + edit
	createWindowEx(0, "STATIC", "IP Address:",
		WS_CHILD|WS_VISIBLE|SS_LEFT,
		pad, y, cW-pad*2, labelH, hwnd, HMENU(idAddHostIPLabel), inst)
	y += labelH + 2
	ipEd, _ := createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,
		pad, y, cW-pad*2, editH, hwnd, HMENU(idAddHostIP), inst)
	hwndAddHostIP = ipEd
	y += editH + gap + 4

	// Hostnames label + edit
	createWindowEx(0, "STATIC", "Hostnames (space-separated):",
		WS_CHILD|WS_VISIBLE|SS_LEFT,
		pad, y, cW-pad*2, labelH, hwnd, HMENU(idAddHostHNLabel), inst)
	y += labelH + 2
	hnEd, _ := createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,
		pad, y, cW-pad*2, editH, hwnd, HMENU(idAddHostNames), inst)
	hwndAddHostNames = hnEd
	y += editH + gap + 8

	// OK / Cancel
	makePushButton(hwnd, "OK", idAddHostOK, cW-pad-btnW*2-8, y, btnW, btnH)
	makePushButton(hwnd, "Cancel", idAddHostCancel, cW-pad-btnW, y, btnW, btnH)
}

// showAddHostEntryDialog shows a modal dialog to collect IP + hostnames, then
// sends a hosts-add request to the sensor service.
func showAddHostEntryDialog(parent HWND) {
	if !serviceRunning() {
		showInfo(parent, "The sensor service is not running.\n\nStart the sensor from the toolbar and try again.", "Hosts File")
		return
	}

	hostsAddResult.ok = false
	hostsAddResult.ip = ""
	hostsAddResult.hostnames = nil

	registerDialogClass("NetScopeAddHost", addHostWndProc)
	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetScopeAddHost", "Add Hosts Entry",
		WS_POPUP|WS_CAPTION|WS_SYSMENU|WS_CLIPCHILDREN,
		0, 0, 340, 165,
		parent, 0, getModuleHandle(),
	)
	if err != nil || dlg == 0 {
		return
	}
	centerWindowOver(dlg, parent)
	setFontAllChildren(dlg, appFont)
	showWindow(dlg, SW_SHOW)
	updateWindow(dlg)
	runModal(dlg, parent)

	if !hostsAddResult.ok {
		return
	}
	if !requestHostsAdd(hostsAddResult.ip, hostsAddResult.hostnames) {
		showError(parent, ErrSendCommand, "Failed to send command to sensor service.", "Hosts File")
	}
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

// showHostsDialog opens (or focuses) the modeless Hosts File dialog.
func showHostsDialog(parent HWND) {
	if hwndHostsDlg != 0 {
		setForegroundWindow(hwndHostsDlg)
		return
	}

	hostsAllRows = nil
	hostsFilterText = ""

	registerDialogClass("NetScopeHosts", hostsWndProc)

	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetScopeHosts", "Hosts File",
		WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
		0, 0, 680, 420,
		parent, 0, getModuleHandle(),
	)
	if err != nil || dlg == 0 {
		return
	}
	centerWindowOver(dlg, parent)
	setFontAllChildren(dlg, appFont)
	showWindow(dlg, SW_SHOW)
	updateWindow(dlg)
	hwndHostsDlg = dlg
	atomic.StoreUintptr(&hwndHostsDialogAtomic, uintptr(dlg))

	if !requestHostsSnapshot() {
		showInfo(dlg,
			"The sensor service is not running.\n\nStart the sensor from the toolbar, then use Refresh.",
			"Hosts File")
	}
}

// closeHostsDialog tears down the Hosts File dialog.
func closeHostsDialog() {
	if hwndHostsDlg == 0 {
		return
	}
	atomic.StoreUintptr(&hwndHostsDialogAtomic, 0)
	destroyWindow(hwndHostsDlg)
	hwndHostsDlg = 0
	hwndHostsList = 0
	hwndHostsFilter = 0
	hwndHostsLoadingHint = 0
	hostsAllRows = nil
}
