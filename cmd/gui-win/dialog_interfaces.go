//go:build windows

// dialog_interfaces.go — Local Network Interfaces viewer dialog.
//
// Opened via Tools > Local Interfaces…
// Shows all local network interfaces with their addresses, MAC, gateway, MTU,
// state, and type.  Data is fetched from the sensor service via the
// "if-snapshot" command.
//
// Layout:
//   ┌──────────────────────────────────────────────────────────┐
//   │  Filter…                                                  │
//   ├──────────────────────────────────────────────────────────┤
//   │  Interface │ Type │ State │ MAC │ IPv4 │ IPv6 │ GW │ MTU │
//   │  …                                                        │
//   ├──────────────────────────────────────────────────────────┤
//   │  [Refresh]                                                │
//   └──────────────────────────────────────────────────────────┘

package guiwin

import (
	"fmt"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/demicloud/net-scope/internal/scan"
)

// ---------------------------------------------------------------------------
// Control IDs
// ---------------------------------------------------------------------------

const (
	idIfFilter  = 1700
	idIfList    = 1701
	idIfRefresh = 1702
)

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

var (
	hwndIfDlg         HWND
	hwndIfList        HWND
	hwndIfFilter      HWND
	hwndIfLoadingHint HWND

	// ifAllRows holds every entry from the last snapshot, enabling filter
	// rebuilds without a new round-trip.
	ifAllRows    []scan.InterfaceEntry
	ifFilterText string
)

var ifColTitles = []string{
	"Interface", "Type", "State", "MAC", "IPv4", "IPv6", "Gateway", "MTU",
}

// ---------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------

var ifDlgWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createIfControls(HWND(hwnd))
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_COMMAND:
		switch loword(wParam) {
		case idIfFilter:
			if hiword(wParam) == EN_CHANGE {
				ifFilterText = strings.ToLower(getWindowText(hwndIfFilter))
				ifRepopulate()
			}
		case idIfRefresh:
			ifDialogRefresh()
		case idIfList:
			// Passthrough — list-view notifications handled by subclass.
		}
		return 0

	case WM_SIZE:
		resizeIfControls(HWND(hwnd))
		return 0

	case WM_KEYDOWN:
		if wParam == VK_ESCAPE {
			closeIfDialog()
		}
		return 0

	case WM_CLOSE:
		closeIfDialog()
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

// ---------------------------------------------------------------------------
// Control creation / layout
// ---------------------------------------------------------------------------

const (
	ifPad       int32 = 8
	ifBtnH      int32 = 26
	ifFilterH   int32 = 24
	ifFilterGap int32 = 6
)

func createIfControls(hwnd HWND) {
	inst := getModuleHandle()
	r := getClientRect(hwnd)
	cW, cH := r.Right, r.Bottom

	// Filter edit.
	filt, _ := createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,
		ifPad, ifPad, cW-ifPad*2, ifFilterH, hwnd, HMENU(idIfFilter), inst)
	cueText := utf16("Filter\u2026")
	sendMessage(filt, EM_SETCUEBANNER, 1, uintptr(unsafe.Pointer(cueText)))
	hwndIfFilter = filt

	listY := ifPad + ifFilterH + ifFilterGap
	listH := ifListHeight(cH)

	lv, _ := createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		ifPad, listY, cW-ifPad*2, listH, hwnd, HMENU(idIfList), inst)
	sendMessage(lv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP)

	widths := ifColWidths(cW - ifPad*2)
	subclassListViewManaged(lv, ifColTitles, nil, nil, nil, func(hw HWND, row int32, pt POINT) {
		showIfContextMenu(getParent(hw), row, pt)
	})
	for i, title := range ifColTitles {
		listViewAddColumn(lv, int32(i), title, widths[i])
	}
	hwndIfList = lv

	// "Loading…" hint overlay (hidden once data arrives).
	hintY := listY + listH/2 - 9
	hwndIfLoadingHint, _ = createWindowEx(0, "STATIC", "Loading\u2026",
		WS_CHILD|WS_VISIBLE|SS_CENTER,
		ifPad, hintY, cW-ifPad*2, 18, hwnd, 0, inst)

	// Footer button.
	btnY := cH - ifPad - ifBtnH
	makePushButton(hwnd, "Refresh", idIfRefresh, ifPad, btnY, 80, ifBtnH)
}

func resizeIfControls(hwnd HWND) {
	if hwndIfList == 0 {
		return
	}
	r := getClientRect(hwnd)
	cW, cH := r.Right, r.Bottom

	listY := ifPad + ifFilterH + ifFilterGap
	listH := ifListHeight(cH)

	setWindowPos(hwndIfFilter, 0, ifPad, ifPad, cW-ifPad*2, ifFilterH, SWP_NOZORDER|SWP_NOACTIVATE)
	setWindowPos(hwndIfList, 0, ifPad, listY, cW-ifPad*2, listH, SWP_NOZORDER|SWP_NOACTIVATE)

	widths := ifColWidths(cW - ifPad*2)
	for i, w := range widths {
		sendMessage(hwndIfList, LVM_SETCOLUMNWIDTH, uintptr(i), uintptr(uint32(w)))
	}

	hintY := listY + listH/2 - 9
	setWindowPos(hwndIfLoadingHint, 0, ifPad, hintY, cW-ifPad*2, 18, SWP_NOZORDER|SWP_NOACTIVATE)
}

func ifListHeight(cH int32) int32 {
	h := cH - (ifPad + ifFilterH + ifFilterGap) - ifFilterGap - ifBtnH - ifPad
	if h < 40 {
		h = 40
	}
	return h
}

// ifColWidths distributes column widths proportionally across the available
// total width.  Fixed-width columns are allocated first; the Interface and
// IPv4 columns share the remainder.
func ifColWidths(total int32) []int32 {
	// Fixed columns (right side).
	typeW    := int32(70)
	stateW   := int32(45)
	macW     := int32(130)
	ipv6W    := int32(120)
	gwW      := int32(110)
	mtuW     := int32(50)
	fixed := typeW + stateW + macW + ipv6W + gwW + mtuW + 6 // +1px per separator
	remaining := total - fixed
	if remaining < 200 {
		remaining = 200
	}
	nameW := remaining * 2 / 5
	ipv4W := remaining - nameW
	if ipv4W < 100 {
		ipv4W = 100
	}
	return []int32{nameW, typeW, stateW, macW, ipv4W, ipv6W, gwW, mtuW}
}

// ---------------------------------------------------------------------------
// Context menu
// ---------------------------------------------------------------------------

func showIfContextMenu(parent HWND, row int32, pt POINT) {
	menu := createPopupMenu()
	defer destroyMenu(menu)

	hasSelection := row >= 0
	mf := func() uint32 {
		if !hasSelection {
			return MF_STRING | MF_GRAYED
		}
		return MF_STRING
	}

	appendMenu(menu, mf(), 3001, "Copy Interface")
	appendMenu(menu, mf(), 3002, "Copy IPv4")
	appendMenu(menu, mf(), 3003, "Copy MAC")
	appendMenu(menu, mf(), 3004, "Copy Row")
	appendMenu(menu, MF_SEPARATOR, 0, "")
	appendCopyAsSubmenu(menu)

	cmd := trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, pt.X, pt.Y, parent)
	switch cmd {
	case 3001:
		copyToClipboard(parent, listViewSelectedText(hwndIfList, 0))
	case 3002:
		copyToClipboard(parent, listViewSelectedText(hwndIfList, 4))
	case 3003:
		copyToClipboard(parent, listViewSelectedText(hwndIfList, 3))
	case 3004:
		if row >= 0 {
			copyToClipboard(parent, listViewGetRowTSV(hwndIfList, row, int32(len(ifColTitles))))
		}
	default:
		rows := listViewGetSelectedRows(hwndIfList)
		handleCopyAsCmd(parent, hwndIfList, cmd, rows, int32(len(ifColTitles)), ifColTitles, nil)
	}
}

// ---------------------------------------------------------------------------
// Data population
// ---------------------------------------------------------------------------

// interfacesDialogAddRow is called on the UI thread for each WM_IF_SNAP_ENTRY.
func interfacesDialogAddRow(e scan.InterfaceEntry) {
	ifAllRows = append(ifAllRows, e)
	if ifFilterText != "" && !ifEntryMatchesFilter(e, ifFilterText) {
		return
	}
	ifInsertRow(hwndIfList, e)
}

// interfacesDialogLoadingDone is called on WM_IF_SNAP_DONE.
func interfacesDialogLoadingDone() {
	if hwndIfLoadingHint != 0 {
		showWindow(hwndIfLoadingHint, SW_HIDE)
	}
}

// ifDialogRefresh clears the list and requests a new snapshot.
func ifDialogRefresh() {
	if hwndIfList != 0 {
		sendMessage(hwndIfList, LVM_DELETEALLITEMS, 0, 0)
	}
	if hwndIfLoadingHint != 0 {
		showWindow(hwndIfLoadingHint, SW_SHOW)
	}
	ifAllRows = nil
	requestIfSnapshot()
}

// ifRepopulate rebuilds the list from ifAllRows applying the current filter.
func ifRepopulate() {
	sendMessage(hwndIfList, LVM_DELETEALLITEMS, 0, 0)
	for _, e := range ifAllRows {
		if ifFilterText != "" && !ifEntryMatchesFilter(e, ifFilterText) {
			continue
		}
		ifInsertRow(hwndIfList, e)
	}
}

func ifInsertRow(lv HWND, e scan.InterfaceEntry) {
	listViewAppendRow(lv, []string{
		e.Name,
		e.Type,
		e.State,
		e.MAC,
		strings.Join(e.Addrs4, ", "),
		strings.Join(e.Addrs6, ", "),
		e.Gateway4,
		func() string {
			if e.MTU > 0 {
				return fmt.Sprintf("%d", e.MTU)
			}
			return ""
		}(),
	})
}

func ifEntryMatchesFilter(e scan.InterfaceEntry, f string) bool {
	return strings.Contains(strings.ToLower(e.Name), f) ||
		strings.Contains(strings.ToLower(e.Type), f) ||
		strings.Contains(strings.ToLower(e.State), f) ||
		strings.Contains(strings.ToLower(e.MAC), f) ||
		strings.Contains(strings.ToLower(strings.Join(e.Addrs4, " ")), f) ||
		strings.Contains(strings.ToLower(strings.Join(e.Addrs6, " ")), f) ||
		strings.Contains(strings.ToLower(e.Gateway4), f) ||
		strings.Contains(fmt.Sprintf("%d", e.MTU), f)
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

// showInterfacesDialog opens (or focuses) the modeless Local Interfaces dialog.
func showInterfacesDialog(parent HWND) {
	if hwndIfDlg != 0 {
		setForegroundWindow(hwndIfDlg)
		return
	}

	ifAllRows = nil
	ifFilterText = ""

	registerDialogClass("NetScopeInterfaces", ifDlgWndProc)

	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetScopeInterfaces",
		"Local Interfaces",
		WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
		0, 0, 860, 400,
		parent, 0, getModuleHandle(),
	)
	if err != nil || dlg == 0 {
		return
	}
	centerWindowOver(dlg, parent)
	setFontAllChildren(dlg, appFont)
	showWindow(dlg, SW_SHOW)
	updateWindow(dlg)
	hwndIfDlg = dlg
	atomic.StoreUintptr(&hwndInterfacesDialogAtomic, uintptr(dlg))

	if !requestIfSnapshot() {
		messageBox(dlg,
			"The sensor service is not running.\n\nStart or elevate the sensor from the toolbar, then use Refresh.",
			"Local Interfaces", MB_ICONINFORMATION)
	}
}

// closeIfDialog tears down the Local Interfaces dialog.
func closeIfDialog() {
	if hwndIfDlg == 0 {
		return
	}
	atomic.StoreUintptr(&hwndInterfacesDialogAtomic, 0)
	destroyWindow(hwndIfDlg)
	hwndIfDlg = 0
	hwndIfList = 0
	hwndIfFilter = 0
	hwndIfLoadingHint = 0
	ifAllRows = nil
}
