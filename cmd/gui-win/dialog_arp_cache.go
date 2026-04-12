//go:build windows

// dialog_arp_cache.go — ARP Cache viewer dialog.
//
// Opened via Tools > ARP Cache…
// Shows the current Windows ARP neighbour table (IPv4 → MAC). Entries are
// fetched from the sensor service via the "arp-snapshot" command so that
// delete/clear operations (which require admin) can be performed under the
// same elevated context.
//
// Layout:
//   ┌──────────────────────────────────────────────────────────┐
//   │  Filter…                                                  │
//   ├──────────────────────────────────────────────────────────┤
//   │  IP Address  │ MAC Address       │ Vendor     │ Type │ If│
//   │  …                                                        │
//   ├──────────────────────────────────────────────────────────┤
//   │  [Refresh]                              [Clear All]       │
//   └──────────────────────────────────────────────────────────┘

package guiwin

import (
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/demicloud/net-scope/internal/netinfo"
	"github.com/demicloud/net-scope/internal/scan"
)

// ---------------------------------------------------------------------------
// Control IDs
// ---------------------------------------------------------------------------

const (
	idARPFilter   = 1400
	idARPList     = 1401
	idARPRefresh  = 1402
	idARPClearAll = 1403

	// Right-click context menu IDs.
	idARPCopyIP  = 1410
	idARPCopyMAC = 1411
	idARPCopyRow = 1412
	idARPDelete  = 1413
)

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

var (
	hwndARPCacheDlg    HWND
	hwndARPList        HWND
	hwndARPFilter      HWND
	hwndARPLoadingHint HWND

	// arpAllRows stores every row fetched from the last snapshot so that the
	// filter can rebuild the list without a new network round-trip.
	arpAllRows    []netinfo.ARPResult
	arpFilterText string
)

var arpColTitles = []string{"IP Address", "MAC Address", "Vendor", "Type", "Interface"}

// ---------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------

var arpCacheWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createARPCacheControls(HWND(hwnd))
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_COMMAND:
		switch loword(wParam) {
		case idARPFilter:
			if hiword(wParam) == EN_CHANGE {
				arpFilterText = strings.ToLower(getWindowText(hwndARPFilter))
				arpRepopulate()
			}
		case idARPRefresh:
			arpCacheDialogRefresh()
		case idARPClearAll:
			arpConfirmClearAll(HWND(hwnd))
		}
		return 0

	case WM_SIZE:
		resizeARPCacheControls(HWND(hwnd))
		return 0

	case WM_KEYDOWN:
		if wParam == VK_ESCAPE {
			closeARPCacheDialog()
		}
		return 0

	case WM_CLOSE:
		closeARPCacheDialog()
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

// ---------------------------------------------------------------------------
// Control creation / layout
// ---------------------------------------------------------------------------

const (
	arpPad    int32 = 8
	arpBtnH   int32 = 26
	arpFilterH int32 = 24
	arpFilterGap int32 = 6
)

func createARPCacheControls(hwnd HWND) {
	inst := getModuleHandle()
	r := getClientRect(hwnd)
	cW, cH := r.Right, r.Bottom

	// Filter edit.
	filt, _ := createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,
		arpPad, arpPad, cW-arpPad*2, arpFilterH, hwnd, HMENU(idARPFilter), inst)
	cueText := utf16("Filter\u2026")
	sendMessage(filt, EM_SETCUEBANNER, 1, uintptr(unsafe.Pointer(cueText)))
	hwndARPFilter = filt

	listY := arpPad + arpFilterH + arpFilterGap
	listH := arpListHeight(cH)

	lv, _ := createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		arpPad, listY, cW-arpPad*2, listH, hwnd, HMENU(idARPList), inst)
	sendMessage(lv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP)

	widths := arpColWidths(cW - arpPad*2)
	subclassListViewManaged(lv, arpColTitles, nil, nil, nil, func(hw HWND, row int32, pt POINT) {
		showARPContextMenu(getParent(hw), row, pt)
	})
	for i, title := range arpColTitles {
		listViewAddColumn(lv, int32(i), title, widths[i])
	}
	hwndARPList = lv

	// "Loading…" hint overlay.
	hintY := listY + listH/2 - 9
	hwndARPLoadingHint, _ = createWindowEx(0, "STATIC", "Loading\u2026",
		WS_CHILD|WS_VISIBLE|SS_CENTER,
		arpPad, hintY, cW-arpPad*2, 18, hwnd, 0, inst)

	// Footer buttons.
	btnY := cH - arpPad - arpBtnH
	makePushButton(hwnd, "Refresh", idARPRefresh, arpPad, btnY, 80, arpBtnH)
	makePushButton(hwnd, "Clear All", idARPClearAll, cW-arpPad-90, btnY, 90, arpBtnH)
}

func resizeARPCacheControls(hwnd HWND) {
	if hwndARPList == 0 {
		return
	}
	r := getClientRect(hwnd)
	cW, cH := r.Right, r.Bottom

	listY := arpPad + arpFilterH + arpFilterGap
	listH := arpListHeight(cH)

	setWindowPos(hwndARPFilter, 0, arpPad, arpPad, cW-arpPad*2, arpFilterH, SWP_NOZORDER|SWP_NOACTIVATE)
	setWindowPos(hwndARPList, 0, arpPad, listY, cW-arpPad*2, listH, SWP_NOZORDER|SWP_NOACTIVATE)

	widths := arpColWidths(cW - arpPad*2)
	for i, w := range widths {
		sendMessage(hwndARPList, LVM_SETCOLUMNWIDTH, uintptr(i), uintptr(uint32(w)))
	}

	hintY := listY + listH/2 - 9
	setWindowPos(hwndARPLoadingHint, 0, arpPad, hintY, cW-arpPad*2, 18, SWP_NOZORDER|SWP_NOACTIVATE)
}

func arpListHeight(cH int32) int32 {
	h := cH - (arpPad + arpFilterH + arpFilterGap) - arpFilterGap - arpBtnH - arpPad
	if h < 40 {
		h = 40
	}
	return h
}

func arpColWidths(total int32) []int32 {
	ifW := int32(50)
	typeW := int32(70)
	ipW := int32(130)
	macW := int32(130)
	vendorW := total - ipW - macW - typeW - ifW - 4
	if vendorW < 80 {
		vendorW = 80
	}
	return []int32{ipW, macW, vendorW, typeW, ifW}
}

// ---------------------------------------------------------------------------
// Context menu
// ---------------------------------------------------------------------------

func showARPContextMenu(parent HWND, row int32, pt POINT) {
	menu := createPopupMenu()
	defer destroyMenu(menu)

	hasSelection := row >= 0
	mf := menuFlagIfSelected(hasSelection)

	appendMenu(menu, mf(MF_STRING), idARPCopyIP, "Copy IP")
	appendMenu(menu, mf(MF_STRING), idARPCopyMAC, "Copy MAC")
	appendMenu(menu, mf(MF_STRING), idARPCopyRow, "Copy Row")
	appendMenu(menu, MF_SEPARATOR, 0, "")
	appendCopyAsSubmenu(menu)
	appendMenu(menu, MF_SEPARATOR, 0, "")
	delFlag := mf(MF_STRING)
	appendMenu(menu, delFlag, idARPDelete, "Delete Entry")

	cmd := trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, pt.X, pt.Y, parent)
	switch cmd {
	case idARPCopyIP:
		copyToClipboard(parent, listViewSelectedText(hwndARPList, 0))
	case idARPCopyMAC:
		copyToClipboard(parent, listViewSelectedText(hwndARPList, 1))
	case idARPCopyRow:
		if row >= 0 {
			copyToClipboard(parent, listViewGetRowTSV(hwndARPList, row, int32(len(arpColTitles))))
		}
	case idARPDelete:
		if !serviceElevated {
			messageBox(parent,
				"Deleting ARP entries requires an elevated sensor.\n\nUse the \u201cElevate Sensor\u201d button in the toolbar.",
				"ARP Cache", MB_ICONINFORMATION)
			return
		}
		for _, r := range listViewGetSelectedRows(hwndARPList) {
			ip := listViewGetCellText(hwndARPList, r, 0)
			if ip != "" && ip != "\u2014" {
				requestARPDelete(ip)
			}
		}
	default:
		rows := listViewGetSelectedRows(hwndARPList)
		handleCopyAsCmd(parent, hwndARPList, cmd, rows, int32(len(arpColTitles)), arpColTitles, nil)
	}
}

// ---------------------------------------------------------------------------
// Data population
// ---------------------------------------------------------------------------

// arpCacheDialogAddRow is called on the UI thread for each WM_ARP_SNAP_ENTRY.
func arpCacheDialogAddRow(e netinfo.ARPResult) {
	arpAllRows = append(arpAllRows, e)
	if arpFilterText != "" && !arpEntryMatchesFilter(e, arpFilterText) {
		return
	}
	arpInsertRow(hwndARPList, e)
}

// arpCacheDialogLoadingDone is called on WM_ARP_SNAP_DONE.
func arpCacheDialogLoadingDone() {
	if hwndARPLoadingHint != 0 {
		showWindow(hwndARPLoadingHint, SW_HIDE)
	}
}

// arpCacheDialogRefresh clears the list and requests a new snapshot.
func arpCacheDialogRefresh() {
	if hwndARPList != 0 {
		sendMessage(hwndARPList, LVM_DELETEALLITEMS, 0, 0)
	}
	if hwndARPLoadingHint != 0 {
		showWindow(hwndARPLoadingHint, SW_SHOW)
	}
	arpAllRows = nil
	requestARPSnapshot()
}

// arpRepopulate rebuilds the listview from arpAllRows using the current filter.
func arpRepopulate() {
	sendMessage(hwndARPList, LVM_DELETEALLITEMS, 0, 0)
	for _, e := range arpAllRows {
		if arpFilterText != "" && !arpEntryMatchesFilter(e, arpFilterText) {
			continue
		}
		arpInsertRow(hwndARPList, e)
	}
}

func arpInsertRow(lv HWND, e netinfo.ARPResult) {
	vendor := scan.LookupVendor(mustParseMAC(e.MAC))
	if vendor == "" {
		vendor = "\u2014"
	}
	ifStr := "\u2014"
	if e.IfIndex > 0 {
		ifStr = uintToStr(e.IfIndex)
	}
	listViewAppendRow(lv, []string{e.IP, e.MAC, vendor, e.Type, ifStr})
}

func arpEntryMatchesFilter(e netinfo.ARPResult, f string) bool {
	vendor := strings.ToLower(scan.LookupVendor(mustParseMAC(e.MAC)))
	for _, field := range []string{e.IP, e.MAC, vendor, e.Type} {
		if strings.Contains(strings.ToLower(field), f) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Clear confirmation
// ---------------------------------------------------------------------------

func arpConfirmClearAll(parent HWND) {
	if !serviceElevated {
		messageBox(parent,
			"Clearing the ARP cache requires an elevated sensor.\n\nUse the \u201cElevate Sensor\u201d button in the toolbar to restart the sensor with admin rights.",
			"ARP Cache", MB_ICONINFORMATION)
		return
	}
	if messageBox(parent,
		"Clear all dynamic ARP entries?\n\nWindows will re-learn them automatically as you communicate with local hosts.",
		"ARP Cache", MB_YESNO|MB_ICONQUESTION) == IDYES {
		requestARPClear()
	}
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

// showARPCacheDialog opens (or focuses) the modeless ARP Cache dialog.
func showARPCacheDialog(parent HWND) {
	if hwndARPCacheDlg != 0 {
		setForegroundWindow(hwndARPCacheDlg)
		return
	}

	arpAllRows = nil
	arpFilterText = ""

	registerDialogClass("NetScopeARPCache", arpCacheWndProc)
	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetScopeARPCache", "ARP Cache",
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
	hwndARPCacheDlg = dlg
	atomic.StoreUintptr(&hwndARPCacheDialogAtomic, uintptr(dlg))

	// Kick off the initial snapshot.
	if !requestARPSnapshot() {
		messageBox(dlg,
			"The sensor service is not running.\n\nStart or elevate the sensor from the toolbar, then use Refresh.",
			"ARP Cache", MB_ICONINFORMATION)
		arpCacheDialogLoadingDone()
	}
}

// closeARPCacheDialog destroys the modeless ARP Cache dialog.
func closeARPCacheDialog() {
	if hwndARPCacheDlg != 0 {
		atomic.StoreUintptr(&hwndARPCacheDialogAtomic, 0)
		destroyWindow(hwndARPCacheDlg)
		hwndARPCacheDlg = 0
		hwndARPList = 0
		hwndARPFilter = 0
		hwndARPLoadingHint = 0
	}
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// mustParseMAC parses a MAC string; returns nil on error.
func mustParseMAC(s string) []byte {
	// net.HardwareAddr is []byte; parse manually to avoid import cycle
	// (we need scan.LookupVendor which takes net.HardwareAddr).
	// Just use the scan package's exported wrapper.
	mac, _ := parseMACBytes(s)
	return mac
}

// parseMACBytes parses a colon-separated MAC string into bytes.
// Returns nil on error.
func parseMACBytes(s string) ([]byte, bool) {
	if len(s) < 17 {
		return nil, false
	}
	b := make([]byte, 6)
	n, _ := parseMACInto(s, b)
	if n != 6 {
		return nil, false
	}
	return b, true
}

func parseMACInto(s string, b []byte) (int, error) {
	i := 0
	for _, part := range strings.Split(s, ":") {
		if i >= len(b) {
			break
		}
		var v uint64
		for _, c := range part {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= uint64(c - '0')
			case c >= 'a' && c <= 'f':
				v |= uint64(c-'a') + 10
			case c >= 'A' && c <= 'F':
				v |= uint64(c-'A') + 10
			}
		}
		b[i] = byte(v)
		i++
	}
	return i, nil
}

// uintToStr converts a uint32 to a decimal string.
func uintToStr(n uint32) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}
