//go:build windows

// dialog_dns_cache.go — DNS Resolver Cache viewer dialog.
//
// Opened via Tools > DNS Cache…
// Shows entries in the Windows DNS Client service resolver cache. Entries are
// fetched from the sensor service via the "dns-snapshot" command; clearing is
// done via "dns-clear" (usually does not require elevation).
//
// Layout:
//   ┌──────────────────────────────────────────────────────────┐
//   │  Filter…                                                  │
//   ├──────────────────────────────────────────────────────────┤
//   │  Record Name                           │ Type            │
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

	"github.com/demicloud/net-scope/internal/scan"
)

// ---------------------------------------------------------------------------
// Control IDs
// ---------------------------------------------------------------------------

const (
	idDNSFilter   = 1500
	idDNSList     = 1501
	idDNSRefresh  = 1502
	idDNSClearAll = 1503

	// Right-click context menu IDs.
	idDNSCopyName    = 1510
	idDNSCopyType    = 1511
	idDNSCopyRow     = 1512
	idDNSDeleteEntry = 1513
)

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

var (
	hwndDNSCacheDlg    HWND
	hwndDNSList        HWND
	hwndDNSFilter      HWND
	hwndDNSLoadingHint HWND

	dnsAllRows    []scan.DNSCacheEntry
	dnsFilterText string
)

var dnsColTitles = []string{"Record Name", "Type"}

// ---------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------

var dnsCacheWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createDNSCacheControls(HWND(hwnd))
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_COMMAND:
		switch loword(wParam) {
		case idDNSFilter:
			if hiword(wParam) == EN_CHANGE {
				dnsFilterText = strings.ToLower(getWindowText(hwndDNSFilter))
				dnsRepopulate()
			}
		case idDNSRefresh:
			dnsCacheDialogRefresh()
		case idDNSClearAll:
			dnsConfirmClearAll(HWND(hwnd))
		case idDNSCopyName:
			copyToClipboard(HWND(hwnd), listViewSelectedText(hwndDNSList, 0))
		case idDNSCopyType:
			copyToClipboard(HWND(hwnd), listViewSelectedText(hwndDNSList, 1))
		case idDNSCopyRow:
			row := int32(sendMessage(hwndDNSList, LVM_GETNEXTITEM, ^uintptr(0), LVNI_SELECTED))
			if row >= 0 {
				copyToClipboard(HWND(hwnd), listViewGetRowTSV(hwndDNSList, row, int32(len(dnsColTitles))))
			}
		case idDNSDeleteEntry:
			rows := listViewGetSelectedRows(hwndDNSList)
			if len(rows) == 0 {
				break
			}
			if !serviceRunning() {
				messageBox(HWND(hwnd), "Sensor service is not running. Start the sensor and try again.", "DNS Cache", MB_ICONINFORMATION)
				break
			}
			for _, r := range rows {
				name := listViewGetCellText(hwndDNSList, r, 0)
				if name != "" {
					requestDNSDelete(name)
				}
			}
		}
		return 0

	case WM_SIZE:
		resizeDNSCacheControls(HWND(hwnd))
		return 0

	case WM_KEYDOWN:
		if wParam == VK_ESCAPE {
			closeDNSCacheDialog()
		}
		return 0

	case WM_CLOSE:
		closeDNSCacheDialog()
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

// ---------------------------------------------------------------------------
// Control creation / layout
// ---------------------------------------------------------------------------

const (
	dnsPad      int32 = 8
	dnsBtnH     int32 = 26
	dnsFilterH  int32 = 24
	dnsFilterGap int32 = 6
)

func createDNSCacheControls(hwnd HWND) {
	inst := getModuleHandle()
	r := getClientRect(hwnd)
	cW, cH := r.Right, r.Bottom

	// Filter edit.
	filt, _ := createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,
		dnsPad, dnsPad, cW-dnsPad*2, dnsFilterH, hwnd, HMENU(idDNSFilter), inst)
	cueText := utf16("Filter\u2026")
	sendMessage(filt, EM_SETCUEBANNER, 1, uintptr(unsafe.Pointer(cueText)))
	hwndDNSFilter = filt

	listY := dnsPad + dnsFilterH + dnsFilterGap
	listH := dnsListHeight(cH)

	lv, _ := createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		dnsPad, listY, cW-dnsPad*2, listH, hwnd, HMENU(idDNSList), inst)
	sendMessage(lv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP)

	widths := dnsColWidths(cW - dnsPad*2)
	subclassListViewManaged(lv, dnsColTitles, nil, nil, nil, func(hw HWND, row int32, pt POINT) {
		showDNSContextMenu(getParent(hw), row, pt)
	})
	for i, title := range dnsColTitles {
		listViewAddColumn(lv, int32(i), title, widths[i])
	}
	hwndDNSList = lv

	// "Loading…" hint overlay.
	hintY := listY + listH/2 - 9
	hwndDNSLoadingHint, _ = createWindowEx(0, "STATIC", "Loading\u2026",
		WS_CHILD|WS_VISIBLE|SS_CENTER,
		dnsPad, hintY, cW-dnsPad*2, 18, hwnd, 0, inst)

	// Footer buttons.
	btnY := cH - dnsPad - dnsBtnH
	makePushButton(hwnd, "Refresh", idDNSRefresh, dnsPad, btnY, 80, dnsBtnH)
	makePushButton(hwnd, "Clear All", idDNSClearAll, cW-dnsPad-90, btnY, 90, dnsBtnH)
}

func resizeDNSCacheControls(hwnd HWND) {
	if hwndDNSList == 0 {
		return
	}
	r := getClientRect(hwnd)
	cW, cH := r.Right, r.Bottom

	listY := dnsPad + dnsFilterH + dnsFilterGap
	listH := dnsListHeight(cH)

	setWindowPos(hwndDNSFilter, 0, dnsPad, dnsPad, cW-dnsPad*2, dnsFilterH, SWP_NOZORDER|SWP_NOACTIVATE)
	setWindowPos(hwndDNSList, 0, dnsPad, listY, cW-dnsPad*2, listH, SWP_NOZORDER|SWP_NOACTIVATE)

	widths := dnsColWidths(cW - dnsPad*2)
	for i, w := range widths {
		sendMessage(hwndDNSList, LVM_SETCOLUMNWIDTH, uintptr(i), uintptr(uint32(w)))
	}

	hintY := listY + listH/2 - 9
	setWindowPos(hwndDNSLoadingHint, 0, dnsPad, hintY, cW-dnsPad*2, 18, SWP_NOZORDER|SWP_NOACTIVATE)
}

func dnsListHeight(cH int32) int32 {
	h := cH - (dnsPad + dnsFilterH + dnsFilterGap) - dnsFilterGap - dnsBtnH - dnsPad
	if h < 40 {
		h = 40
	}
	return h
}

func dnsColWidths(total int32) []int32 {
	typeW := int32(70)
	nameW := total - typeW - 4
	if nameW < 100 {
		nameW = 100
	}
	return []int32{nameW, typeW}
}

// ---------------------------------------------------------------------------
// Context menu
// ---------------------------------------------------------------------------

func showDNSContextMenu(parent HWND, row int32, pt POINT) {
	menu := createPopupMenu()
	defer destroyMenu(menu)

	hasSelection := row >= 0
	mf := func(flag uint32) uint32 {
		if !hasSelection {
			return MF_STRING | MF_GRAYED
		}
		return flag
	}

	appendMenu(menu, mf(MF_STRING), idDNSCopyName, "Copy Name")
	appendMenu(menu, mf(MF_STRING), idDNSCopyType, "Copy Type")
	appendMenu(menu, mf(MF_STRING), idDNSCopyRow, "Copy Row")
	appendMenu(menu, MF_SEPARATOR, 0, "")
	appendCopyAsSubmenu(menu)
	appendMenu(menu, MF_SEPARATOR, 0, "")
	appendMenu(menu, mf(MF_STRING), idDNSDeleteEntry, "Delete Entry")
	appendMenu(menu, MF_SEPARATOR, 0, "")
	appendMenu(menu, MF_STRING, idDNSClearAll, "Clear All Cache")

	cmd := trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, pt.X, pt.Y, parent)
	switch cmd {
	case idDNSCopyName:
		copyToClipboard(parent, listViewSelectedText(hwndDNSList, 0))
	case idDNSCopyType:
		copyToClipboard(parent, listViewSelectedText(hwndDNSList, 1))
	case idDNSCopyRow:
		if row >= 0 {
			copyToClipboard(parent, listViewGetRowTSV(hwndDNSList, row, int32(len(dnsColTitles))))
		}
	case idDNSDeleteEntry:
		selRows := listViewGetSelectedRows(hwndDNSList)
		if len(selRows) > 0 {
			if !serviceRunning() {
				messageBox(parent, "Sensor service is not running. Start the sensor and try again.", "DNS Cache", MB_ICONINFORMATION)
			} else {
				for _, r := range selRows {
					name := listViewGetCellText(hwndDNSList, r, 0)
					if name != "" {
						requestDNSDelete(name)
					}
				}
			}
		}
	case idDNSClearAll:
		dnsConfirmClearAll(parent)
	default:
		rows := listViewGetSelectedRows(hwndDNSList)
		handleCopyAsCmd(parent, hwndDNSList, cmd, rows, int32(len(dnsColTitles)), dnsColTitles, nil)
	}
}

// ---------------------------------------------------------------------------
// Data population
// ---------------------------------------------------------------------------

// dnsCacheDialogAddRow is called on the UI thread for each WM_DNS_SNAP_ENTRY.
func dnsCacheDialogAddRow(e scan.DNSCacheEntry) {
	dnsAllRows = append(dnsAllRows, e)
	if dnsFilterText != "" && !dnsEntryMatchesFilter(e, dnsFilterText) {
		return
	}
	dnsInsertRow(hwndDNSList, e)
}

// dnsCacheDialogLoadingDone is called on WM_DNS_SNAP_DONE.
func dnsCacheDialogLoadingDone() {
	if hwndDNSLoadingHint != 0 {
		showWindow(hwndDNSLoadingHint, SW_HIDE)
	}
}

// dnsCacheDialogRefresh clears the list and requests a new snapshot.
func dnsCacheDialogRefresh() {
	if hwndDNSList != 0 {
		sendMessage(hwndDNSList, LVM_DELETEALLITEMS, 0, 0)
	}
	if hwndDNSLoadingHint != 0 {
		showWindow(hwndDNSLoadingHint, SW_SHOW)
	}
	dnsAllRows = nil
	requestDNSSnapshot()
}

// dnsRepopulate rebuilds the listview from dnsAllRows using the current filter.
func dnsRepopulate() {
	sendMessage(hwndDNSList, LVM_DELETEALLITEMS, 0, 0)
	for _, e := range dnsAllRows {
		if dnsFilterText != "" && !dnsEntryMatchesFilter(e, dnsFilterText) {
			continue
		}
		dnsInsertRow(hwndDNSList, e)
	}
}

func dnsInsertRow(lv HWND, e scan.DNSCacheEntry) {
	listViewAppendRow(lv, []string{e.Name, e.Type})
}

func dnsEntryMatchesFilter(e scan.DNSCacheEntry, f string) bool {
	return strings.Contains(strings.ToLower(e.Name), f) ||
		strings.Contains(strings.ToLower(e.Type), f)
}

// ---------------------------------------------------------------------------
// Clear confirmation
// ---------------------------------------------------------------------------

func dnsConfirmClearAll(parent HWND) {
	if messageBox(parent,
		"Clear the Windows DNS resolver cache?\n\nAll cached lookups will be discarded. Windows will re-query DNS servers as needed.",
		"DNS Cache", MB_YESNO|MB_ICONQUESTION) == IDYES {
		if !requestDNSClear() {
			messageBox(parent, "Sensor service is not running. Start the sensor and try again.", "DNS Cache", MB_ICONINFORMATION)
		}
	}
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

// showDNSCacheDialog opens (or focuses) the modeless DNS Cache dialog.
func showDNSCacheDialog(parent HWND) {
	if hwndDNSCacheDlg != 0 {
		setForegroundWindow(hwndDNSCacheDlg)
		return
	}

	dnsAllRows = nil
	dnsFilterText = ""

	registerDialogClass("NetScopeDNSCache", dnsCacheWndProc)
	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetScopeDNSCache", "DNS Resolver Cache",
		WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
		0, 0, 560, 460,
		parent, 0, getModuleHandle(),
	)
	if err != nil || dlg == 0 {
		return
	}
	centerWindowOver(dlg, parent)
	setFontAllChildren(dlg, appFont)
	showWindow(dlg, SW_SHOW)
	updateWindow(dlg)
	hwndDNSCacheDlg = dlg
	atomic.StoreUintptr(&hwndDNSCacheDialogAtomic, uintptr(dlg))

	// Kick off the initial snapshot.
	if !requestDNSSnapshot() {
		messageBox(dlg,
			"The sensor service is not running.\n\nStart the sensor from the toolbar, then use Refresh.",
			"DNS Cache", MB_ICONWARNING)
		dnsCacheDialogLoadingDone()
	}
}

// closeDNSCacheDialog destroys the modeless DNS Cache dialog.
func closeDNSCacheDialog() {
	if hwndDNSCacheDlg != 0 {
		atomic.StoreUintptr(&hwndDNSCacheDialogAtomic, 0)
		destroyWindow(hwndDNSCacheDlg)
		hwndDNSCacheDlg = 0
		hwndDNSList = 0
		hwndDNSFilter = 0
		hwndDNSLoadingHint = 0
	}
}
