//go:build windows

// dialog_route_table.go — IPv4 Route Table viewer dialog.
//
// Opened via Tools > Route Table…
// Shows the system IPv4 forwarding table. Entries are fetched from the sensor
// service via the "route-snapshot" command. Route deletion requires elevation
// because DeleteIpForwardEntry demands admin rights.
//
// Layout:
//   ┌──────────────────────────────────────────────────────────┐
//   │  Filter…                                                  │
//   ├──────────────────────────────────────────────────────────┤
//   │  Destination  │ Gateway  │  If  │ Metric │ Proto │ Type  │
//   │  …                                                        │
//   ├──────────────────────────────────────────────────────────┤
//   │  [Refresh]                                                │
//   └──────────────────────────────────────────────────────────┘

package guiwin

import (
	"fmt"
	"net"
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
	idRouteFilter  = 1600
	idRouteList    = 1601
	idRouteRefresh = 1602

	// Right-click context menu IDs.
	idRouteCopyDest    = 1610
	idRouteCopyGW      = 1611
	idRouteCopyRow     = 1612
	idRouteDeleteEntry = 1613
)

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

var (
	hwndRouteTableDlg    HWND
	hwndRouteList        HWND
	hwndRouteFilter      HWND
	hwndRouteLoadingHint HWND

	// routeAllRows holds every entry from the last snapshot, allowing filter
	// rebuilds without another network round-trip.
	routeAllRows    []netinfo.RouteEntry
	routeFilterText string
)

var routeColTitles = []string{"Destination", "Gateway", "Interface", "Metric", "Protocol", "Type"}

// ---------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------

var routeTableWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createRouteTableControls(HWND(hwnd))
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_COMMAND:
		switch loword(wParam) {
		case idRouteFilter:
			if hiword(wParam) == EN_CHANGE {
				routeFilterText = strings.ToLower(getWindowText(hwndRouteFilter))
				routeRepopulate()
			}
		case idRouteRefresh:
			routeTableDialogRefresh()
		}
		return 0

	case WM_SIZE:
		resizeRouteTableControls(HWND(hwnd))
		return 0

	case WM_KEYDOWN:
		if wParam == VK_ESCAPE {
			closeRouteTableDialog()
		}
		return 0

	case WM_CLOSE:
		closeRouteTableDialog()
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

// ---------------------------------------------------------------------------
// Control creation / layout
// ---------------------------------------------------------------------------

const (
	routePad      int32 = 8
	routeBtnH     int32 = 26
	routeFilterH  int32 = 24
	routeFilterGap int32 = 6
)

func createRouteTableControls(hwnd HWND) {
	inst := getModuleHandle()
	r := getClientRect(hwnd)
	cW, cH := r.Right, r.Bottom

	// Filter edit.
	filt, _ := createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,
		routePad, routePad, cW-routePad*2, routeFilterH, hwnd, HMENU(idRouteFilter), inst)
	cueText := utf16("Filter\u2026")
	sendMessage(filt, EM_SETCUEBANNER, 1, uintptr(unsafe.Pointer(cueText)))
	hwndRouteFilter = filt

	listY := routePad + routeFilterH + routeFilterGap
	listH := routeListHeight(cH)

	lv, _ := createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		routePad, listY, cW-routePad*2, listH, hwnd, HMENU(idRouteList), inst)
	sendMessage(lv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP)

	widths := routeColWidths(cW - routePad*2)
	subclassListViewManaged(lv, routeColTitles, nil, nil, nil, func(hw HWND, row int32, pt POINT) {
		showRouteContextMenu(getParent(hw), row, pt)
	})
	for i, title := range routeColTitles {
		listViewAddColumn(lv, int32(i), title, widths[i])
	}
	hwndRouteList = lv

	// "Loading…" hint overlay.
	hintY := listY + listH/2 - 9
	hwndRouteLoadingHint, _ = createWindowEx(0, "STATIC", "Loading\u2026",
		WS_CHILD|WS_VISIBLE|SS_CENTER,
		routePad, hintY, cW-routePad*2, 18, hwnd, 0, inst)

	// Footer button — Refresh only (no Clear All for routes).
	btnY := cH - routePad - routeBtnH
	makePushButton(hwnd, "Refresh", idRouteRefresh, routePad, btnY, 80, routeBtnH)
}

func resizeRouteTableControls(hwnd HWND) {
	if hwndRouteList == 0 {
		return
	}
	r := getClientRect(hwnd)
	cW, cH := r.Right, r.Bottom

	listY := routePad + routeFilterH + routeFilterGap
	listH := routeListHeight(cH)

	setWindowPos(hwndRouteFilter, 0, routePad, routePad, cW-routePad*2, routeFilterH, SWP_NOZORDER|SWP_NOACTIVATE)
	setWindowPos(hwndRouteList, 0, routePad, listY, cW-routePad*2, listH, SWP_NOZORDER|SWP_NOACTIVATE)

	widths := routeColWidths(cW - routePad*2)
	for i, w := range widths {
		sendMessage(hwndRouteList, LVM_SETCOLUMNWIDTH, uintptr(i), uintptr(uint32(w)))
	}

	hintY := listY + listH/2 - 9
	setWindowPos(hwndRouteLoadingHint, 0, routePad, hintY, cW-routePad*2, 18, SWP_NOZORDER|SWP_NOACTIVATE)
}

func routeListHeight(cH int32) int32 {
	h := cH - (routePad + routeFilterH + routeFilterGap) - routeFilterGap - routeBtnH - routePad
	if h < 40 {
		h = 40
	}
	return h
}

func routeColWidths(total int32) []int32 {
	ifW := int32(40)
	metricW := int32(55)
	protoW := int32(65)
	typeW := int32(60)
	gwW := int32(130)
	destW := total - gwW - ifW - metricW - protoW - typeW - 4
	if destW < 120 {
		destW = 120
	}
	return []int32{destW, gwW, ifW, metricW, protoW, typeW}
}

// ---------------------------------------------------------------------------
// Context menu
// ---------------------------------------------------------------------------

func showRouteContextMenu(parent HWND, row int32, pt POINT) {
	menu := createPopupMenu()
	defer destroyMenu(menu)

	hasSelection := row >= 0
	mf := menuFlagIfSelected(hasSelection)

	appendMenu(menu, mf(MF_STRING), idRouteCopyDest, "Copy Destination")
	appendMenu(menu, mf(MF_STRING), idRouteCopyGW, "Copy Gateway")
	appendMenu(menu, mf(MF_STRING), idRouteCopyRow, "Copy Row")
	appendMenu(menu, MF_SEPARATOR, 0, "")
	appendCopyAsSubmenu(menu)
	appendMenu(menu, MF_SEPARATOR, 0, "")
	appendMenu(menu, mf(MF_STRING), idRouteDeleteEntry, "Delete Route")

	cmd := trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, pt.X, pt.Y, parent)
	switch cmd {
	case idRouteCopyDest:
		copyToClipboard(parent, listViewSelectedText(hwndRouteList, 0))
	case idRouteCopyGW:
		copyToClipboard(parent, listViewSelectedText(hwndRouteList, 1))
	case idRouteCopyRow:
		if row >= 0 {
			copyToClipboard(parent, listViewGetRowTSV(hwndRouteList, row, int32(len(routeColTitles))))
		}
	case idRouteDeleteEntry:
		if !serviceElevated {
			showInfo(parent,
				"Deleting routes requires an elevated sensor.\n\nUse the \u201cElevate Sensor\u201d button in the toolbar.",
				"Route Table")
			return
		}
		for _, r := range listViewGetSelectedRows(hwndRouteList) {
			if target := routeDeleteTarget(r); target != "" {
				requestRouteDelete(target)
			}
		}
	default:
		rows := listViewGetSelectedRows(hwndRouteList)
		handleCopyAsCmd(parent, hwndRouteList, cmd, rows, int32(len(routeColTitles)), routeColTitles, nil)
	}
}

// ---------------------------------------------------------------------------
// Data population
// ---------------------------------------------------------------------------

// routeTableDialogAddRow is called on the UI thread for each WM_ROUTE_SNAP_ENTRY.
func routeTableDialogAddRow(e netinfo.RouteEntry) {
	routeAllRows = append(routeAllRows, e)
	if routeFilterText != "" && !routeEntryMatchesFilter(e, routeFilterText) {
		return
	}
	routeInsertRow(hwndRouteList, e)
}

// routeTableDialogLoadingDone is called on WM_ROUTE_SNAP_DONE.
func routeTableDialogLoadingDone() {
	if hwndRouteLoadingHint != 0 {
		showWindow(hwndRouteLoadingHint, SW_HIDE)
	}
}

// routeTableDialogRefresh clears the list and requests a new snapshot.
func routeTableDialogRefresh() {
	if hwndRouteList != 0 {
		sendMessage(hwndRouteList, LVM_DELETEALLITEMS, 0, 0)
	}
	if hwndRouteLoadingHint != 0 {
		showWindow(hwndRouteLoadingHint, SW_SHOW)
	}
	routeAllRows = nil
	requestRouteSnapshot()
}

// routeRepopulate rebuilds the listview from routeAllRows applying the current filter.
func routeRepopulate() {
	sendMessage(hwndRouteList, LVM_DELETEALLITEMS, 0, 0)
	for _, e := range routeAllRows {
		if routeFilterText != "" && !routeEntryMatchesFilter(e, routeFilterText) {
			continue
		}
		routeInsertRow(hwndRouteList, e)
	}
}

func routeInsertRow(lv HWND, e netinfo.RouteEntry) {
	listViewAppendRow(lv, []string{
		routeDestCIDR(e),
		e.Gateway,
		fmt.Sprintf("%d", e.IfIndex),
		fmt.Sprintf("%d", e.Metric),
		e.Protocol,
		e.Type,
	})
}

func routeEntryMatchesFilter(e netinfo.RouteEntry, f string) bool {
	cidr := strings.ToLower(routeDestCIDR(e))
	return strings.Contains(cidr, f) ||
		strings.Contains(strings.ToLower(e.Gateway), f) ||
		strings.Contains(strings.ToLower(e.Protocol), f) ||
		strings.Contains(strings.ToLower(e.Type), f) ||
		strings.Contains(fmt.Sprintf("%d", e.IfIndex), f) ||
		strings.Contains(fmt.Sprintf("%d", e.Metric), f)
}

// routeDestCIDR formats e.Dest/e.Mask as a CIDR string, e.g. "192.168.1.0/24".
func routeDestCIDR(e netinfo.RouteEntry) string {
	mask := net.ParseIP(e.Mask).To4()
	if mask == nil {
		return e.Dest
	}
	ones, _ := net.IPMask(mask).Size()
	return fmt.Sprintf("%s/%d", e.Dest, ones)
}

// routeDeleteTarget returns the "dest|mask|gateway" target string for the
// given visible list-row index, used by requestRouteDelete. Returns "" when
// the row index is out of range (can happen if a filter is applied and the
// visible-row index differs from routeAllRows index — in that case we look up
// Dest and Gateway from the cell text to find the matching entry).
func routeDeleteTarget(listRow int32) string {
	cidr := listViewGetCellText(hwndRouteList, listRow, 0)
	gw := listViewGetCellText(hwndRouteList, listRow, 1)
	if cidr == "" || gw == "" {
		return ""
	}
	// Look up the full entry (with raw Mask) from routeAllRows.
	for _, e := range routeAllRows {
		if routeDestCIDR(e) == cidr && e.Gateway == gw {
			return e.Dest + "|" + e.Mask + "|" + e.Gateway
		}
	}
	// Fallback: parse the CIDR to reconstruct dest and mask.
	destIP, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	_ = destIP
	mask := net.IP(ipnet.Mask).String()
	return ipnet.IP.String() + "|" + mask + "|" + gw
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

// showRouteTableDialog opens (or focuses) the modeless Route Table dialog.
func showRouteTableDialog(parent HWND) {
	if hwndRouteTableDlg != 0 {
		setForegroundWindow(hwndRouteTableDlg)
		return
	}

	routeAllRows = nil
	routeFilterText = ""

	registerDialogClass("NetScopeRouteTable", routeTableWndProc)

	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetScopeRouteTable",
		"Route Table",
		WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
		0, 0, 780, 480,
		parent, 0, getModuleHandle(),
	)
	if err != nil || dlg == 0 {
		return
	}
	centerWindowOver(dlg, parent)
	setFontAllChildren(dlg, appFont)
	showWindow(dlg, SW_SHOW)
	updateWindow(dlg)
	hwndRouteTableDlg = dlg
	atomic.StoreUintptr(&hwndRouteTableDialogAtomic, uintptr(dlg))

	if !requestRouteSnapshot() {
		showInfo(dlg,
			"The sensor service is not running.\n\nStart or elevate the sensor from the toolbar, then use Refresh.",
			"Route Table")
	}
}

// closeRouteTableDialog tears down the Route Table dialog.
func closeRouteTableDialog() {
	if hwndRouteTableDlg == 0 {
		return
	}
	atomic.StoreUintptr(&hwndRouteTableDialogAtomic, 0)
	destroyWindow(hwndRouteTableDlg)
	hwndRouteTableDlg = 0
	hwndRouteList = 0
	hwndRouteFilter = 0
	hwndRouteLoadingHint = 0
	routeAllRows = nil
}
