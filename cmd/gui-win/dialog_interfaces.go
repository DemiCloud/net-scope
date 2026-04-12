//go:build windows

// dialog_interfaces.go — Local Network Interfaces viewer dialog.
//
// Opened via Tools > Local Interfaces…
// Shows all local network interfaces with every detail the OS exposes.
//
// Layout:
//   ┌──────────────────────────────────────────────────────────┐
//   │  Filter…                                                  │
//   ├──────────────────────────────────────────────────────────┤
//   │  Interface │ Type │ State │ MAC │ IPv4                   │  ← summary list
//   │  …                                                        │
//   ├── Properties ─────────────────────────────────────────────┤
//   │  Attribute │ Value                                        │  ← detail list
//   │  …                                                        │
//   ├──────────────────────────────────────────────────────────┤
//   │  [Refresh]                                                │
//   └──────────────────────────────────────────────────────────┘
//
// Selecting a row in the summary list populates the Properties panel below
// with every field available for that adapter. Empty / zero fields are omitted.

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
	idIfFilter  = 1700
	idIfList    = 1701
	idIfRefresh = 1702
	idIfDetails = 1703
)

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

var (
	hwndIfDlg         HWND
	hwndIfList        HWND
	hwndIfDetails     HWND
	hwndIfPropLabel   HWND
	hwndIfFilter      HWND
	hwndIfLoadingHint HWND

	// ifAllRows holds every entry from the last snapshot, enabling filter
	// rebuilds without a new round-trip.
	ifAllRows    []netinfo.InterfaceEntry
	ifFilterText string
)

// Summary columns: condensed view.
var ifSumColTitles = []string{"Interface", "Type", "State", "MAC", "IPv4"}

// Property panel columns.
var ifPropColTitles = []string{"Attribute", "Value"}

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
		}
		return 0

	case WM_NOTIFY:
		nm := (*NMHDR)(unsafe.Pointer(lParam))
		if nm.HwndFrom == uintptr(hwndIfList) && nm.Code == LVN_ITEMCHANGED {
			ifUpdateDetailPanel()
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
	ifPropLblH  int32 = 18
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

	// Summary list (top panel).
	listY := ifPad + ifFilterH + ifFilterGap
	topH, _, propY, propH := ifPanelLayout(cW, cH)

	lv, _ := createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS|LVS_SINGLESEL,
		ifPad, listY, cW-ifPad*2, topH, hwnd, HMENU(idIfList), inst)
	sendMessage(lv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP)
	subclassListViewManaged(lv, ifSumColTitles, nil, nil, nil, func(hw HWND, row int32, pt POINT) {
		showIfContextMenu(getParent(hw), row, pt)
	})
	sumWidths := ifSumColWidths(cW - ifPad*2)
	for i, title := range ifSumColTitles {
		listViewAddColumn(lv, int32(i), title, sumWidths[i])
	}
	hwndIfList = lv

	// "Loading…" hint overlay (hidden once data arrives).
	hintY := listY + topH/2 - 9
	hwndIfLoadingHint, _ = createWindowEx(0, "STATIC", "Loading\u2026",
		WS_CHILD|WS_VISIBLE|SS_CENTER,
		ifPad, hintY, cW-ifPad*2, 18, hwnd, 0, inst)

	// "Properties" section label.
	lblY := propY - ifPropLblH - 2
	hwndIfPropLabel, _ = createWindowEx(0, "STATIC", "Properties",
		WS_CHILD|WS_VISIBLE|SS_LEFT,
		ifPad, lblY, cW-ifPad*2, ifPropLblH, hwnd, 0, inst)

	// Detail list (bottom panel) — read-only, no selection.
	det, _ := createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		ifPad, propY, cW-ifPad*2, propH, hwnd, HMENU(idIfDetails), inst)
	sendMessage(det, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER)
	subclassListViewManaged(det, ifPropColTitles, nil, nil, nil, func(hw HWND, row int32, pt POINT) {
		showIfPropContextMenu(getParent(hw), row, pt)
	})
	propWidths := ifPropColWidths(cW - ifPad*2)
	for i, title := range ifPropColTitles {
		listViewAddColumn(det, int32(i), title, propWidths[i])
	}
	hwndIfDetails = det

	// Footer button.
	btnY := cH - ifPad - ifBtnH
	makePushButton(hwnd, "Refresh", idIfRefresh, ifPad, btnY, 80, ifBtnH)
}

// ifPanelLayout returns the heights and Y positions of the summary (top) and
// property (bottom) panels.  Both share the space between the filter and the
// footer.  Top takes 40%, bottom takes 55%, with a small gap + label between.
func ifPanelLayout(cW, cH int32) (topH, topY, propY, propH int32) {
	topY = ifPad + ifFilterH + ifFilterGap
	btnY := cH - ifPad - ifBtnH
	total := btnY - topY - ifPad // total available between filter and footer

	// Deduct space for the label.
	labelGap := ifPropLblH + 4 // label + spacing above it
	available := total - labelGap
	if available < 80 {
		available = 80
	}
	topH = available * 40 / 100
	if topH < 60 {
		topH = 60
	}
	propH = available - topH
	if propH < 60 {
		propH = 60
	}
	propY = topY + topH + labelGap
	return
}

func resizeIfControls(hwnd HWND) {
	if hwndIfList == 0 {
		return
	}
	r := getClientRect(hwnd)
	cW, cH := r.Right, r.Bottom

	listY := ifPad + ifFilterH + ifFilterGap
	topH, _, propY, propH := ifPanelLayout(cW, cH)
	lblY := propY - ifPropLblH - 2

	setWindowPos(hwndIfFilter, 0, ifPad, ifPad, cW-ifPad*2, ifFilterH, SWP_NOZORDER|SWP_NOACTIVATE)
	setWindowPos(hwndIfList, 0, ifPad, listY, cW-ifPad*2, topH, SWP_NOZORDER|SWP_NOACTIVATE)
	setWindowPos(hwndIfPropLabel, 0, ifPad, lblY, cW-ifPad*2, ifPropLblH, SWP_NOZORDER|SWP_NOACTIVATE)
	setWindowPos(hwndIfDetails, 0, ifPad, propY, cW-ifPad*2, propH, SWP_NOZORDER|SWP_NOACTIVATE)

	sumWidths := ifSumColWidths(cW - ifPad*2)
	for i, w := range sumWidths {
		sendMessage(hwndIfList, LVM_SETCOLUMNWIDTH, uintptr(i), uintptr(uint32(w)))
	}
	propWidths := ifPropColWidths(cW - ifPad*2)
	for i, w := range propWidths {
		sendMessage(hwndIfDetails, LVM_SETCOLUMNWIDTH, uintptr(i), uintptr(uint32(w)))
	}

	hintY := listY + topH/2 - 9
	setWindowPos(hwndIfLoadingHint, 0, ifPad, hintY, cW-ifPad*2, 18, SWP_NOZORDER|SWP_NOACTIVATE)
}

func ifSumColWidths(total int32) []int32 {
	typeW  := int32(70)
	stateW := int32(55)
	macW   := int32(135)
	rem := total - typeW - stateW - macW - 4
	if rem < 140 {
		rem = 140
	}
	nameW := rem * 2 / 5
	ipv4W := rem - nameW
	return []int32{nameW, typeW, stateW, macW, ipv4W}
}

func ifPropColWidths(total int32) []int32 {
	attrW := total * 28 / 100
	if attrW < 120 {
		attrW = 120
	}
	return []int32{attrW, total - attrW - 2}
}

// ---------------------------------------------------------------------------
// Context menus
// ---------------------------------------------------------------------------

func showIfContextMenu(parent HWND, row int32, pt POINT) {
	menu := createPopupMenu()
	defer destroyMenu(menu)

	mf := func() uint32 {
		if row < 0 {
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
			copyToClipboard(parent, listViewGetRowTSV(hwndIfList, row, int32(len(ifSumColTitles))))
		}
	default:
		rows := listViewGetSelectedRows(hwndIfList)
		handleCopyAsCmd(parent, hwndIfList, cmd, rows, int32(len(ifSumColTitles)), ifSumColTitles, nil)
	}
}

func showIfPropContextMenu(parent HWND, row int32, pt POINT) {
	if row < 0 {
		return
	}
	menu := createPopupMenu()
	defer destroyMenu(menu)
	appendMenu(menu, MF_STRING, 3010, "Copy Value")
	appendMenu(menu, MF_STRING, 3011, "Copy Row")

	cmd := trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, pt.X, pt.Y, parent)
	switch cmd {
	case 3010:
		copyToClipboard(parent, listViewSelectedText(hwndIfDetails, 1))
	case 3011:
		if row >= 0 {
			copyToClipboard(parent, listViewGetRowTSV(hwndIfDetails, row, 2))
		}
	}
}

// ---------------------------------------------------------------------------
// Detail panel
// ---------------------------------------------------------------------------

// ifUpdateDetailPanel refreshes the Properties list to show all fields
// for the currently selected row in the summary list.
func ifUpdateDetailPanel() {
	if hwndIfDetails == 0 {
		return
	}
	sendMessage(hwndIfDetails, LVM_DELETEALLITEMS, 0, 0)
	rows := listViewGetSelectedRows(hwndIfList)
	if len(rows) == 0 {
		return
	}
	// Map list-view row back to the InterfaceEntry.
	// ifAllRows is in original (unfiltered) order; visible rows may be a subset.
	// We recover the entry by matching the Interface name from column 0.
	name := listViewGetCellText(hwndIfList, rows[0], 0)
	for _, e := range ifAllRows {
		if e.Name == name {
			ifPopulateDetails(e)
			return
		}
	}
}

// ifPopulateDetails inserts key-value property rows for e into hwndIfDetails.
func ifPopulateDetails(e netinfo.InterfaceEntry) {
	add := func(attr, value string) {
		if value == "" || value == "0" {
			return
		}
		listViewAppendRow(hwndIfDetails, []string{attr, value})
	}
	addif := func(attr, value string, cond bool) {
		if cond {
			add(attr, value)
		}
	}

	add("Interface", e.Name)
	add("Description", e.Description)
	add("Index", fmt.Sprintf("%d", e.Index))
	add("Type", e.Type)
	add("State", e.State)
	add("Oper State", e.OperState)
	add("MAC", e.MAC)

	addif("Broadcast", "yes", e.Broadcast)
	addif("Multicast", "yes", e.Multicast)
	addif("Point-to-Point", "yes", e.PointToPoint)

	for i, a := range e.Addrs4 {
		label := "IPv4"
		if len(e.Addrs4) > 1 {
			label = fmt.Sprintf("IPv4 [%d]", i+1)
		}
		add(label, a)
	}
	for i, a := range e.Addrs6 {
		label := "IPv6"
		if len(e.Addrs6) > 1 {
			label = fmt.Sprintf("IPv6 [%d]", i+1)
		}
		add(label, a)
	}

	add("Gateway (IPv4)", e.Gateway4)

	if e.MTU > 0 {
		add("MTU", fmt.Sprintf("%d bytes", e.MTU))
	}
	if e.Speed > 0 {
		add("Speed", fmtIfSpeed(e.Speed))
	}
	add("Duplex", e.Duplex)

	for i, s := range e.DNSServers {
		label := "DNS Server"
		if len(e.DNSServers) > 1 {
			label = fmt.Sprintf("DNS Server [%d]", i+1)
		}
		add(label, s)
	}
	add("DNS Suffix", e.DNSSuffix)

	if e.DHCPEnabled {
		add("DHCP", "enabled")
	}
	add("DHCP Server", e.DHCPServer)
	add("DHCP Lease Expiry", e.DHCPLeaseExpiry)

	if e.RXBytes > 0 || e.TXBytes > 0 {
		add("Received (bytes)", fmtBytes(e.RXBytes))
		add("Received (packets)", fmtCount(e.RXPackets))
		add("Received (errors)", fmtCount(e.RXErrors))
		add("Received (dropped)", fmtCount(e.RXDropped))
		add("Sent (bytes)", fmtBytes(e.TXBytes))
		add("Sent (packets)", fmtCount(e.TXPackets))
		add("Sent (errors)", fmtCount(e.TXErrors))
		add("Sent (dropped)", fmtCount(e.TXDropped))
	}
}

// fmtIfSpeed returns a human-readable speed string, e.g. "1 Gbps", "100 Mbps".
func fmtIfSpeed(mbps int64) string {
	if mbps >= 1000 && mbps%1000 == 0 {
		return fmt.Sprintf("%d Gbps", mbps/1000)
	}
	return fmt.Sprintf("%d Mbps", mbps)
}

// fmtBytes formats a byte count with a SI suffix.
func fmtBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB (%d)", float64(n)/float64(1<<30), n)
	case n >= 1<<20:
		return fmt.Sprintf("%.2f MB (%d)", float64(n)/float64(1<<20), n)
	case n >= 1<<10:
		return fmt.Sprintf("%.2f KB (%d)", float64(n)/float64(1<<10), n)
	default:
		return fmt.Sprintf("%d", n)
	}
}

// fmtCount formats a packet/error counter with comma grouping.
func fmtCount(n uint64) string {
	if n == 0 {
		return "0"
	}
	s := fmt.Sprintf("%d", n)
	// Insert commas.
	out := make([]byte, 0, len(s)+len(s)/3)
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(c))
	}
	return string(out)
}

// ---------------------------------------------------------------------------
// Data population
// ---------------------------------------------------------------------------

// interfacesDialogAddRow is called on the UI thread for each WM_IF_SNAP_ENTRY.
func interfacesDialogAddRow(e netinfo.InterfaceEntry) {
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
	if hwndIfDetails != 0 {
		sendMessage(hwndIfDetails, LVM_DELETEALLITEMS, 0, 0)
	}
	if hwndIfLoadingHint != 0 {
		showWindow(hwndIfLoadingHint, SW_SHOW)
	}
	ifAllRows = nil
	requestIfSnapshot()
}

// ifRepopulate rebuilds the summary list from ifAllRows applying the current filter.
func ifRepopulate() {
	sendMessage(hwndIfList, LVM_DELETEALLITEMS, 0, 0)
	sendMessage(hwndIfDetails, LVM_DELETEALLITEMS, 0, 0)
	for _, e := range ifAllRows {
		if ifFilterText != "" && !ifEntryMatchesFilter(e, ifFilterText) {
			continue
		}
		ifInsertRow(hwndIfList, e)
	}
}

func ifInsertRow(lv HWND, e netinfo.InterfaceEntry) {
	listViewAppendRow(lv, []string{
		e.Name,
		e.Type,
		e.State,
		e.MAC,
		strings.Join(e.Addrs4, ", "),
	})
}

func ifEntryMatchesFilter(e netinfo.InterfaceEntry, f string) bool {
	haystack := strings.Join([]string{
		e.Name, e.Type, e.State, e.MAC,
		strings.Join(e.Addrs4, " "),
		strings.Join(e.Addrs6, " "),
		e.Gateway4, e.Description, e.DNSSuffix, e.DHCPServer,
		strings.Join(e.DNSServers, " "),
		e.OperState,
		fmt.Sprintf("%d", e.MTU),
	}, " ")
	return strings.Contains(strings.ToLower(haystack), f)
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
		0, 0, 860, 560,
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
	hwndIfDetails = 0
	hwndIfPropLabel = 0
	hwndIfFilter = 0
	hwndIfLoadingHint = 0
	ifAllRows = nil
}

