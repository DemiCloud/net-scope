//go:build windows

package guiwin

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// ---------------------------------------------------------------------------
// Service detail dialog
//
// Opened by double-clicking a row in the Services tab or from View All
// Services.  Mirrors the Host detail dialog structure:
//
//  ┌─ Service — OpenSSH · 192.168.1.10 · 22 ─────────────────────────────┐
//  │ Name:     OpenSSH                                                      │
//  │ IP:       192.168.1.10                                                 │
//  │ Hostname: myhost                                                       │
//  │ Port:     22      Source: Port scan (95% confidence)                   │
//  ├────────────────────────────────────────────────────────────────────────│
//  │ Interactions  (placeholder — to be wired in a future release)         │
//  ├────────────────────────────────────────────────────────────────────────│
//  │ Observations                                                           │
//  │ ┌──────────────┬──────────────────────────────────────────────────┐   │
//  │ │ Attribute    │ Value                                            │   │
//  │ └──────────────┴──────────────────────────────────────────────────┘   │
//  │  [View Host]                                              [Close]     │
//  └────────────────────────────────────────────────────────────────────────┘
// ---------------------------------------------------------------------------

const (
	idSvcDetailClose    = 740
	idSvcDetailViewHost = 741
	idSvcDetailObsList  = 742 // listview control ID
)

// Dialog-local handles.
var (
	hwndSvcSummary HWND // identity body EDIT
	hwndSvcObsList HWND // observations listview
	hwndSvcObsHint HWND // "No observations" overlay
)

// currentSvcDetail holds the entry currently shown in the service detail dialog.
var currentSvcDetail svcTabEntry

// svcDetailWndProc is the window procedure for the service detail modal.
var svcDetailWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createSvcDetailControls(HWND(hwnd))
		return 0

	case WM_CTLCOLORSTATIC:
		if isEmptyStateOverlay(HWND(lParam)) {
			return applyEmptyStateColor(wParam)
		}
		return ctlColorDialog(wParam)

	case WM_CTLCOLOREDIT:
		return ctlColorDlgBody(wParam)

	case WM_COMMAND:
		switch loword(wParam) {
		case idSvcDetailClose:
			closeModal(HWND(hwnd))
		case idSvcDetailViewHost:
			ip := currentSvcDetail.ip
			closeModal(HWND(hwnd))
			if ip != "" {
				showHostDetailDialog(hwndMain, ip)
			}
		}
		return 0

	case WM_CLOSE:
		closeModal(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

// showServiceDetailDialog opens the modal service detail dialog for e.
func showServiceDetailDialog(parent HWND, e svcTabEntry) {
	currentSvcDetail = e

	name := svcEntryDisplayName(e)
	portPart := svcEntryPortStr(e)
	title := fmt.Sprintf("Service \u2014 %s \u00b7 %s \u00b7 %s", name, e.ip, portPart)

	registerDialogClass("NetScopeSvcDetail", svcDetailWndProc)
	dlg := createAndCenterDialog("NetScopeSvcDetail", title, 640, 560, svcDetailWndProc, parent)
	if dlg == 0 {
		return
	}

	setWindowText(hwndSvcSummary, buildSvcSummary(e))
	svcDetailPopulateObservations(e)

	setFontAllChildren(dlg, appFont)
	sendMessage(hwndSvcSummary, WM_SETFONT, uintptr(getMonoFont()), 1)

	runModal(dlg, parent)
}

// createSvcDetailControls builds all child controls for the service detail dialog.
func createSvcDetailControls(hwnd HWND) {
	inst := getModuleHandle()
	r := getClientRect(hwnd)
	cW := r.Right
	cH := r.Bottom
	const pad int32 = 10

	// ── Section 1: Service Identity ──────────────────────────────────────
	y := pad

	const summaryH int32 = 72
	hwndSvcSummary, _ = createWindowEx(0, "EDIT", "",
		WS_CHILD|WS_VISIBLE|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
		pad, y, cW-pad*2, summaryH, hwnd, 0, inst)
	y += summaryH + 6

	createDlgSeparator(hwnd, inst, pad, y, cW-pad*2)
	y += 10

	// ── Section 2: Interactions (stub) ───────────────────────────────────
	createCtrl("STATIC", "Interactions", WS_CHILD|WS_VISIBLE, pad, y+2, 110, 14, hwnd, 0, inst)
	createCtrl("STATIC", "Interactions will be available in a future release.",
		WS_CHILD|WS_VISIBLE, pad+116, y+2, cW-pad*2-116, 14, hwnd, 0, inst)
	y += 22

	createDlgSeparator(hwnd, inst, pad, y, cW-pad*2)
	y += 10

	// ── Section 3: Observations ───────────────────────────────────────────
	createCtrl("STATIC", "Observations", WS_CHILD|WS_VISIBLE, pad, y+2, 110, 14, hwnd, 0, inst)
	y += 20

	const btnRowH int32 = pad + 28 + pad
	obsH := cH - y - btnRowH
	if obsH < 60 {
		obsH = 60
	}
	const colAttrW int32 = 160
	hwndSvcObsList, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		pad, y, cW-pad*2, obsH, hwnd, HMENU(idSvcDetailObsList), inst)
	sendMessage(hwndSvcObsList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER)
	subclassListViewManaged(hwndSvcObsList, []string{"Attribute", "Value"}, nil, nil, nil, nil)
	listViewAddColumn(hwndSvcObsList, 0, "Attribute", colAttrW)
	listViewAddColumn(hwndSvcObsList, 1, "Value", cW-pad*2-colAttrW-4)

	hwndSvcObsHint = createEmptyStateOverlay(hwnd, "No observations",
		pad, y+(obsH-18)/2, cW-pad*2, 18)
	showWindow(hwndSvcObsHint, SW_SHOW)

	// Footer.
	btnY := cH - pad - 28
	makePushButton(hwnd, "View Host", idSvcDetailViewHost, pad, btnY, 90, 28)
	makePushButton(hwnd, "Close", idSvcDetailClose, cW-pad-80, btnY, 80, 28)
}

// svcDetailAddObsRow appends one attribute/value row to hwndSvcObsList.
func svcDetailAddObsRow(attr, value string) {
	showWindow(hwndSvcObsHint, SW_HIDE)
	p := utf16(attr)
	item := LVITEM{Mask: LVIF_TEXT, IItem: 0x7fffffff, PszText: p}
	row := int32(sendMessage(hwndSvcObsList, LVM_INSERTITEM, 0, uintptr(unsafe.Pointer(&item))))
	if row < 0 {
		return
	}
	setSubItem(hwndSvcObsList, row, 1, value)
}

// svcDetailPopulateObservations fills the Observations listview for e.
func svcDetailPopulateObservations(e svcTabEntry) {
	sendMessage(hwndSvcObsList, LVM_DELETEALLITEMS, 0, 0)
	showWindow(hwndSvcObsHint, SW_SHOW)

	switch e.kind {
	case svcKindPort:
		ps := e.ps
		if ps.Version != "" {
			svcDetailAddObsRow("Version", ps.Version)
		}
		if ps.Banner != "" {
			svcDetailAddObsRow("Banner", ps.Banner)
		}
		if ps.TLSCert != "" {
			svcDetailAddObsRow("TLS Certificate", ps.TLSCert)
		}
		if ps.ALPN != "" {
			svcDetailAddObsRow("ALPN Protocol", ps.ALPN)
		}
		if ps.Confidence > 0 {
			svcDetailAddObsRow("Confidence", fmt.Sprintf("%d%%", ps.Confidence))
		}
		for _, kv := range svcDetailRows(ps.Details) {
			svcDetailAddObsRow(kv[0], kv[1])
		}
		svcDetailAddObsRow("Service ID", e.id)

	default:
		svc := e.svc
		if svc.Type != "" {
			svcDetailAddObsRow("Type", svc.Type)
		}
		// Parse TXT records / SSDP headers into key=value pairs where possible.
		for _, d := range svc.Details {
			eq := strings.IndexByte(d, '=')
			if eq > 0 {
				svcDetailAddObsRow(d[:eq], d[eq+1:])
			} else if strings.HasPrefix(d, "http://") || strings.HasPrefix(d, "https://") {
				svcDetailAddObsRow("URL", d)
			} else if d != "" {
				svcDetailAddObsRow("Detail", d)
			}
		}
		svcDetailAddObsRow("Source", strings.ToUpper(svc.Source))
		svcDetailAddObsRow("Service ID", e.id)
	}
}

// buildSvcSummary returns the identity block text for the summary EDIT.
func buildSvcSummary(e svcTabEntry) string {
	var b strings.Builder

	name := svcEntryDisplayName(e)
	fmt.Fprintf(&b, "Name:     %s\r\n", name)
	fmt.Fprintf(&b, "IP:       %s\r\n", e.ip)
	hostname := e.hostname
	if hostname == "" {
		hostname = "\u2014"
	}
	fmt.Fprintf(&b, "Hostname: %s\r\n", hostname)
	switch e.kind {
	case svcKindPort:
		fmt.Fprintf(&b, "Port:     %s      Source:  Port scan (%d%% confidence)\r\n",
			strconv.Itoa(e.ps.Port), e.ps.Confidence)
	default:
		fmt.Fprintf(&b, "Source:   %s      Type:    %s\r\n",
			strings.ToUpper(e.kind), e.svc.Type)
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// View All Services dialog — all sources, all confidence levels.
// ---------------------------------------------------------------------------

const idAllSvcsDlgClose = 750

var (
	hwndAllSvcsDlgList HWND
	allSvcsDlgEntries  = map[int32]svcTabEntry{} // row → entry
)

func allSvcsDlgHeaders() []string {
	return []string{"Service Name", "IP", "Hostname", "Source", "Version / Type"}
}

func allSvcsDlgColWidths(total int32) []int32 {
	fixed := int32(120 + 160 + 70)
	nameW := int32(180)
	restW := total - nameW - fixed - 5
	if restW < 100 {
		restW = 100
	}
	return []int32{nameW, 120, 160, 70, restW}
}

var allSvcsDlgWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		inst := getModuleHandle()
		r := getClientRect(HWND(hwnd))
		cW, cH := r.Right, r.Bottom
		const pad int32 = 10
		const hintH int32 = 16
		const btnH int32 = 26

		listH := cH - pad - hintH - pad - btnH - pad

		lv, _ := createWindowEx(0, WC_LISTVIEW, "",
			WS_CHILD|WS_VISIBLE|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS|LVS_SINGLESEL,
			pad, pad, cW-pad*2, listH, HWND(hwnd), HMENU(idAllSvcsDlgClose+1), inst)
		sendMessage(lv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
			LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP)
		hdrs := allSvcsDlgHeaders()
		subclassListViewManaged(lv, hdrs, nil, nil, nil, nil)
		widths := allSvcsDlgColWidths(cW - pad*2)
		for i, h := range hdrs {
			listViewAddColumn(lv, int32(i), h, widths[i])
		}
		allSvcsDlgPopulate(lv)

		hintY := pad + listH + pad/2
		createWindowEx(0, "STATIC",
			"Double-click or Enter to open service details  \u00b7  all sources and confidence levels",
			WS_CHILD|WS_VISIBLE,
			pad, hintY, cW-pad*2-110, hintH, HWND(hwnd), 0, inst)

		makePushButton(HWND(hwnd), "Close", idAllSvcsDlgClose,
			cW-pad-100, cH-pad-btnH, 100, btnH)

		hwndAllSvcsDlgList = lv
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_COMMAND:
		if loword(wParam) == idAllSvcsDlgClose {
			closeModal(HWND(hwnd))
		}
		return 0

	case WM_NOTIFY:
		hdr := (*NMHDR)(unsafe.Pointer(lParam)) //nolint:govet
		if hdr.HwndFrom != uintptr(hwndAllSvcsDlgList) {
			return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
		}
		if hdr.Code == NM_DBLCLK {
			openAllSvcsSelectedRow(HWND(hwnd))
		}
		return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)

	case WM_KEYDOWN:
		if wParam == VK_RETURN {
			openAllSvcsSelectedRow(HWND(hwnd))
		}
		return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)

	case WM_CLOSE:
		closeModal(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

func allSvcsDlgPopulate(sv HWND) {
	allSvcsDlgEntries = map[int32]svcTabEntry{}
	sendMessage(sv, LVM_DELETEALLITEMS, 0, 0)

	shown := map[string]bool{}

	// Everything already in svcTabData (above-threshold port + all discovery).
	for _, e := range svcTabData {
		shown[e.id] = true
		row := allSvcsDlgInsertRow(sv, e)
		if row >= 0 {
			allSvcsDlgEntries[row] = e
		}
	}

	// Below-threshold port services from the registry.
	for _, ip := range allHostIPs() {
		en, ok := hostRegistry[ip]
		if !ok || !en.HasResult {
			continue
		}
		hostname := en.Result.Hostname
		if hostname == "" {
			hostname = en.Result.NetBIOS
		}
		for _, ps := range en.Result.PortServices {
			if shown[ps.ID] {
				continue
			}
			shown[ps.ID] = true
			e := svcTabEntry{id: ps.ID, kind: svcKindPort, ip: ip, hostname: hostname, ps: ps}
			row := allSvcsDlgInsertRow(sv, e)
			if row >= 0 {
				allSvcsDlgEntries[row] = e
			}
		}
	}
}

func allSvcsDlgInsertRow(sv HWND, e svcTabEntry) int32 {
	name := svcEntryDisplayName(e)
	p := utf16(name)
	item := LVITEM{Mask: LVIF_TEXT, IItem: 0x7fffffff, PszText: p}
	row := int32(sendMessage(sv, LVM_INSERTITEM, 0, uintptr(unsafe.Pointer(&item))))
	if row < 0 {
		return -1
	}
	setSubItem(sv, row, 1, e.ip)
	hn := e.hostname
	if hn == "" {
		hn = "\u2014"
	}
	setSubItem(sv, row, 2, hn)
	setSubItem(sv, row, 3, strings.ToUpper(e.kind))
	setSubItem(sv, row, 4, svcEntryVersion(e))
	return row
}

func openAllSvcsSelectedRow(parent HWND) {
	row := int32(sendMessage(hwndAllSvcsDlgList, LVM_GETNEXTITEM, ^uintptr(0), LVNI_SELECTED))
	if row < 0 {
		return
	}
	e, ok := allSvcsDlgEntries[row]
	if !ok {
		return
	}
	closeModal(parent)
	showServiceDetailDialog(hwndMain, e)
}

// showAllServicesDlg opens the unified View All Services dialog.
// Called from the Tools > View All Services menu item.
func showAllServicesDlg(parent HWND) {
	total := len(svcTabData)
	for _, ip := range allHostIPs() {
		if en, ok := hostRegistry[ip]; ok && en.HasResult {
			total += len(en.Result.PortServices)
		}
	}
	if total == 0 {
		messageBox(parent,
			"No services have been discovered yet.\n\n"+
				"Run a scan with Banner Grab enabled, or wait for mDNS / SSDP / WSD traffic.",
			"All Services", MB_OK)
		return
	}

	registerDialogClass("NetScopeAllSvcsDlg", allSvcsDlgWndProc)
	dlg := createAndCenterDialog("NetScopeAllSvcsDlg", "All Services",
		860, 500, allSvcsDlgWndProc, parent)
	if dlg == 0 {
		return
	}
	setFontAllChildren(dlg, appFont)
	runModal(dlg, parent)
}

// ---------------------------------------------------------------------------
// svcDetailRows — protocol-specific detail formatter shared with dialog_host.go
// ---------------------------------------------------------------------------

// svcDetailRows converts a PortService.Details map into ordered [label, value]
// pairs for display in the observations listview.
func svcDetailRows(d map[string]string) [][2]string {
	type rule struct {
		key   string
		label string
	}
	rules := []rule{
		{"smb_dialect", "SMB Dialect"},
		{"smb1", "SMBv1"},
		{"dns_recursion", "DNS Recursion"},
		{"dns_server", "DNS Server"},
		{"ldap_domain", "LDAP Domain"},
		{"ldap_version", "LDAP Version"},
		{"mqtt_anon", "MQTT Anon"},
	}
	var rows [][2]string
	seen := make(map[string]bool, len(d))
	for _, r := range rules {
		if v, ok := d[r.key]; ok && v != "" {
			rows = append(rows, [2]string{r.label, v})
			seen[r.key] = true
		}
	}
	var extra []string
	for k := range d {
		if !seen[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		if v := d[k]; v != "" {
			rows = append(rows, [2]string{k, v})
		}
	}
	return rows
}

