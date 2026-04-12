//go:build windows

package guiwin

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/demicloud/net-scope/internal/scan"
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
	idSvcDetailCopy     = 743 // Copy ▾ footer button
	idSvcDetailCopyFP   = 744 // popup menu: service fingerprint
)

// Dialog-local handles.
var (
	hwndSvcSummary HWND // identity body EDIT
	hwndSvcObsList HWND // observations listview
	hwndSvcObsHint HWND // "No observations" overlay
	hwndSvcCopyBtn HWND // Copy ▾ footer button
)

// currentSvcDetail holds the service currently shown in the service detail dialog.
var currentSvcDetail scan.Service

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
		case idSvcDetailCopy:
			if !shouldSuppressDropdown(HWND(lParam)) {
				showSvcCopyMenu(HWND(hwnd))
			}
		case idSvcDetailViewHost:
			ip := currentSvcDetail.IP
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

// showServiceDetailDialog opens the modal service detail dialog for s.
func showServiceDetailDialog(parent HWND, s scan.Service) {
	currentSvcDetail = s

	name := svcEntryDisplayName(s)
	portPart := svcEntryPortStr(s)
	title := fmt.Sprintf("Service \u2014 %s \u00b7 %s \u00b7 %s", name, s.IP, portPart)

	registerDialogClass("NetScopeSvcDetail", svcDetailWndProc)
	dlg := createDialogForClient("NetScopeSvcDetail", title, 640, 560, svcDetailWndProc, parent)
	if dlg == 0 {
		return
	}

	setWindowText(hwndSvcSummary, buildSvcSummary(s))
	svcDetailPopulateObservations(s)

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

	// Attributes listview

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
	hwndSvcCopyBtn, _ = createWindowEx(0, "BUTTON", "Copy \u25be",
		WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
		pad+90+8, btnY, 80, 28, hwnd, HMENU(idSvcDetailCopy), inst)
	makePushButton(hwnd, "Close", idSvcDetailClose, cW-pad-80, btnY, 80, 28)
}

// svcDetailAddObsRow appends one attribute/value row to hwndSvcObsList.
func svcDetailAddObsRow(attr, value string) {
	showWindow(hwndSvcObsHint, SW_HIDE)
	if listViewAppendRow(hwndSvcObsList, []string{attr, value}) < 0 {
		return
	}
}

// svcDetailPopulateObservations fills the Observations listview for s.
func svcDetailPopulateObservations(s scan.Service) {
	sendMessage(hwndSvcObsList, LVM_DELETEALLITEMS, 0, 0)
	showWindow(hwndSvcObsHint, SW_SHOW)

	for _, obs := range s.Obs {
		val := obs.Value
		if obs.Key == "confidence" {
			val = val + "%"
		}
		svcDetailAddObsRow(obsKeyLabel(obs.Key), val)
	}

	// Derived capabilities (from signature engine).
	if len(s.Capabilities) > 0 {
		caps := make([]string, 0, len(s.Capabilities))
		for k := range s.Capabilities {
			caps = append(caps, k)
		}
		sort.Strings(caps)
		for _, k := range caps {
			claim := s.Capabilities[k]
			svcDetailAddObsRow("Capability: "+k,
				fmt.Sprintf("%d%% confidence", claim.Confidence))
		}
	}

	// Identity fingerprints (from signature engine).
	if len(s.Fingerprints) > 0 {
		fps := make([]string, 0, len(s.Fingerprints))
		for k := range s.Fingerprints {
			fps = append(fps, k)
		}
		sort.Strings(fps)
		for _, k := range fps {
			claim := s.Fingerprints[k]
			svcDetailAddObsRow("Identity: "+k,
				fmt.Sprintf("%d%% confidence", claim.Confidence))
		}
	}

	if s.ID != "" {
		svcDetailAddObsRow("Service ID", s.ID)
	}
}

// showSvcCopyMenu shows a dropdown from the service detail Copy ▾ button.
func showSvcCopyMenu(hwnd HWND) {
	menu := createPopupMenu()
	appendMenu(menu, MF_STRING, idSvcDetailCopyFP, "Service Fingerprint")
	cmd := popupMenuFromButton(hwnd, menu, hwndSvcCopyBtn)
	destroyMenu(menu)
	if int32(cmd) == idSvcDetailCopyFP {
		svcDetailCopyFP(hwnd)
	}
}

// svcDetailCopyFP serialises all service evidence for the current service
// as JSON and puts it on the clipboard. Intended for developer diagnostics.
func svcDetailCopyFP(hwnd HWND) {
	b, err := json.MarshalIndent(currentSvcDetail, "", "    ")
	if err != nil {
		return
	}
	copyToClipboard(hwnd, string(b))
}

// obsKeyLabel maps an observation key to a human-readable column label.
func obsKeyLabel(key string) string {
	labels := map[string]string{
		"name":          "Name",
		"version":       "Version",
		"banner":        "Banner",
		"tls_cert":      "TLS Certificate",
		"alpn":          "ALPN Protocol",
		"http_server":   "HTTP Server Header",
		"confidence":    "Confidence",
		"type":          "Type",
		"instance":      "Instance",
		"smb_dialect":   "SMB Dialect",
		"smb1":          "SMBv1",
		"dns_recursion": "DNS Recursion",
		"dns_server":    "DNS Server",
		"ldap_domain":   "LDAP Domain",
		"ldap_version":  "LDAP Version",
		"mqtt_anon":     "MQTT Anon",
	}
	if l, ok := labels[key]; ok {
		return l
	}
	return key
}

// buildSvcSummary returns the identity block text for the summary EDIT.
func buildSvcSummary(s scan.Service) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Name:     %s\r\n", svcEntryDisplayName(s))
	fmt.Fprintf(&b, "IP:       %s\r\n", s.IP)
	hostname := svcDisplayHostname(s)
	if hostname == "" {
		hostname = "\u2014"
	}
	fmt.Fprintf(&b, "Hostname: %s\r\n", hostname)
	if s.Port > 0 {
		conf := ""
		if s.Confidence > 0 {
			conf = fmt.Sprintf("  (%d%% confidence)", s.Confidence)
		}
		fmt.Fprintf(&b, "Port:     %s      Source: Port scan%s\r\n",
			strconv.Itoa(s.Port), conf)
	} else {
		src := strings.ToUpper(svcFirstSource(s))
		fmt.Fprintf(&b, "Source:   %s\r\n", src)
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// View All Services dialog — all sources, all confidence levels.
// ---------------------------------------------------------------------------

const (
	idAllSvcsDlgClose  = 750
	idAllSvcsDlgFilter = 752
)

var (
	hwndAllSvcsDlgList   HWND
	hwndAllSvcsDlgFilter HWND
	allSvcsDlgEntries    = map[int32]scan.Service{} // row → service
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
		const filterH int32 = 24
		const filterGap int32 = 6

		// Filter edit box.
		filt, _ := createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
			WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,
			pad, pad, cW-pad*2, filterH, HWND(hwnd), HMENU(idAllSvcsDlgFilter), inst)
		cueText := utf16("Filter\u2026")
		sendMessage(filt, EM_SETCUEBANNER, 1, uintptr(unsafe.Pointer(cueText)))
		hwndAllSvcsDlgFilter = filt

		listY := pad + filterH + filterGap
		listH := cH - listY - filterGap - hintH - pad - btnH - pad

		lv, _ := createWindowEx(0, WC_LISTVIEW, "",
			WS_CHILD|WS_VISIBLE|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS|LVS_SINGLESEL,
			pad, listY, cW-pad*2, listH, HWND(hwnd), HMENU(idAllSvcsDlgClose+1), inst)
		sendMessage(lv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
			LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP)
		hdrs := allSvcsDlgHeaders()
		subclassListViewManaged(lv, hdrs, nil, nil, nil, nil)
		widths := allSvcsDlgColWidths(cW - pad*2)
		for i, h := range hdrs {
			listViewAddColumn(lv, int32(i), h, widths[i])
		}
		allSvcsDlgPopulate(lv, "")

		hintY := listY + listH + filterGap
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
		switch loword(wParam) {
		case idAllSvcsDlgClose:
			closeModal(HWND(hwnd))
		case idAllSvcsDlgFilter:
			if hiword(wParam) == EN_CHANGE {
				f := strings.ToLower(getWindowText(hwndAllSvcsDlgFilter))
				allSvcsDlgPopulate(hwndAllSvcsDlgList, f)
			}
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

func allSvcsDlgPopulate(sv HWND, filter string) {
	allSvcsDlgEntries = map[int32]scan.Service{}
	sendMessage(sv, LVM_DELETEALLITEMS, 0, 0)
	for _, s := range svcTabData {
		if filter != "" && !allSvcsDlgMatchesFilter(s, filter) {
			continue
		}
		row := allSvcsDlgInsertRow(sv, s)
		if row >= 0 {
			allSvcsDlgEntries[row] = s
		}
	}
}

func allSvcsDlgMatchesFilter(s scan.Service, f string) bool {
	fields := []string{
		svcEntryDisplayName(s),
		s.IP,
		svcDisplayHostname(s),
		svcEntryVersion(s),
		svcFirstSource(s),
	}
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), f) {
			return true
		}
	}
	return false
}

func allSvcsDlgInsertRow(sv HWND, s scan.Service) int32 {
	hn := svcDisplayHostname(s)
	if hn == "" {
		hn = "\u2014"
	}
	return listViewAppendRow(sv, []string{
		svcEntryDisplayName(s),
		s.IP,
		hn,
		strings.ToUpper(svcFirstSource(s)),
		svcEntryVersion(s),
	})
}

func openAllSvcsSelectedRow(parent HWND) {
	row := int32(sendMessage(hwndAllSvcsDlgList, LVM_GETNEXTITEM, ^uintptr(0), LVNI_SELECTED))
	if row < 0 {
		return
	}
	s, ok := allSvcsDlgEntries[row]
	if !ok {
		return
	}
	closeModal(parent)
	showServiceDetailDialog(hwndMain, s)
}

// showAllServicesDialog opens the unified View All Services dialog.
// Called from the Tools > View All Services menu item.
func showAllServicesDialog(parent HWND) {
	if len(svcTabData) == 0 {
		messageBox(parent,
			"No services have been discovered yet.\n\n"+
				"Run a scan with Banner Grab enabled, or wait for mDNS / SSDP / WSD traffic.",
			"All Services", MB_OK)
		return
	}

	registerDialogClass("NetScopeAllSvcsDlg", allSvcsDlgWndProc)
	dlg := createDialogForClient("NetScopeAllSvcsDlg", "All Services",
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

