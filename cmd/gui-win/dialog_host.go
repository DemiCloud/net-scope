//go:build windows

package guiwin

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/demicloud/net-scope/internal/scan"
)

// ---------------------------------------------------------------------------
// Host detail dialog
// ---------------------------------------------------------------------------
//
// Opened by double-clicking a row in the Hosts listview, or via right-click
// "View details…". Shows a consolidated summary of everything known about the
// selected host, plus an on-demand probe panel.
//
// Layout (740 × 640) — four vertical sections:
//
//  ┌─ Host — 192.168.1.42 ─────────────────────────────────────────────────┐
//  │ Passive only   ·   Sources: mDNS · SSDP   ·   last seen 2m ago        │
//  │ IP: 192.168.1.42   Hostname: myhost   Vendor: Acme                     │
//  │ OS: Linux (72% confidence)                                              │
//  ├────────────────────────────────────────────────────────────────────────│
//  │ Connect  [ Connect ▾ ]                                                  │
//  ├────────────────────────────────────────────────────────────────────────│
//  │ Investigate  Port:[___] Type:[▾] [Run Probe]   [Run Common Probes]     │
//  │ Diagnostics: [Ping]  [Ping continuous]                                  │
//  ├────────────────────────────────────────────────────────────────────────│
//  │ Observations                                                            │
//  │ ┌──────────────┬──────────┬──────────┬──────────────────────────────┐  │
//  │ │ Type         │ Target   │ Source   │ Result                        │  │
//  │ └──────────────┴──────────┴──────────┴──────────────────────────────┘  │
//  │ [Copy Fingerprint]  [Copy Report]                         [Close]      │
//  └────────────────────────────────────────────────────────────────────────┘

const (
	idHostClose  = 601
	idHostForget = 602 // «Forget Host» — removes host from registry

	// idHostCopyReport and idHostCopyFP are used as TPM_RETURNCMD items inside
	// showCopyMenu only — they are NOT posted as WM_COMMAND messages.
	idHostCopyReport = 604
	idHostProbeList  = 608
	idHostCopyFP     = 609
	idHostCopy       = 610 // single «Copy ▾» footer button

	// Connect context-menu item IDs (resolved via TPM_RETURNCMD, not WM_COMMAND).
	idHostConnHTTPS  = 621
	idHostConnHTTP   = 620
	idHostConnSSH    = 622
	idHostConnRDP    = 623
	idHostConnSMB    = 626
	idHostConnFTP    = 624
	idHostConnTelnet = 625
	idHostConnect    = 629 // «Connect ▾» action-strip button

	// Action strip.
	idHostProbes      = 630
	idHostScan        = 631
	idHostDiagnostics = 632

	// Probes sub-dialog.
	idProbesRun  = 642
	idProbesPort = 644
	idProbesType = 645

	// Diagnostics sub-dialog.
	idDiagPing    = 652
	idDiagPingCont = 653
	idDiagTracert = 654

	// Observations listview context menu (TPM_RETURNCMD; not WM_COMMAND).
	idObsCtxCopy   = 660
	idObsCtxDelete = 661
)

// Dialog-local handles (valid while dialog is open).
var (
	// Host detail dialog controls.
	hwndHostStatus       HWND // one-line status: sources + freshness + completeness
	hwndHostSummary      HWND
	hwndHostProbeList    HWND // observations listview
	hwndHostObsHint      HWND // empty-state hint label
	hwndHostCopyBtn      HWND // «Copy ▾» footer dropdown button
	hwndHostCloseBtn     HWND
	hwndHostForgetBtn    HWND // «Forget Host» footer button
	hwndHostConnect      HWND // «Connect ▾» action-strip button
	hwndHostProbesBtn    HWND // «Probes» action-strip button
	hwndHostScanBtn      HWND // «Scan» action-strip button
	hwndHostDiagBtn      HWND // «Diagnostics» action-strip button

	// Probes sub-dialog controls (valid while probes dialog is open).
	hwndProbesPort       HWND
	hwndProbesType       HWND
	hwndProbesRun        HWND
	hwndProbesHostDetail HWND // host detail HWND; restored to hwndActiveProbeDialogAtomic on close

	// currentDetailIP is the IP shown in the dialog right now.
	currentDetailIP string

	// pendingProbeResults: receive loop appends, UI thread reads via WM_PROBE_RESULT.
	pendingProbeResults   []scan.ProbeResult
	pendingProbeResultsMu sync.Mutex

	// activeProbes is the count of probe commands still awaiting a result.
	activeProbes int32
)

// probeKinds lists the probe types shown in the Probes dialog combo.
// "Port Test" maps to ProbeSpec.Type "TCP". All others map 1:1.
var probeKinds = []struct {
	label   string // shown in combo
	ptype   string // ProbeSpec.Type value
	needsPort bool  // false = port field is greyed out
}{
	{"Port Test", "TCP", true},
	{"SSH Banner", "SSH", true},
	{"HTTP(S) Banner", "HTTPS", true},
	{"TLS Info", "TLS", true},
	{"OS Probe", "OSProbe", false},
	{"SNMP", "SNMP", false},
	{"SteamQuery", "Steam", true},
	{"RDP", "RDP", true},
}

// hostDetailWndProc is the window procedure for the host detail dialog.
var hostDetailWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createHostDetailControls(HWND(hwnd))
		return 0

	case WM_CTLCOLORSTATIC:
		// The obs empty-state overlay should appear as gray text on white background.
		if HWND(lParam) == hwndHostObsHint {
			setBkMode(wParam, TRANSPARENT)
			setTextColor(wParam, 0x00999999)
			return uintptr(getSysColorBrush(COLOR_WINDOW))
		}
		return ctlColorDialog(wParam)

	case WM_CTLCOLOREDIT:
		return ctlColorDlgBody(wParam)

	case WM_COMMAND:
		switch loword(wParam) {
		case idHostClose:
			hostDetailClose(HWND(hwnd))
		case idHostForget:
			hostDetailForget(HWND(hwnd))
		case idHostCopy:
			if !shouldSuppressDropdown(HWND(lParam)) {
				showCopyMenu(HWND(hwnd))
			}
		case idHostConnect:
			// lParam is the button HWND; check for spurious re-open from a dismiss click.
			if !shouldSuppressDropdown(HWND(lParam)) {
				showConnectMenu(HWND(hwnd))
			}
		case idHostProbes:
			showProbesDialog(HWND(hwnd))
		case idHostScan:
			hostDetailRunScan(HWND(hwnd))
		case idHostDiagnostics:
			showDiagnosticsDialog(HWND(hwnd))
		}
		return 0

	case WM_NOTIFY:
		nm := (*NMHDR)(unsafe.Pointer(lParam))
		if nm.IdFrom == idHostProbeList && nm.Code == NM_RCLICK {
			showObsContextMenu(HWND(hwnd))
		}
		return 0

	case WM_PROBE_RESULT:
		pendingProbeResultsMu.Lock()
		var pr scan.ProbeResult
		if int(wParam) < len(pendingProbeResults) {
			pr = pendingProbeResults[int(wParam)]
		}
		pendingProbeResultsMu.Unlock()
		if pr.Type != "" {
			hostDetailAddProbeRow(HWND(hwnd), pr)
		}
		// When all probes complete, re-enable the Probes action button.
		if atomic.AddInt32(&activeProbes, -1) == 0 {
			enableWindow(hwndHostProbesBtn, true)
		}
		return 0

	case WM_CLOSE:
		hostDetailClose(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

func hostDetailClose(hwnd HWND) {
	// Clear the probe target so the receive loop stops posting results to
	// this (now-closing) dialog window.
	atomic.StoreUintptr(&hwndActiveProbeDialogAtomic, 0)
	closeModal(hwnd)
}

// buildStatusLine returns a compact one-liner for the status STATIC control
// at the top of the host detail dialog. It shows:
//
//	data completeness  ·  observation sources  ·  freshness
func buildStatusLine(ip string) string {
	e, ok := hostRegistry[ip]
	if !ok {
		return "No prior data"
	}

	var parts []string

	// Data completeness.
	if e.HasResult {
		parts = append(parts, "Port-scanned")
	} else {
		parts = append(parts, "Passive only")
	}

	// Observation sources (mDNS, SSDP, DHCP, etc.).
	seen := map[string]bool{}
	var sources []string
	allSvcs := append(append([]scan.ServiceInfo{}, e.Result.Services...), e.ExtraServices...)
	for _, svc := range allSvcs {
		s := svc.Source
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		sources = append(sources, strings.ToUpper(s[:1])+s[1:])
	}
	if len(e.DHCPEvents) > 0 && !seen["dhcp"] {
		sources = append(sources, "DHCP")
	}
	if len(sources) > 0 {
		parts = append(parts, "Sources: "+strings.Join(sources, " \u00b7 "))
	}

	// Freshness.
	age := time.Since(e.LastSeen)
	switch {
	case age < time.Minute:
		parts = append(parts, fmt.Sprintf("last seen %ds ago", int(age.Seconds())))
	case age < time.Hour:
		parts = append(parts, fmt.Sprintf("last seen %dm ago", int(age.Minutes())))
	default:
		parts = append(parts, "last seen "+e.LastSeen.Format("15:04"))
	}

	return strings.Join(parts, "   \u00b7   ")
}

// showConnectMenu builds a flat protocol menu anchored below the Connect
// button. Items that have a confirmed-open port are enabled; items whose
// port hasn't appeared in a scan result are grayed out. Port numbers are
// not shown in the labels — the user picks by protocol name.
func showConnectMenu(hwnd HWND) {
	type entry struct {
		port  int
		proto string
		label string
		id    int32
	}
	candidates := []entry{
		{443, "https", "HTTPS", idHostConnHTTPS},
		{80, "http", "HTTP", idHostConnHTTP},
		{22, "ssh", "SSH", idHostConnSSH},
		{3389, "rdp", "RDP", idHostConnRDP},
		{445, "smb", "SMB", idHostConnSMB},
		{21, "ftp", "FTP", idHostConnFTP},
		{23, "telnet", "Telnet", idHostConnTelnet},
	}

	menu := createPopupMenu()
	for _, c := range candidates {
		flags := uint32(MF_STRING)
		// Gray unless we have confirmed evidence this port is reachable.
		if !isPortAvailable(currentDetailIP, c.port) {
			flags |= MF_GRAYED
		}
		appendMenu(menu, flags, uintptr(c.id), c.label)
	}

	cmd := popupMenuFromButton(hwnd, menu, hwndHostConnect)
	destroyMenu(menu)

	for _, c := range candidates {
		if int32(cmd) == c.id {
			openProtocol(hwnd, currentDetailIP, c.proto)
			break
		}
	}
}

// hasFPData returns true when the host has enough fingerprint data to make
// the "Copy OS Fingerprint" option meaningful (OS guess, TCP SYN info, banners,
// or SNMP identity).
func hasFPData(ip string) bool {
	e, ok := hostRegistry[ip]
	if !ok {
		return false
	}
	r := e.Result
	return string(r.OS) != "" || r.SYNProbe.WindowSize > 0 ||
		r.Banner.SSH != "" || r.Banner.HTTP != "" || r.Banner.HTTPS != "" ||
		r.Banner.TLSCert != "" || r.SNMP != nil
}

// isPortAvailable returns true if we have positive evidence that port is
// reachable on ip — from a scan result or a successful on-demand probe.
func isPortAvailable(ip string, port int) bool {
	e, ok := hostRegistry[ip]
	if !ok {
		return false
	}
	if portOpen(e.Result, port) {
		return true
	}
	// Any probe on this port that returned a real response counts.
	for _, pr := range e.ProbeResults {
		if pr.Port == port && pr.Result != "" && pr.Result != "no response" &&
			pr.Result != "timeout" && pr.Result != "refused" {
			return true
		}
	}
	return false
}

// showCopyMenu shows a dropdown from the footer Copy ▾ button.
func showCopyMenu(hwnd HWND) {
	fpFlags := uint32(MF_STRING)
	if !hasFPData(currentDetailIP) {
		fpFlags |= MF_GRAYED
	}
	menu := createPopupMenu()
	appendMenu(menu, MF_STRING, idHostCopyReport, "Report")
	appendMenu(menu, fpFlags, idHostCopyFP, "OS Fingerprint")
	cmd := popupMenuFromButton(hwnd, menu, hwndHostCopyBtn)
	destroyMenu(menu)
	switch int32(cmd) {
	case idHostCopyReport:
		hostDetailCopyReport(hwnd)
	case idHostCopyFP:
		hostDetailCopyFP(hwnd)
	}
}

// showObsContextMenu shows a right-click context menu over the Observations listview.
// Offers "Copy row" and "Delete row" actions on the currently selected row.
func showObsContextMenu(hwnd HWND) {
	row := int32(sendMessage(hwndHostProbeList, LVM_GETNEXTITEM, ^uintptr(0), LVNI_SELECTED))
	if row < 0 {
		return
	}
	menu := createPopupMenu()
	appendMenu(menu, MF_STRING, idObsCtxCopy, "Copy")
	appendMenu(menu, MF_STRING, idObsCtxDelete, "Delete")
	pt := getCursorPos()
	cmd := int32(trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, pt.X, pt.Y, hwnd))
	destroyMenu(menu)
	switch cmd {
	case idObsCtxCopy:
		t := listViewGetCellText(hwndHostProbeList, row, 0)
		tgt := listViewGetCellText(hwndHostProbeList, row, 1)
		src := listViewGetCellText(hwndHostProbeList, row, 2)
		res := listViewGetCellText(hwndHostProbeList, row, 3)
		copyToClipboard(hwnd, fmt.Sprintf("%-14s %-10s %-10s %s", t, tgt, src, res))
	case idObsCtxDelete:
		sendMessage(hwndHostProbeList, LVM_DELETEITEM, uintptr(row), 0)
		// Show hint again if list is now empty.
		if sendMessage(hwndHostProbeList, LVM_GETITEMCOUNT, 0, 0) == 0 {
			showWindow(hwndHostObsHint, SW_SHOW)
		}
		hostDetailUpdateCopyButtons()
	}
}

// hostDetailForget asks for confirmation then removes the host from the registry and closes.
func hostDetailForget(hwnd HWND) {
	msg := "Remove " + currentDetailIP + " from the session?\n\nAll observations, scan results, and service history for this host will be deleted. The host may reappear if observed again."
	if messageBox(hwnd, msg, "Forget Host", MB_YESNO|MB_ICONWARNING) != IDYES {
		return
	}
	delete(hostRegistry, currentDetailIP)
	// Remove the row from the main-window host list if present.
	postMessage(hwndMain, WM_HOST_REFRESH, 0, 0)
	hostDetailClose(hwnd)
}

// showHostDetailDialog opens the host detail modal for the given IP.
func showHostDetailDialog(parent HWND, ip string) {
	registerDialogClass("NetScopeHostDetail", hostDetailWndProc)

	// Reset probe state.
	pendingProbeResultsMu.Lock()
	pendingProbeResults = pendingProbeResults[:0]
	pendingProbeResultsMu.Unlock()
	atomic.StoreInt32(&activeProbes, 0)
	currentDetailIP = ip

	const dlgW, dlgH int32 = 740, 640
	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetScopeHostDetail", "Host \u2014 "+ip,
		WS_POPUP|WS_CAPTION|WS_SYSMENU|WS_CLIPCHILDREN,
		0, 0, dlgW, dlgH,
		parent, 0, getModuleHandle(),
	)
	if err != nil || dlg == 0 {
		return
	}
	centerOnParent(dlg, parent, dlgW, dlgH)

	// Auto-create a minimal registry entry so probe/scan results are persisted
	// for manually entered addresses that aren't yet in the session registry.
	// ensureHostEntry initialises hostRegistry if nil — never write directly.
	ensureHostEntry(ip)

	// Fill identity section: status line + summary body.
	setWindowText(hwndHostStatus, buildStatusLine(ip))
	setWindowText(hwndHostSummary, buildHostSummary(ip))

	// Pre-populate observations from passive and prior scan data.
	hostDetailPopulateObservations(ip)

	setFontAllChildren(dlg, appFont)
	// Override the summary pane with a monospace font so padded labels align.
	sendMessage(hwndHostSummary, WM_SETFONT, uintptr(getMonoFont()), 1)

	// Register this dialog as the target for WM_PROBE_RESULT messages from
	// the service receive loop. Cleared by hostDetailClose on close.
	atomic.StoreUintptr(&hwndActiveProbeDialogAtomic, uintptr(dlg))

	runModal(dlg, parent)
}

// createHostDetailControls builds all child controls for the dialog.
// All positions are derived from the actual client rect so they are
// correct regardless of caption-bar height, border size, or DPI.
//
// Layout (740 × 640) — three vertical sections:
//
//  1. Host Identity & State — status line + scrollable summary body
//  2. Actions strip         — [ Connect ▾ ]  [ Probes ]  [ Scan ]  [ Diagnostics ]
//  3. Observations          — heterogeneous listview + footer buttons
func createHostDetailControls(hwnd HWND) {
	inst := getModuleHandle()
	r := getClientRect(hwnd)
	cW := r.Right  // actual client width
	cH := r.Bottom // actual client height
	const pad int32 = 10

	// ── Section 1: Host Identity & State ─────────────────────────────────
	y := pad

	// One-line status: data completeness · observation sources · freshness.
	hwndHostStatus, _ = createWindowEx(0, "STATIC", "",
		WS_CHILD|WS_VISIBLE,
		pad, y, cW-pad*2, 18, hwnd, 0, inst)
	y += 22

	// Summary body: identity-only (hostname, MAC, vendor, OS, timing).
	const summaryH int32 = 110
	hwndHostSummary, _ = createWindowEx(0, "EDIT", "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
		pad, y, cW-pad*2, summaryH, hwnd, 0, inst)
	y += summaryH + 6

	createDlgSeparator(hwnd, inst, pad, y, cW-pad*2)
	y += 10

	// ── Section 2: Actions strip ──────────────────────────────────────────
	// Four intent-driven buttons on one row. No inline probe parameters.
	const actionBtnH int32 = 28
	const actionGap  int32 = 6

	hwndHostScanBtn, _ = createWindowEx(0, "BUTTON", "Scan",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		pad, y, 70, actionBtnH, hwnd, HMENU(idHostScan), inst)

	hwndHostConnect, _ = createWindowEx(0, "BUTTON", "Connect \u25be",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		pad+70+actionGap, y, 100, actionBtnH, hwnd, HMENU(idHostConnect), inst)

	hwndHostProbesBtn, _ = createWindowEx(0, "BUTTON", "Probes",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		pad+70+actionGap+100+actionGap, y, 80, actionBtnH, hwnd, HMENU(idHostProbes), inst)

	hwndHostDiagBtn, _ = createWindowEx(0, "BUTTON", "Diagnostics",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		pad+70+actionGap+100+actionGap+80+actionGap, y, 110, actionBtnH, hwnd, HMENU(idHostDiagnostics), inst)

	y += actionBtnH + 8

	createDlgSeparator(hwnd, inst, pad, y, cW-pad*2)
	y += 10

	// ── Section 3: Observations ───────────────────────────────────────────
	createCtrl("STATIC", "Observations", WS_CHILD|WS_VISIBLE,
		pad, y+3, 100, 14, hwnd, 0, inst)
	y += 20

	// Observations listview: heterogeneous rows (ports, banners, services, OS…).
	const btnRowH int32 = pad + 28 + pad
	obsListH := cH - y - btnRowH
	if obsListH < 60 {
		obsListH = 60
	}
	const (
		colTypeW   int32 = 72
		colTargetW int32 = 68
		colSourceW int32 = 72
	)
	hwndHostProbeList, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		pad, y, cW-pad*2, obsListH, hwnd, HMENU(idHostProbeList), inst)
	sendMessage(hwndHostProbeList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER)
	listViewAddColumn(hwndHostProbeList, 0, "Type", colTypeW)
	listViewAddColumn(hwndHostProbeList, 1, "Target", colTargetW)
	listViewAddColumn(hwndHostProbeList, 2, "Source", colSourceW)
	listViewAddColumn(hwndHostProbeList, 3, "Result", cW-pad*2-colTypeW-colTargetW-colSourceW-4)

	// Empty-state overlay: floats on top of the listview when no rows are present.
	hwndHostObsHint, _ = createWindowEx(0, "STATIC", "No data yet",
		WS_CHILD|WS_VISIBLE|SS_CENTER,
		pad, y+(obsListH-18)/2, cW-pad*2, 18, hwnd, 0, inst)

	// Footer: [ Copy ▾ ]  [ Forget Host ]  ·····  [ Close ]
	// Copy starts disabled; enabled once observations exist.
	btnY := cH - pad - 28
	hwndHostCopyBtn, _ = createWindowEx(0, "BUTTON", "Copy \u25be",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		pad, btnY, 80, 28, hwnd, HMENU(idHostCopy), inst)
	hwndHostForgetBtn, _ = createWindowEx(0, "BUTTON", "Forget Host",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		pad+80+8, btnY, 100, 28, hwnd, HMENU(idHostForget), inst)
	hwndHostCloseBtn, _ = createWindowEx(0, "BUTTON", "Close",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		cW-pad-80, btnY, 80, 28, hwnd, HMENU(idHostClose), inst)
}

// startProbe sends a single on-demand probe to the sensor service.
// Probe results are delivered asynchronously via WM_PROBE_RESULT.
// Returns false when the sensor service is unavailable; the caller is
// responsible for restoring any UI state that was changed before the call.
func startProbe(hwnd HWND, ip string, spec scan.ProbeSpec) bool {
	atomic.AddInt32(&activeProbes, 1)
	if err := sendProbeViaService(ip, spec, appConfig.Scan.SOCKSProxy); err != nil {
		atomic.AddInt32(&activeProbes, -1)
		messageBox(hwnd, "Cannot run probe: the sensor service is not running.\nClick \"Elevate Sensor\" on the main window and try again.", "Probe", MB_ICONWARNING)
		return false
	}
	return true
}

// hostDetailAddObsRow appends one observation row to hwndHostProbeList.
// Columns: Type | Target | Source | Result.
// Hides the empty-state hint on the first insertion.
func hostDetailAddObsRow(obsType, target, source, result string) {
	showWindow(hwndHostObsHint, SW_HIDE)
	p := utf16(obsType)
	item := LVITEM{
		Mask:    LVIF_TEXT,
		IItem:   0x7fffffff, // append
		PszText: p,
	}
	row := int32(sendMessage(hwndHostProbeList, LVM_INSERTITEM, 0, uintptr(unsafe.Pointer(&item))))
	if row < 0 {
		return
	}
	setSubItem(hwndHostProbeList, row, 1, target)
	setSubItem(hwndHostProbeList, row, 2, source)
	setSubItem(hwndHostProbeList, row, 3, result)
}

// hostDetailAddProbeRow maps an on-demand ProbeResult to an observation row
// and persists it to the host registry so it survives dialog close/reopen.
func hostDetailAddProbeRow(_ HWND, pr scan.ProbeResult) {
	result := pr.Result
	if result == "" {
		result = "no response"
	}
	hostDetailAddObsRow(pr.Type, strconv.Itoa(pr.Port), "Probe", result)
	// Persist to registry so this observation survives dialog close/reopen.
	if e, ok := hostRegistry[currentDetailIP]; ok {
		e.ProbeResults = append(e.ProbeResults, pr)
	}
	hostDetailUpdateCopyButtons()
}

// hostDetailUpdateCopyButtons enables the Copy ▾ footer button only when there
// is something to copy.
func hostDetailUpdateCopyButtons() {
	_, known := hostRegistry[currentDetailIP]
	rows := sendMessage(hwndHostProbeList, LVM_GETITEMCOUNT, 0, 0)
	enableWindow(hwndHostCopyBtn, known || rows > 0)
}

// hostDetailPopulateObservations pre-fills the observations table with all
// data already known about ip from passive discovery and prior scans.
// It is called once when the dialog opens, after the controls are ready.
func hostDetailPopulateObservations(ip string) {
	sendMessage(hwndHostProbeList, LVM_DELETEALLITEMS, 0, 0)
	showWindow(hwndHostObsHint, SW_SHOW) // reset to visible; rows will hide it

	e, ok := hostRegistry[ip]
	if !ok {
		return
	}
	r := e.Result

	// Open ports from previous scan.
	for _, p := range r.OpenPorts {
		hostDetailAddObsRow("Port", strconv.Itoa(p), "Scan", "Open")
	}

	// Service banners from scan.
	for _, b := range []struct{ svc, val string }{
		{"SSH", r.Banner.SSH}, {"HTTP", r.Banner.HTTP}, {"HTTPS", r.Banner.HTTPS},
		{"FTP", r.Banner.FTP}, {"SMTP", r.Banner.SMTP}, {"Telnet", r.Banner.Telnet},
	} {
		if b.val != "" {
			hostDetailAddObsRow("Banner", b.svc, "Scan", b.val)
		}
	}

	// TLS certificate fingerprint.
	if r.Banner.TLSCert != "" {
		hostDetailAddObsRow("TLS Cert", "443", "Scan", r.Banner.TLSCert)
	}

	// OS guess (derived, surfaced in observations for traceability).
	if string(r.OS) != "" {
		osLabel := string(r.OS)
		if r.OSConfidence > 0 {
			osLabel = fmt.Sprintf("%s  (%d%% confidence)", r.OS, r.OSConfidence)
		}
		hostDetailAddObsRow("OS Guess", "\u2014", "Inference", osLabel)
	}

	// TCP SYN fingerprint.
	if r.SYNProbe.WindowSize > 0 {
		hostDetailAddObsRow("TCP Fingerprint", "\u2014", "Scan",
			fmt.Sprintf("window=%d  opts=%s", r.SYNProbe.WindowSize, r.SYNProbe.Options))
	}

	// SNMP device identity.
	if r.SNMP != nil && r.SNMP.SysDescr != "" {
		hostDetailAddObsRow("SNMP", "\u2014", "SNMP", r.SNMP.SysDescr)
	}

	// Passive services (mDNS / SSDP / WSD / NetBIOS).
	allSvcs := append(append([]scan.ServiceInfo{}, r.Services...), e.ExtraServices...)
	seen := map[string]bool{}
	for _, svc := range allSvcs {
		key := svc.Source + ":" + svc.Name + ":" + svc.Type
		if seen[key] {
			continue
		}
		seen[key] = true
		name := unescapeDNSLabel(svc.Name)
		if name == "" {
			name = svc.Type
		}
		src := svc.Source
		if src == "" {
			src = "Passive"
		}
		hostDetailAddObsRow("Service", svc.Type, strings.ToUpper(src[:1])+src[1:], name)
	}

	// DHCP events.
	for _, evt := range e.DHCPEvents {
		detail := evt.Type.String()
		if evt.Hostname != "" {
			detail += "  host=" + evt.Hostname
		}
		if evt.OfferedIP != "" && evt.OfferedIP != "0.0.0.0" {
			detail += "  offered=" + evt.OfferedIP
		}
		hostDetailAddObsRow("DHCP", evt.OfferedIP, "DHCP", detail)
	}

	// Persisted probe results from previous interactions this session.
	for _, pr := range e.ProbeResults {
		res := pr.Result
		if res == "" {
			res = "no response"
		}
		hostDetailAddObsRow(pr.Type, strconv.Itoa(pr.Port), "Probe", res)
	}

	hostDetailUpdateCopyButtons()
}

// hostDetailCopyReport builds a plain-text report from the summary and all
// observation rows currently visible in the listview, then puts it on the
// clipboard. Uses the listview directly so the report always matches what
// the user sees — regardless of whether rows came from passive data or probes.
func hostDetailCopyReport(hwnd HWND) {
	var sb strings.Builder
	sb.WriteString(buildHostSummary(currentDetailIP))

	// Observations table.
	n := int(sendMessage(hwndHostProbeList, LVM_GETITEMCOUNT, 0, 0))
	if n > 0 {
		sb.WriteString("\r\n\u2500\u2500 Observations \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\r\n")
		for i := 0; i < n; i++ {
			obsType := listViewGetCellText(hwndHostProbeList, int32(i), 0)
			target  := listViewGetCellText(hwndHostProbeList, int32(i), 1)
			source  := listViewGetCellText(hwndHostProbeList, int32(i), 2)
			result  := listViewGetCellText(hwndHostProbeList, int32(i), 3)
			sb.WriteString(fmt.Sprintf("  %-14s %-10s %-10s %s\r\n", obsType, target, source, result))
		}
	}
	copyToClipboard(hwnd, sb.String())
}

// hostDetailCopyFP copies raw fingerprint signals for the current host as JSON.
func hostDetailCopyFP(hwnd HWND) {
	e, ok := hostRegistry[currentDetailIP]
	if !ok {
		return
	}
	copyToClipboard(hwnd, fpBuildJSON(e.Result))
}

// fpBuildJSON serialises the fingerprint-relevant fields of a scan result as
// indented JSON. Used by the Copy Fingerprint button in the host detail dialog.
//
// Field semantics:
//   - string/slice fields with omitempty: absent = not discovered
//   - icmp_ttl: null = no ICMP response received; number = observed TTL
//   - latency_ms: null = not measured (e.g. no ICMP); number = round-trip ms
//   - syn_probe: null = probe ran but no SYN-ACK captured; object = TCP stack data
//   - banner: null = BannerGrab ran but no recognisable headers; object = banners
//   - snmp: null = SNMP queried but no response; object = sysDescr etc.
func fpBuildJSON(r scan.Result) string {
	type jSYN struct {
		WindowSize uint16 `json:"window_size"`
		Options    string `json:"options"`
	}
	type jBanner struct {
		SSH     string `json:"ssh,omitempty"`
		HTTP    string `json:"http,omitempty"`
		HTTPS   string `json:"https,omitempty"`
		TLSCert string `json:"tls_cert,omitempty"`
		FTP     string `json:"ftp,omitempty"`
		SMTP    string `json:"smtp,omitempty"`
		Telnet  string `json:"telnet,omitempty"`
	}
	type jSNMP struct {
		SysDescr    string `json:"sys_descr,omitempty"`
		SysName     string `json:"sys_name,omitempty"`
		SysLocation string `json:"sys_location,omitempty"`
		SysContact  string `json:"sys_contact,omitempty"`
	}
	type jService struct {
		Source  string   `json:"source"`
		Name    string   `json:"name,omitempty"`
		Type    string   `json:"type,omitempty"`
		Details []string `json:"details,omitempty"`
	}
	type jOut struct {
		IP           string     `json:"ip"`
		Alive        bool       `json:"alive"`
		MAC          string     `json:"mac,omitempty"`
		Vendor       string     `json:"vendor,omitempty"`
		Hostname     string     `json:"hostname,omitempty"`
		NetBIOS      string     `json:"netbios,omitempty"`
		LatencyMs    *int64     `json:"latency_ms"`  // null = not measured
		OpenPorts    []int      `json:"open_ports,omitempty"`
		OS           string     `json:"os"`
		OSConfidence uint8      `json:"os_confidence"`
		ICMPTTL      *uint8     `json:"icmp_ttl"`    // null = no ICMP response
		SYN          *jSYN      `json:"syn_probe"`   // null = probe ran, no SYN-ACK
		Banner       *jBanner   `json:"banner"`      // null = grab ran, no headers
		SNMP         *jSNMP     `json:"snmp"`        // null = queried, no response
		Services     []jService `json:"services,omitempty"`
	}

	out := jOut{
		IP:           r.IP.String(),
		Alive:        r.Alive,
		Vendor:       r.Vendor,
		Hostname:     r.Hostname,
		NetBIOS:      r.NetBIOS,
		OpenPorts:    r.OpenPorts,
		OS:           string(r.OS),
		OSConfidence: r.OSConfidence,
	}
	if r.MAC != nil {
		out.MAC = r.MAC.String()
	}
	if r.TTL != 0 {
		ttl := r.TTL
		out.ICMPTTL = &ttl
	}
	if r.Latency != 0 {
		ms := r.Latency.Milliseconds()
		out.LatencyMs = &ms
	}
	if r.SYNProbe.WindowSize > 0 {
		out.SYN = &jSYN{WindowSize: r.SYNProbe.WindowSize, Options: r.SYNProbe.Options}
	}
	b := r.Banner
	if b.SSH != "" || b.HTTP != "" || b.HTTPS != "" || b.TLSCert != "" || b.FTP != "" || b.SMTP != "" || b.Telnet != "" {
		out.Banner = &jBanner{SSH: b.SSH, HTTP: b.HTTP, HTTPS: b.HTTPS, TLSCert: b.TLSCert, FTP: b.FTP, SMTP: b.SMTP, Telnet: b.Telnet}
	}
	if r.SNMP != nil {
		out.SNMP = &jSNMP{
			SysDescr: r.SNMP.SysDescr, SysName: r.SNMP.SysName,
			SysLocation: r.SNMP.SysLocation, SysContact: r.SNMP.SysContact,
		}
	}
	for _, svc := range r.Services {
		out.Services = append(out.Services, jService{
			Source: svc.Source, Name: svc.Name, Type: svc.Type, Details: svc.Details,
		})
	}

	buf, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return `{"error": "marshal failed"}`
	}
	return string(buf)
}

// unescapeDNSLabel removes DNS-SD backslash escapes from a service instance
// name (e.g. "TCL\ C149X\ 4682" → "TCL C149X 4682").
func unescapeDNSLabel(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	skip := false
	for _, r := range s {
		if skip {
			b.WriteRune(r)
			skip = false
			continue
		}
		if r == '\\' {
			skip = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// monoFont is a Consolas font for the summary EDIT control so that
// manually-padded labels align correctly with a proportional window font.
var (
	monoFont     HFONT
	monoFontOnce sync.Once
)

func getMonoFont() HFONT {
	monoFontOnce.Do(func() {
		face, _ := syscall.UTF16PtrFromString("Consolas")
		height := int32(-13) // -13px ≈ 10pt at 96 DPI; runtime var avoids constant-overflow
		r, _, _ := procCreateFontW.Call(
			uintptr(height),
			0, 0, 0,
			FW_NORMAL,
			0, 0, 0, 0, 0, 0,
			CLEARTYPE_QUALITY,
			0,
			uintptr(unsafe.Pointer(face)),
		)
		monoFont = HFONT(r)
	})
	return monoFont
}

// buildHostJSON serialises one or more registry entries as a JSON array in the
// same format as scan.WriteJSON / "Export All Hosts as JSON". ExtraServices
// are merged into the scan.Result's Services slice before encoding so broadcast-
// only services are included even when no full scan was run for that host.
func buildHostJSON(ips []string) string {
	results := make([]scan.Result, 0, len(ips))
	for _, ip := range ips {
		e := hostRegistry[ip]
		if e == nil {
			// Host with no registry entry — emit a minimal stub.
			r := scan.Result{}
			r.IP = net.ParseIP(ip)
			results = append(results, r)
			continue
		}
		r := e.Result
		if r.IP == nil {
			r.IP = net.ParseIP(ip)
		}
		// Merge broadcast/passive services that aren't already in r.Services.
		seen := make(map[string]bool, len(r.Services))
		for _, svc := range r.Services {
			seen[svc.Source+"|"+svc.Name] = true
		}
		for _, svc := range e.ExtraServices {
			if !seen[svc.Source+"|"+svc.Name] {
				r.Services = append(r.Services, svc)
			}
		}
		results = append(results, r)
	}
	var buf strings.Builder
	_ = scan.WriteJSON(&buf, results)
	return buf.String()
}

// buildHostSummary returns a concise identity summary for ip.
//
// This covers derived knowledge and stable identity fields only:
// hostname, MAC, vendor, OS belief, timing, SNMP device name.
// Raw observations (ports, banners, services, DHCP) are presented in
// the Observations table and are intentionally excluded here.
func buildHostSummary(ip string) string {
	var sb strings.Builder

	e := hostRegistry[ip]
	if e == nil {
		sb.WriteString("IP:         " + ip + "\r\n")
		sb.WriteString("State:      No data yet\r\n")
		sb.WriteString("OS:         Unknown\r\n")
		return sb.String()
	}

	r := e.Result

	sb.WriteString("IP:         " + ip + "\n")

	// Identity names.
	if r.Hostname != "" {
		sb.WriteString("Hostname:   " + r.Hostname + "\n")
	}
	if r.NetBIOS != "" && r.NetBIOS != r.Hostname {
		sb.WriteString("NetBIOS:    " + r.NetBIOS + "\n")
	}
	if r.MAC != nil {
		sb.WriteString("MAC:        " + r.MAC.String() + "\n")
	}
	if r.Vendor != "" {
		sb.WriteString("Vendor:     " + r.Vendor + "\n")
	}

	// SNMP device name — concise identifier used in SNMP-capable devices.
	if r.SNMP != nil && r.SNMP.SysName != "" {
		sb.WriteString("SNMP name:  " + r.SNMP.SysName + "\n")
	}

	// OS belief — always shown; "Unknown" is a valid and informative state.
	switch {
	case string(r.OS) != "" && r.OSConfidence > 0:
		sb.WriteString(fmt.Sprintf("OS:         %s  (%d%% confidence)\n", r.OS, r.OSConfidence))
	case string(r.OS) != "":
		sb.WriteString("OS:         " + string(r.OS) + "\n")
	default:
		sb.WriteString("OS:         Unknown\n")
	}

	// Network timing (useful for fingerprinting and troubleshooting).
	if r.Latency > 0 {
		line := fmt.Sprintf("Latency:    %s", r.Latency.Round(time.Millisecond))
		if r.TTL > 0 {
			line += fmt.Sprintf("  (TTL %d)", r.TTL)
		}
		sb.WriteString(line + "\n")
	}

	// Timestamps.
	sb.WriteString(fmt.Sprintf("First seen: %s\n", e.FirstSeen.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Last seen:  %s\n", e.LastSeen.Format("2006-01-02 15:04:05")))

	return strings.ReplaceAll(sb.String(), "\n", "\r\n")
}

// ---------------------------------------------------------------------------
// Action strip — Scan
// ---------------------------------------------------------------------------

// hostDetailRunScan queues a targeted scan for currentDetailIP via the main
// window. Sets the target edit box and posts IDC_SCAN to hwndMain so the
// existing scan machinery runs. The host detail dialog stays open; results
// accumulate in the registry and the Observations table will be refreshed on
// the next open.
func hostDetailRunScan(hwnd HWND) {
	setWindowText(hwndTarget, currentDetailIP)
	postMessage(hwndMain, WM_COMMAND, uintptr(IDC_SCAN), 0)
	setWindowText(hwndHostStatus, "Scan queued for "+currentDetailIP+"  \u2014  results appear in the host list")
}

// ---------------------------------------------------------------------------
// Probes sub-dialog
// ---------------------------------------------------------------------------
//
// A focused modal opened from the Probes action button.
// The combo lists semantic probe intents; the port edit is greyed out for
// probes that do not target a specific port.
//
// While this dialog is open it registers itself as the WM_PROBE_RESULT
// target so it receives probe completions in real-time. Observation rows
// are written to hwndHostProbeList (the host detail listview), visible
// behind the disabled-but-open parent dialog, and persisted to the host
// registry so they survive dialog close/reopen.

var probesWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createProbesDialogControls(HWND(hwnd))
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_CTLCOLOREDIT:
		if HWND(lParam) == hwndProbesPort && !isWindowEnabled(hwndProbesPort) {
			return ctlColorDialog(wParam)
		}
		return ctlColorDlgBody(wParam)

	case WM_COMMAND:
		switch loword(wParam) {
		case idProbesRun:
			probesRunSingle(HWND(hwnd))
		case idProbesType:
			if hiword(wParam) == CBN_SELCHANGE {
				probesUpdatePortEnabled()
			}
		}
		return 0

	case WM_PROBE_RESULT:
		pendingProbeResultsMu.Lock()
		var pr scan.ProbeResult
		if int(wParam) < len(pendingProbeResults) {
			pr = pendingProbeResults[int(wParam)]
		}
		pendingProbeResultsMu.Unlock()
		if pr.Type != "" {
			hostDetailAddProbeRow(HWND(hwnd), pr)
		}
		if atomic.AddInt32(&activeProbes, -1) == 0 {
			enableWindow(hwndProbesRun, true)
			setWindowText(hwndProbesRun, "Run Probe")
			enableWindow(hwndHostProbesBtn, true)
		}
		return 0

	case WM_CLOSE:
		probesDialogClose(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

func createProbesDialogControls(hwnd HWND) {
	inst := getModuleHandle()
	r := getClientRect(hwnd)
	cW := r.Right
	const pad int32 = 10

	// Layout: [Probe combo]  [Port: edit]  [Run Probe]
	// Probe type combo on the left; port to its right; run button far right.
	const (
		typeLblW   int32 = 42
		typeComboW int32 = 155
		portLblW   int32 = 34
		portEditW  int32 = 60
		runBtnW    int32 = 100
		gap        int32 = 6
	)
	y := pad
	x := pad

	createCtrl("STATIC", "Probe:", WS_CHILD|WS_VISIBLE,
		x, y+5, typeLblW, 16, hwnd, 0, inst)
	x += typeLblW
	hwndProbesType, _ = createWindowEx(0, "COMBOBOX", "",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|CBS_DROPDOWNLIST,
		x, y, typeComboW, 220, hwnd, HMENU(idProbesType), inst)
	x += typeComboW + gap*2

	createCtrl("STATIC", "Port:", WS_CHILD|WS_VISIBLE,
		x, y+5, portLblW, 16, hwnd, 0, inst)
	x += portLblW
	hwndProbesPort, _ = createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "22",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL,
		x, y, portEditW, 24, hwnd, HMENU(idProbesPort), inst)
	x += portEditW + gap*3

	// Run button flush right.
	hwndProbesRun, _ = createWindowEx(0, "BUTTON", "Run Probe",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		cW-pad-runBtnW, y, runBtnW, 24, hwnd, HMENU(idProbesRun), inst)
	_ = x // suppress unused-variable lint
}

// probesUpdatePortEnabled greys out the port edit when the selected probe
// type does not require a port number.
func probesUpdatePortEnabled() {
	idx := int(sendMessage(hwndProbesType, CB_GETCURSEL, 0, 0))
	if idx < 0 || idx >= len(probeKinds) {
		return
	}
	enableWindow(hwndProbesPort, probeKinds[idx].needsPort)
}

func probesDialogClose(hwnd HWND) {
	// Restore WM_PROBE_RESULT target to the host detail dialog.
	atomic.StoreUintptr(&hwndActiveProbeDialogAtomic, uintptr(hwndProbesHostDetail))
	enableWindow(hwndHostProbesBtn, true)
	closeModal(hwnd)
}

func probesRunSingle(hwnd HWND) {
	idx := int(sendMessage(hwndProbesType, CB_GETCURSEL, 0, 0))
	if idx < 0 || idx >= len(probeKinds) {
		return
	}
	kind := probeKinds[idx]

	port := 0
	if kind.needsPort {
		portStr := strings.TrimSpace(getWindowText(hwndProbesPort))
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			messageBox(hwnd, "Enter a valid port number (1\u201365535).", "Probes", MB_ICONWARNING)
			return
		}
		port = p
	}

	enableWindow(hwndProbesRun, false)
	setWindowText(hwndProbesRun, "Running\u2026")
	if !startProbe(hwnd, currentDetailIP, scan.ProbeSpec{Port: port, Type: kind.ptype}) {
		enableWindow(hwndProbesRun, true)
		setWindowText(hwndProbesRun, "Run Probe")
	}
}

// showProbesDialog opens the Probes sub-dialog for the current host.
// Registers itself as the WM_PROBE_RESULT target while open; restores on close.
func showProbesDialog(parent HWND) {
	registerDialogClass("NetScopeProbes", probesWndProc)
	hwndProbesHostDetail = parent

	// Disable the Probes button while the dialog is open.
	enableWindow(hwndHostProbesBtn, false)

	const dlgW, dlgH int32 = 520, 90
	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetScopeProbes", "Probes \u2014 "+currentDetailIP,
		WS_POPUP|WS_CAPTION|WS_SYSMENU|WS_CLIPCHILDREN,
		0, 0, dlgW, dlgH,
		parent, 0, getModuleHandle(),
	)
	if err != nil || dlg == 0 {
		enableWindow(hwndHostProbesBtn, true)
		return
	}
	centerOnParent(dlg, parent, dlgW, dlgH)

	// Populate the probe kind combo.
	for _, k := range probeKinds {
		pt, _ := syscall.UTF16PtrFromString(k.label)
		sendMessage(hwndProbesType, CB_ADDSTRING, 0, uintptr(unsafe.Pointer(pt)))
	}
	sendMessage(hwndProbesType, CB_SETCURSEL, 0, 0) // default: Port Test
	probesUpdatePortEnabled()

	setFontAllChildren(dlg, appFont)

	// Transfer WM_PROBE_RESULT ownership to this dialog.
	atomic.StoreUintptr(&hwndActiveProbeDialogAtomic, uintptr(dlg))

	runModal(dlg, parent)
	// probesDialogClose restores hwndActiveProbeDialogAtomic before calling closeModal.
}

// ---------------------------------------------------------------------------
// Diagnostics sub-dialog
// ---------------------------------------------------------------------------
//
// A focused modal for network diagnostic tools: ping, continuous ping,
// traceroute. Kept separate from Probes so there is a clear semantic split
// between "gather evidence" (Probes) and "test reachability" (Diagnostics).

var diagWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createDiagnosticsControls(HWND(hwnd))
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_COMMAND:
		switch loword(wParam) {
		case idDiagPing:
			shellExecute(HWND(hwnd), "open", "cmd.exe",
				"/c ping "+currentDetailIP+" && pause", "", SW_SHOW)
		case idDiagPingCont:
			shellExecute(HWND(hwnd), "open", "cmd.exe",
				"/k ping -t "+currentDetailIP, "", SW_SHOW)
		case idDiagTracert:
			shellExecute(HWND(hwnd), "open", "cmd.exe",
				"/c tracert "+currentDetailIP+" && pause", "", SW_SHOW)
		}
		return 0

	case WM_CLOSE:
		closeModal(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

func createDiagnosticsControls(hwnd HWND) {
	inst := getModuleHandle()
	const pad int32 = 10

	y := pad
	x := pad
	const btnH int32 = 26
	const btnGap int32 = 6

	createWindowEx(0, "BUTTON", "Ping once",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		x, y, 90, btnH, hwnd, HMENU(idDiagPing), inst)
	x += 90 + btnGap
	createWindowEx(0, "BUTTON", "Ping continuous",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		x, y, 120, btnH, hwnd, HMENU(idDiagPingCont), inst)
	x += 120 + btnGap
	createWindowEx(0, "BUTTON", "Traceroute",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		x, y, 100, btnH, hwnd, HMENU(idDiagTracert), inst)
	_ = y // all buttons on one row
}

// showDiagnosticsDialog opens the Diagnostics sub-dialog for the current host.
func showDiagnosticsDialog(parent HWND) {
	registerDialogClass("NetScopeDiagnostics", diagWndProc)

	const dlgW, dlgH int32 = 400, 90
	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetScopeDiagnostics", "Diagnostics \u2014 "+currentDetailIP,
		WS_POPUP|WS_CAPTION|WS_SYSMENU|WS_CLIPCHILDREN,
		0, 0, dlgW, dlgH,
		parent, 0, getModuleHandle(),
	)
	if err != nil || dlg == 0 {
		return
	}
	centerOnParent(dlg, parent, dlgW, dlgH)
	setFontAllChildren(dlg, appFont)
	runModal(dlg, parent)
}

// ---------------------------------------------------------------------------
// hostDisplayName returns "IP — hostname" if a hostname is known, else "IP".
func hostDisplayName(ip string) string {
	if e, ok := hostRegistry[ip]; ok {
		name := e.Result.Hostname
		if name == "" {
			name = e.Result.NetBIOS
		}
		if name != "" {
			return ip + "  —  " + name
		}
	}
	return ip
}

// ---------------------------------------------------------------------------
// "View All Hosts" dialog
// ---------------------------------------------------------------------------
//
// A read-only list of every host in the session registry.
// Columns: IP (140 px) | Hostname (remainder).
// Double-clicking a row opens the host-detail dialog for that IP.

const (
	idAllHostsList  = 700
	idAllHostsClose = 701
	// context menu IDs
	idAllHostsCtxDetails = 720
	idAllHostsCtxExport  = 721
	idAllHostsCtxCopy    = 722
)

var (
	hwndAllHostsList HWND
)

// allHostsSelectedIP returns the IP of the currently selected All-Hosts row, or "".
func allHostsSelectedIP() string {
	return listViewSelectedText(hwndAllHostsList, 0)
}

// hostsListViewRepopulate clears hwnd and fills it with IP + hostname rows
// from the session registry, keeping only rows where IP or hostname contains
// filter (case-insensitive). An empty filter shows all hosts.
func hostsListViewRepopulate(hwnd HWND, filter string) {
	filter = strings.ToLower(filter)
	sendMessage(hwnd, LVM_DELETEALLITEMS, 0, 0)
	for _, ip := range allHostIPs() {
		name := ""
		if e, ok := hostRegistry[ip]; ok {
			name = e.Result.Hostname
			if name == "" {
				name = e.Result.NetBIOS
			}
		}
		if filter != "" {
			if !strings.Contains(strings.ToLower(ip), filter) &&
				!strings.Contains(strings.ToLower(name), filter) {
				continue
			}
		}
		p := utf16(ip)
		item := LVITEM{Mask: LVIF_TEXT, IItem: 0x7fffffff, PszText: p}
		row := int32(sendMessage(hwnd, LVM_INSERTITEM, 0, uintptr(unsafe.Pointer(&item))))
		if row >= 0 {
			setSubItem(hwnd, row, 1, name)
		}
	}
}

// allHostsDoAction executes a context-menu action for the given ip.
func allHostsDoAction(dlg HWND, ip string, action int32) {
	switch action {
	case idAllHostsCtxDetails:
		closeModal(dlg)
		showHostDetailDialog(hwndMain, ip)
	case idAllHostsCtxCopy:
		copyToClipboard(dlg, buildHostJSON([]string{ip}))
	case idAllHostsCtxExport:
		path := getSaveFileName(dlg, "Export Host Data", "txt",
			"Text files|*.txt|All files|*.*|")
		if path == "" {
			return
		}
		if err := os.WriteFile(path, []byte(buildHostSummary(ip)), 0o644); err != nil {
			messageBox(dlg, "Could not write file:\n"+err.Error(), "Export Error", MB_OK)
		}
	}
}

var allHostsWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		inst := getModuleHandle()
		r := getClientRect(HWND(hwnd))
		cW, cH := r.Right, r.Bottom
		const pad int32 = 10
		const hintH int32 = 16
		const btnH int32 = 26

		// Listview leaves room for hint label + button row.
		listH := cH - pad - hintH - pad - btnH - pad
		hwndAllHostsList, _ = createWindowEx(0, WC_LISTVIEW, "",
			WS_CHILD|WS_VISIBLE|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS|LVS_SINGLESEL,
			pad, pad, cW-pad*2, listH, HWND(hwnd), HMENU(idAllHostsList), inst)
		sendMessage(hwndAllHostsList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
			LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER)
		listViewAddColumn(hwndAllHostsList, 0, "IP", 140)
		listViewAddColumn(hwndAllHostsList, 1, "Hostname", cW-pad*2-140-4)

		// Hint label between list and buttons.
		hintY := pad + listH + pad/2
		createWindowEx(0, "STATIC",
			"Double-click or Enter for details  ·  Right-click for more options",
			WS_CHILD|WS_VISIBLE,
			pad, hintY, cW-pad*2-110, hintH, HWND(hwnd), 0, inst)

		createWindowEx(0, "BUTTON", "Close",
			WS_CHILD|WS_VISIBLE|WS_TABSTOP,
			cW-pad-100, cH-pad-btnH, 100, btnH, HWND(hwnd), HMENU(idAllHostsClose), inst)

		// Populate rows from registry.
		hostsListViewRepopulate(hwndAllHostsList, "")
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_COMMAND:
		if loword(wParam) == idAllHostsClose {
			closeModal(HWND(hwnd))
		}
		return 0

	case WM_KEYDOWN:
		if wParam == VK_RETURN {
			if ip := allHostsSelectedIP(); ip != "" {
				closeModal(HWND(hwnd))
				showHostDetailDialog(hwndMain, ip)
			}
		}
		return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)

	case WM_NOTIFY:
		hdr := (*NMHDR)(unsafe.Pointer(lParam))
		if hdr.IdFrom != idAllHostsList {
			return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
		}
		switch hdr.Code {
		case NM_DBLCLK:
			if ip := allHostsSelectedIP(); ip != "" {
				closeModal(HWND(hwnd))
				showHostDetailDialog(hwndMain, ip)
			}
		case NM_RCLICK:
			ip := allHostsSelectedIP()
			if ip == "" {
				// Try hit-test at cursor position.
				pt := getCursorPos()
				cpt := POINT{X: pt.X, Y: pt.Y}
				procScreenToClient.Call(uintptr(hwndAllHostsList), uintptr(unsafe.Pointer(&cpt)))
				ht := LVHITTESTINFO{Pt: cpt}
				row := int32(sendMessage(hwndAllHostsList, LVM_HITTEST, 0, uintptr(unsafe.Pointer(&ht))))
				if row >= 0 {
					ip = listViewGetCellText(hwndAllHostsList, row, 0)
				}
			}
			if ip != "" {
				pt := getCursorPos()
				menu := createPopupMenu()
				appendMenu(menu, MF_STRING, idAllHostsCtxDetails, "Host Details")
				appendMenu(menu, MF_STRING, idAllHostsCtxCopy, "Copy Data")
				appendMenu(menu, MF_STRING, idAllHostsCtxExport, "Export Data…")
				cmd := trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, pt.X, pt.Y, HWND(hwnd))
				destroyMenu(menu)
				if cmd != 0 {
					allHostsDoAction(HWND(hwnd), ip, cmd)
				}
			}
		}
		return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)

	case WM_CLOSE:
		closeModal(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

// showAllHostsDialog opens the "View All Hosts" modal.
func showAllHostsDialog(parent HWND) {
	if len(hostRegistry) == 0 {
		messageBox(parent, "No hosts have been discovered in this session yet.", "All Hosts", MB_OK)
		return
	}

	registerDialogClass("NetScopeAllHosts", allHostsWndProc)

	const dlgW, dlgH int32 = 480, 400
	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetScopeAllHosts", "All Hosts",
		WS_POPUP|WS_CAPTION|WS_SYSMENU|WS_CLIPCHILDREN,
		0, 0, dlgW, dlgH,
		parent, 0, getModuleHandle(),
	)
	if err != nil || dlg == 0 {
		return
	}
	centerOnParent(dlg, parent, dlgW, dlgH)
	setFontAllChildren(dlg, appFont)
	runModal(dlg, parent)
}

// ---------------------------------------------------------------------------
// "Query Host…" dialog
// ---------------------------------------------------------------------------
//
// Type a host address or IP to open its detail dialog.  The list of known
// session hosts filters as you type; selection is always explicit (no
// auto-select).  Enter opens the typed input (or the explicitly selected row).
// Esc / window-X dismisses without opening anything.

const (
	idPickHostEdit = 710
	idPickHostList = 713
	idPickHostHint = 714 // inline hint / validation label

	// context menu (TPM_RETURNCMD; not WM_COMMAND)
	idPickHostCtxView   = 730
	idPickHostCtxCopy   = 731
	idPickHostCtxForget = 732
)

var (
	hwndPickEdit            HWND
	hwndPickList            HWND
	hwndPickHint            HWND   // bottom hint / validation label
	hwndPickHostPlaceholder HWND   // empty-state overlay for the listview
	hwndPickDialog          HWND   // the Hosts dialog itself (set in WM_CREATE)
	pickHintIsError         bool   // true → hint is shown in red
	pickEditOrigProc        uintptr // original wndproc for the edit subclass
)

// pickEditSubclassProc intercepts VK_RETURN and VK_ESCAPE from the Hosts
// dialog edit field so they trigger open / dismiss without needing a button.
var pickEditSubclassProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	if uint32(msg) == WM_KEYDOWN {
		switch wParam {
		case VK_RETURN:
			pickHostConfirm(hwndPickDialog)
			return 0
		case VK_ESCAPE:
			closeModal(hwndPickDialog)
			return 0
		}
	}
	return callWindowProc(pickEditOrigProc, HWND(hwnd), uint32(msg), wParam, lParam)
})

// isValidHostInput returns true if s is a complete, valid host specification.
// Partial IPs like "1.1.1" and empty strings are rejected.
// Hostnames are validated per RFC 952 / RFC 1123: labels of 1–63 characters
// containing only ASCII letters, digits, and hyphens (not leading or trailing),
// separated by dots, total length ≤ 253 characters.
func isValidHostInput(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	// IPv6 — contains colons; accept loosely.
	if strings.Contains(s, ":") {
		return true
	}
	// Looks like an IPv4 candidate (only digits and dots).
	looksIPv4 := true
	for _, c := range s {
		if (c < '0' || c > '9') && c != '.' {
			looksIPv4 = false
			break
		}
	}
	if looksIPv4 {
		// Must be exactly 4 octets, each 0 – 255.
		parts := strings.Split(s, ".")
		if len(parts) != 4 {
			return false
		}
		for _, p := range parts {
			if p == "" {
				return false
			}
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 || n > 255 {
				return false
			}
		}
		return true
	}
	// Hostname — validate per RFC 952 / RFC 1123.
	// Strip a single trailing dot (absolute FQDN form).
	host := s
	if strings.HasSuffix(host, ".") {
		host = host[:len(host)-1]
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

// pickHostUpdateHint refreshes the bottom hint label with state-appropriate
// text and sets pickHintIsError so WM_CTLCOLORSTATIC colours it correctly.
func pickHostUpdateHint(hwnd HWND) {
	input := strings.TrimSpace(getWindowText(hwndPickEdit))
	sel := pickHostSelectedIP()

	var text string
	pickHintIsError = false
	switch {
	case sel != "":
		text = "Enter to open selected host"
	case input == "":
		text = ""
	case !isValidHostInput(input):
		pickHintIsError = true
		text = "Enter a full IP or hostname"
	default:
		text = "Enter to open \u201c" + input + "\u201d"
	}
	setWindowText(hwndPickHint, text)
}

// pickHostRepopulate filters the list to rows matching filter.
// Selection is never forced — it remains explicit only.
func pickHostRepopulate(filter string) {
	hostsListViewRepopulate(hwndPickList, filter)
	// No auto-select: selection is always explicit (mouse or arrow keys).
	if sendMessage(hwndPickList, LVM_GETITEMCOUNT, 0, 0) == 0 {
		showWindow(hwndPickHostPlaceholder, SW_SHOW)
	} else {
		showWindow(hwndPickHostPlaceholder, SW_HIDE)
	}
}

// pickHostSelectedIP returns the IP of the explicitly selected row, or "".
func pickHostSelectedIP() string {
	return listViewSelectedText(hwndPickList, 0)
}

// pickHostConfirm opens the host detail dialog.
//
// Priority:  explicit listview selection  →  typed input (validated).
// Invalid typed input shows an inline hint and does nothing else.
func pickHostConfirm(hwnd HWND) {
	ip := pickHostSelectedIP()
	if ip == "" {
		ip = strings.TrimSpace(getWindowText(hwndPickEdit))
		if !isValidHostInput(ip) {
			// Inline error — no modal.
			pickHintIsError = true
			setWindowText(hwndPickHint, "Enter a full IP or hostname")
			return
		}
	}
	if ip == "" {
		return
	}
	closeModal(hwnd)
	showHostDetailDialog(hwndMain, ip)
}

var pickHostWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		inst := getModuleHandle()
		r := getClientRect(HWND(hwnd))
		cW, cH := r.Right, r.Bottom
		const pad int32 = 10
		const editH int32 = 24
		const hintH int32 = 18

		hwndPickDialog = HWND(hwnd)

		// Filter / freeform edit field at the top.
		hwndPickEdit, _ = createWindowEx(
			WS_EX_CLIENTEDGE, "EDIT", "",
			WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL,
			pad, pad, cW-pad*2, editH, HWND(hwnd), HMENU(idPickHostEdit), inst)

		// Set cue (placeholder) text.
		cueTxt, _ := syscall.UTF16PtrFromString("Search or enter host address")
		sendMessage(hwndPickEdit, EM_SETCUEBANNER, 0, uintptr(unsafe.Pointer(cueTxt)))

		// Subclass the edit field to intercept Enter and Esc.
		pickEditOrigProc = setWindowLongPtr(hwndPickEdit, GWLP_WNDPROC, pickEditSubclassProc)

		// Filtered listview fills the middle section.
		listTop := pad + editH + pad/2
		listH := cH - listTop - pad/2 - hintH - pad
		hwndPickList, _ = createWindowEx(0, WC_LISTVIEW, "",
			WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS|LVS_SINGLESEL,
			pad, listTop, cW-pad*2, listH, HWND(hwnd), HMENU(idPickHostList), inst)
		sendMessage(hwndPickList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
			LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER)
		listViewAddColumn(hwndPickList, 0, "IP", 140)
		listViewAddColumn(hwndPickList, 1, "Hostname", cW-pad*2-140-4)

		// Empty-state overlay floats over the listview when it is empty.
		hwndPickHostPlaceholder, _ = createWindowEx(0, "STATIC", "No hosts yet",
			WS_CHILD|SS_CENTER,
			pad, listTop+(listH-18)/2, cW-pad*2, 18, HWND(hwnd), 0, inst)

		// Hint label at the very bottom (replaces OK/Cancel buttons).
		hintY := cH - pad - hintH
		hwndPickHint, _ = createWindowEx(0, "STATIC", "",
			WS_CHILD|WS_VISIBLE|SS_CENTER,
			pad, hintY, cW-pad*2, hintH, HWND(hwnd), HMENU(idPickHostHint), inst)

		// Populate and update hint.
		pickHostRepopulate("")
		pickHostUpdateHint(HWND(hwnd))
		setFocus(hwndPickEdit)
		return 0

	case WM_CTLCOLORSTATIC:
		if HWND(lParam) == hwndPickHostPlaceholder {
			setBkMode(wParam, TRANSPARENT)
			setTextColor(wParam, 0x00999999)
			return uintptr(getSysColorBrush(COLOR_WINDOW))
		}
		if HWND(lParam) == hwndPickHint {
			setBkMode(wParam, TRANSPARENT)
			if pickHintIsError {
				setTextColor(wParam, 0x000000BB) // red-ish for errors
			} else {
				setTextColor(wParam, 0x00666666) // gray for normal hints
			}
			return uintptr(getSysColorBrush(COLOR_WINDOW))
		}
		return ctlColorDialog(wParam)

	case WM_COMMAND:
		if loword(wParam) == idPickHostEdit && hiword(wParam) == EN_CHANGE {
			// Typing clears any list selection (selection is explicit only).
			lv := LVITEM{StateMask: LVIS_SELECTED}
			sendMessage(hwndPickList, LVM_SETITEMSTATE, ^uintptr(0), uintptr(unsafe.Pointer(&lv)))
			pickHostRepopulate(getWindowText(hwndPickEdit))
			pickHostUpdateHint(HWND(hwnd))
		}
		return 0

	case WM_NOTIFY:
		hdr := (*NMHDR)(unsafe.Pointer(lParam)) //nolint:govet
		if hdr.IdFrom != idPickHostList {
			return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
		}
		switch hdr.Code {
		case NM_DBLCLK:
			pickHostConfirm(HWND(hwnd))
		case LVN_KEYDOWN:
			kd := (*NMLVKEYDOWN)(unsafe.Pointer(lParam)) //nolint:govet
			if kd.WVKey == VK_RETURN {
				pickHostConfirm(HWND(hwnd))
			}
		case LVN_ITEMCHANGED:
			pickHostUpdateHint(HWND(hwnd))
		case NM_RCLICK:
			ip := pickHostSelectedIP()
			if ip == "" {
				pt := getCursorPos()
				cpt := POINT{X: pt.X, Y: pt.Y}
				procScreenToClient.Call(uintptr(hwndPickList), uintptr(unsafe.Pointer(&cpt)))
				ht := LVHITTESTINFO{Pt: cpt}
				row := int32(sendMessage(hwndPickList, LVM_HITTEST, 0, uintptr(unsafe.Pointer(&ht))))
				if row >= 0 {
					ip = listViewGetCellText(hwndPickList, row, 0)
				}
			}
			if ip != "" {
				pt := getCursorPos()
				menu := createPopupMenu()
				appendMenu(menu, MF_STRING, idPickHostCtxView, "View Host")
				appendMenu(menu, MF_STRING, idPickHostCtxCopy, "Copy Data")
				appendMenu(menu, MF_SEPARATOR, 0, "")
				appendMenu(menu, MF_STRING, idPickHostCtxForget, "Forget Host")
				cmd := int32(trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, pt.X, pt.Y, HWND(hwnd)))
				destroyMenu(menu)
				switch cmd {
				case idPickHostCtxView:
					closeModal(HWND(hwnd))
					showHostDetailDialog(hwndMain, ip)
				case idPickHostCtxCopy:
					copyToClipboard(HWND(hwnd), buildHostJSON([]string{ip}))
				case idPickHostCtxForget:
					confirmMsg := "Remove " + ip + " from the session?\n\nAll observations for this host will be deleted."
					if messageBox(HWND(hwnd), confirmMsg, "Forget Host", MB_YESNO|MB_ICONWARNING) == IDYES {
						delete(hostRegistry, ip)
						postMessage(hwndMain, WM_HOST_REFRESH, 0, 0)
						pickHostRepopulate(getWindowText(hwndPickEdit))
						pickHostUpdateHint(HWND(hwnd))
					}
				}
			}
		}
		return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)

	case WM_CLOSE:
		closeModal(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

// showPickHostDialog opens the Query Host dialog.
// Works without any prior scan — the user can type any IP or hostname.
func showPickHostDialog(parent HWND) {
	registerDialogClass("NetScopePickHost", pickHostWndProc)

	const dlgW, dlgH int32 = 460, 360
	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetScopePickHost", "Hosts",
		WS_POPUP|WS_CAPTION|WS_SYSMENU|WS_CLIPCHILDREN,
		0, 0, dlgW, dlgH,
		parent, 0, getModuleHandle(),
	)
	if err != nil || dlg == 0 {
		return
	}
	centerOnParent(dlg, parent, dlgW, dlgH)
	setFontAllChildren(dlg, appFont)
	runModal(dlg, parent)
}
