//go:build windows

package guiwin

import (
	"encoding/json"
	"fmt"
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
//  │ [status: passive / sources / freshness]                                │
//  │  Summary body (hostname, MAC, vendor, OS, ports, banners, services)    │
//  ├────────────────────────────────────────────────────────────────────────│
//  │ Connect   [HTTP] [HTTPS] [SSH] [RDP] [FTP] [SMB] [More ▾]             │
//  ├────────────────────────────────────────────────────────────────────────│
//  │ Investigate  Port:[___] Type:[▾] [Run Probe]   [Run Common Probes]     │
//  │              [Ping]  [Ping continuous]                                  │
//  ├────────────────────────────────────────────────────────────────────────│
//  │ Evidence & Observations                                                 │
//  │ ┌────────┬────────┬───────────────────────────────────────────────┐   │
//  │ │  Port  │  Type  │  Result                                        │   │
//  │ └────────┴────────┴───────────────────────────────────────────────┘   │
//  │              [Copy Fingerprint]  [Copy Report]            [Close]      │
//  └────────────────────────────────────────────────────────────────────────┘

const (
	idHostClose      = 601
	idHostRunProbe   = 602
	idHostRunAll     = 603
	idHostCopyReport = 604
	idHostPortEdit   = 606
	idHostTypeCombo  = 607
	idHostProbeList  = 608
	idHostCopyFP     = 609

	// Connect quick-action buttons (primary protocols).
	idHostConnHTTP  = 620
	idHostConnHTTPS = 621
	idHostConnSSH   = 622
	idHostConnRDP   = 623
	idHostConnFTP   = 624
	idHostConnTelnet = 625 // used in «More…» popup menu, not a direct button
	idHostConnSMB   = 626
	idHostConnMore  = 629 // «More…» dropdown for legacy / less-common protocols

	// Investigate section.
	idHostPingOnce = 627
	idHostPingCont = 628
)

// Dialog-local handles (valid while dialog is open).
var (
	hwndHostStatus    HWND // one-line status: sources + freshness + completeness
	hwndHostSummary   HWND
	hwndHostPortEdit  HWND
	hwndHostTypeCombo HWND
	hwndHostRunBtn    HWND
	hwndHostRunAllBtn HWND
	hwndHostProbeList HWND
	hwndHostEvidHint  HWND // «No probes run yet» hint inside evidence section
	hwndHostCopyBtn   HWND
	hwndHostCloseBtn  HWND
	hwndHostCopyFPBtn HWND

	// Connect quick-action buttons (primary protocols only).
	hwndHostConnHTTP  HWND
	hwndHostConnHTTPS HWND
	hwndHostConnSSH   HWND
	hwndHostConnRDP   HWND
	hwndHostConnFTP   HWND
	hwndHostConnSMB   HWND
	hwndHostConnMore  HWND // «More…» opens popup with legacy protocols

	// Investigate section.
	hwndHostPingOnce HWND
	hwndHostPingCont HWND

	// currentDetailIP is the IP shown in the dialog right now.
	currentDetailIP string

	// pendingProbeResults: receive loop appends, UI thread reads via WM_PROBE_RESULT.
	pendingProbeResults   []scan.ProbeResult
	pendingProbeResultsMu sync.Mutex

	// activeProbes is the count of probe commands still awaiting a result.
	activeProbes int32
)

// probeTypeLabels is the ordered list shown in the Type combo.
var probeTypeLabels = []string{
	"TCP", "SSH", "HTTP", "HTTPS", "FTP", "SMTP", "Telnet", "RDP", "Steam",
}

// hostDetailWndProc is the window procedure for the host detail dialog.
var hostDetailWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createHostDetailControls(HWND(hwnd))
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_CTLCOLOREDIT:
		return ctlColorDlgBody(wParam)

	case WM_COMMAND:
		switch loword(wParam) {
		case idHostClose:
			hostDetailClose(HWND(hwnd))
		case idHostRunProbe:
			hostDetailRunSingle(HWND(hwnd))
		case idHostRunAll:
			hostDetailRunAll(HWND(hwnd))
		case idHostCopyReport:
			hostDetailCopyReport(HWND(hwnd))
		case idHostCopyFP:
			hostDetailCopyFP(HWND(hwnd))
		case idHostConnHTTP:
			openProtocol(HWND(hwnd), currentDetailIP, "http")
		case idHostConnHTTPS:
			openProtocol(HWND(hwnd), currentDetailIP, "https")
		case idHostConnSSH:
			openProtocol(HWND(hwnd), currentDetailIP, "ssh")
		case idHostConnRDP:
			openProtocol(HWND(hwnd), currentDetailIP, "rdp")
		case idHostConnFTP:
			openProtocol(HWND(hwnd), currentDetailIP, "ftp")
		case idHostConnSMB:
			openProtocol(HWND(hwnd), currentDetailIP, "smb")
		case idHostConnMore:
			showConnectMoreMenu(HWND(hwnd))
		case idHostPingOnce:
			shellExecute(HWND(hwnd), "open", "cmd.exe",
				"/c ping "+currentDetailIP+" && pause", "", SW_SHOW)
		case idHostPingCont:
			shellExecute(HWND(hwnd), "open", "cmd.exe",
				"/k ping -t "+currentDetailIP, "", SW_SHOW)
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
		// Decrement and re-enable when the last probe result arrives.
		if atomic.AddInt32(&activeProbes, -1) == 0 {
			enableWindow(hwndHostRunAllBtn, true)
			setWindowText(hwndHostRunAllBtn, "Run Common Probes")
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
		return "No prior data  \u2014  manually entered address"
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

// showConnectMoreMenu displays a popup menu of less-common / legacy connection
// options, anchored to the bottom-left of the "More ▾" button.
func showConnectMoreMenu(hwnd HWND) {
	menu := createPopupMenu()
	appendMenu(menu, MF_STRING, idHostConnTelnet, "Telnet (port 23)")
	br := getWindowRect(hwndHostConnMore)
	cmd := trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, br.Left, br.Bottom, hwnd)
	destroyMenu(menu)
	switch cmd {
	case idHostConnTelnet:
		openProtocol(hwnd, currentDetailIP, "telnet")
	}
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
		"NetScopeHostDetail", "Host — "+ip,
		WS_POPUP|WS_CAPTION|WS_SYSMENU|WS_CLIPCHILDREN,
		0, 0, dlgW, dlgH,
		parent, 0, getModuleHandle(),
	)
	if err != nil || dlg == 0 {
		return
	}
	centerOnParent(dlg, parent, dlgW, dlgH)

	// Populate probe type combo.
	for _, t := range probeTypeLabels {
		pt, _ := syscall.UTF16PtrFromString(t)
		sendMessage(hwndHostTypeCombo, CB_ADDSTRING, 0, uintptr(unsafe.Pointer(pt)))
	}
	sendMessage(hwndHostTypeCombo, CB_SETCURSEL, 1, 0) // default: SSH

	// Fill identity section: status line + summary body.
	setWindowText(hwndHostStatus, buildStatusLine(ip))
	setWindowText(hwndHostSummary, buildHostSummary(ip))
	hostDetailUpdateConnectButtons(ip)
	_, known := hostRegistry[ip]
	enableWindow(hwndHostCopyFPBtn, known)

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
// The dialog is organised into four vertically-stacked sections:
//
//  1. Host Identity & State  — status line + scrollable summary body
//  2. Connect                — primary protocol buttons + More… menu
//  3. Investigate            — on-demand probe row + ping row
//  4. Evidence & Observations — probe results listview + bottom buttons
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

	// Summary body: identity details (hostname, MAC, vendor, OS, ports, etc.)
	const summaryH int32 = 110
	hwndHostSummary, _ = createWindowEx(0, "EDIT", "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
		pad, y, cW-pad*2, summaryH, hwnd, 0, inst)
	y += summaryH + 6

	createDlgSeparator(hwnd, inst, pad, y, cW-pad*2)
	y += 10

	// ── Section 2: Connect ────────────────────────────────────────────────
	createCtrl("STATIC", "Connect", WS_CHILD|WS_VISIBLE,
		pad, y+3, 56, 14, hwnd, 0, inst)
	y += 18

	const (
		connGap  int32 = 5
		connBtnH int32 = 24
	)
	cx := pad
	for _, btn := range []struct {
		label string
		dst   *HWND
		id    int32
		w     int32
	}{
		{"HTTP", &hwndHostConnHTTP, idHostConnHTTP, 48},
		{"HTTPS", &hwndHostConnHTTPS, idHostConnHTTPS, 54},
		{"SSH", &hwndHostConnSSH, idHostConnSSH, 46},
		{"RDP", &hwndHostConnRDP, idHostConnRDP, 46},
		{"FTP", &hwndHostConnFTP, idHostConnFTP, 44},
		{"SMB", &hwndHostConnSMB, idHostConnSMB, 46},
		{"More \u25be", &hwndHostConnMore, idHostConnMore, 58},
	} {
		*btn.dst, _ = createWindowEx(0, "BUTTON", btn.label,
			WS_CHILD|WS_VISIBLE|WS_TABSTOP,
			cx, y, btn.w, connBtnH, hwnd, HMENU(btn.id), inst)
		cx += btn.w + connGap
	}
	y += connBtnH + 8

	createDlgSeparator(hwnd, inst, pad, y, cW-pad*2)
	y += 10

	// ── Section 3: Investigate ────────────────────────────────────────────
	createCtrl("STATIC", "Investigate", WS_CHILD|WS_VISIBLE,
		pad, y+3, 78, 14, hwnd, 0, inst)
	y += 18

	// Probe row: Port [___] Type [▾] [Run Probe]      [Run Common Probes]
	const (
		portLblW   int32 = 32
		portEditW  int32 = 52
		typeLblW   int32 = 36
		typeComboW int32 = 110
		runBtnW    int32 = 80
		invGap     int32 = 6
	)
	x := pad
	createCtrl("STATIC", "Port:", WS_CHILD|WS_VISIBLE,
		x, y+4, portLblW, 16, hwnd, 0, inst)
	x += portLblW
	hwndHostPortEdit, _ = createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "22",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL,
		x, y, portEditW, 22, hwnd, HMENU(idHostPortEdit), inst)
	x += portEditW + invGap
	createCtrl("STATIC", "Type:", WS_CHILD|WS_VISIBLE,
		x, y+4, typeLblW, 16, hwnd, 0, inst)
	x += typeLblW
	hwndHostTypeCombo, _ = createWindowEx(0, "COMBOBOX", "",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|CBS_DROPDOWNLIST,
		x, y, typeComboW, 200, hwnd, HMENU(idHostTypeCombo), inst)
	x += typeComboW + invGap
	hwndHostRunBtn, _ = createWindowEx(0, "BUTTON", "Run Probe",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		x, y, runBtnW, 24, hwnd, HMENU(idHostRunProbe), inst)
	x += runBtnW + invGap*2
	runAllW := cW - pad - x
	if runAllW < 140 {
		runAllW = 140
	}
	hwndHostRunAllBtn, _ = createWindowEx(0, "BUTTON", "Run Common Probes",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		x, y, runAllW, 24, hwnd, HMENU(idHostRunAll), inst)
	y += 30

	// Ping sub-row (investigative, not connects).
	cx = pad
	hwndHostPingOnce, _ = createWindowEx(0, "BUTTON", "Ping",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		cx, y, 60, 24, hwnd, HMENU(idHostPingOnce), inst)
	cx += 60 + connGap
	hwndHostPingCont, _ = createWindowEx(0, "BUTTON", "Ping continuous",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		cx, y, 116, 24, hwnd, HMENU(idHostPingCont), inst)
	y += 24 + 8

	createDlgSeparator(hwnd, inst, pad, y, cW-pad*2)
	y += 10

	// ── Section 4: Evidence & Observations ───────────────────────────────
	createCtrl("STATIC", "Evidence & Observations", WS_CHILD|WS_VISIBLE,
		pad, y+3, 170, 14, hwnd, 0, inst)
	y += 20

	// Empty-state hint shown until the first probe result arrives.
	hwndHostEvidHint, _ = createWindowEx(0, "STATIC",
		"No probes run yet  \u2014  use Investigate above to gather evidence.",
		WS_CHILD|WS_VISIBLE,
		pad+2, y, cW-pad*2-4, 18, hwnd, 0, inst)
	y += 22

	// Probe results listview: fills remaining space above the button row.
	const btnRowH int32 = pad + 26 + pad
	probeListH := cH - y - btnRowH
	if probeListH < 60 {
		probeListH = 60
	}
	hwndHostProbeList, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		pad, y, cW-pad*2, probeListH, hwnd, HMENU(idHostProbeList), inst)
	sendMessage(hwndHostProbeList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER)
	listViewAddColumn(hwndHostProbeList, 0, "Port", 55)
	listViewAddColumn(hwndHostProbeList, 1, "Type", 75)
	listViewAddColumn(hwndHostProbeList, 2, "Result", cW-pad*2-55-75-4)

	// Bottom button row pinned to client bottom.
	btnY := cH - pad - 26
	hwndHostCopyBtn, _ = createWindowEx(0, "BUTTON", "Copy Report",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		cW-pad-330, btnY, 110, 26, hwnd, HMENU(idHostCopyReport), inst)
	hwndHostCopyFPBtn, _ = createWindowEx(0, "BUTTON", "Copy Fingerprint",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		cW-pad-210, btnY, 110, 26, hwnd, HMENU(idHostCopyFP), inst)
	hwndHostCloseBtn, _ = createWindowEx(0, "BUTTON", "Close",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		cW-pad-100, btnY, 100, 26, hwnd, HMENU(idHostClose), inst)
}

// hostDetailUpdateConnectButtons enables/disables Connect buttons based on
// which ports are known to be open for ip. If ip is not in the registry
// (manually entered), all buttons are left enabled.
func hostDetailUpdateConnectButtons(ip string) {
	type portBtn struct {
		port int
		hwnd *HWND
	}
	portBtns := []portBtn{
		{80, &hwndHostConnHTTP},
		{443, &hwndHostConnHTTPS},
		{22, &hwndHostConnSSH},
		{3389, &hwndHostConnRDP},
		{21, &hwndHostConnFTP},
		{445, &hwndHostConnSMB},
	}
	e, known := hostRegistry[ip]
	for _, pb := range portBtns {
		en := !known || portOpen(e.Result, pb.port)
		enableWindow(*pb.hwnd, en)
	}
}

// hostDetailRunSingle reads the Port and Type fields and runs one probe.
func hostDetailRunSingle(hwnd HWND) {
	portStr := strings.TrimSpace(getWindowText(hwndHostPortEdit))
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return
	}
	typeIdx := sendMessage(hwndHostTypeCombo, CB_GETCURSEL, 0, 0)
	probeType := "TCP"
	if int(typeIdx) < len(probeTypeLabels) {
		probeType = probeTypeLabels[int(typeIdx)]
	}
	spec := scan.ProbeSpec{Port: port, Type: probeType}
	startProbe(hwnd, currentDetailIP, spec)
}

// hostDetailRunAll fires probes for all CommonProbes in parallel.
func hostDetailRunAll(hwnd HWND) {
	enableWindow(hwndHostRunAllBtn, false)
	setWindowText(hwndHostRunAllBtn, "Running…")
	for _, spec := range scan.CommonProbes {
		startProbe(hwnd, currentDetailIP, spec)
	}
}

// startProbe sends a single on-demand probe to the sensor service.
// Probe results are delivered asynchronously via WM_PROBE_RESULT.
func startProbe(hwnd HWND, ip string, spec scan.ProbeSpec) {
	atomic.AddInt32(&activeProbes, 1)
	if err := sendProbeViaService(ip, spec, appConfig.Scan.SOCKSProxy); err != nil {
		atomic.AddInt32(&activeProbes, -1)
		if atomic.LoadInt32(&activeProbes) == 0 {
			enableWindow(hwndHostRunAllBtn, true)
			setWindowText(hwndHostRunAllBtn, "Run Common Probes")
		}
		messageBox(hwnd, "Cannot run probe: the sensor service is not running.\nClick \"Elevate Sensor\" on the main window and try again.", "Probe", MB_ICONWARNING)
		return
	}
}

// hostDetailAddProbeRow inserts one probe result into the probe listview.
func hostDetailAddProbeRow(hwnd HWND, pr scan.ProbeResult) {
	_ = hwnd
	// Hide the empty-state hint once the first evidence row arrives.
	showWindow(hwndHostEvidHint, SW_HIDE)
	portStr := strconv.Itoa(pr.Port)
	p := utf16(portStr)
	item := LVITEM{
		Mask:    LVIF_TEXT,
		IItem:   0x7fffffff, // append
		PszText: p,
	}
	row := int32(sendMessage(hwndHostProbeList, LVM_INSERTITEM, 0, uintptr(unsafe.Pointer(&item))))
	if row < 0 {
		return
	}
	setSubItem(hwndHostProbeList, row, 1, pr.Type)
	setSubItem(hwndHostProbeList, row, 2, pr.Result)
}

// hostDetailCopyReport builds a text report and puts it on the clipboard.
func hostDetailCopyReport(hwnd HWND) {
	var sb strings.Builder
	sb.WriteString(buildHostSummary(currentDetailIP))

	// Append probe results.
	pendingProbeResultsMu.Lock()
	probes := append([]scan.ProbeResult{}, pendingProbeResults...)
	pendingProbeResultsMu.Unlock()
	if len(probes) > 0 {
		sb.WriteString("\n── On-demand probes ───────────────────────────────────\n")
		for _, pr := range probes {
			sb.WriteString(fmt.Sprintf("  %-6d %-8s %s\n", pr.Port, pr.Type, pr.Result))
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

// buildHostSummary returns a multi-line text summary for ip.
func buildHostSummary(ip string) string {
	var sb strings.Builder

	e := hostRegistry[ip] // may be nil for IPs typed manually
	if e == nil {
		sb.WriteString("IP:       " + ip + "\r\n")
		sb.WriteString("(No scan data available for this host)\r\n")
		return sb.String()
	}

	r := e.Result

	// ── Basic ───────────────────────────────────────────────────────────────
	sb.WriteString("IP:         " + ip + "\n")
	sb.WriteString(fmt.Sprintf("First seen: %s\n", e.FirstSeen.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Last seen:  %s\n", e.LastSeen.Format("2006-01-02 15:04:05")))

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
	if string(r.OS) != "" {
		sb.WriteString("OS hint:    " + string(r.OS) + "\n")
	}
	if r.Latency > 0 {
		line := fmt.Sprintf("Latency:    %s", r.Latency.Round(time.Millisecond))
		if r.TTL > 0 {
			line += fmt.Sprintf("  (TTL %d)", r.TTL)
		}
		sb.WriteString(line + "\n")
	}
	if len(r.OpenPorts) > 0 {
		ports := make([]string, len(r.OpenPorts))
		for i, p := range r.OpenPorts {
			ports[i] = strconv.Itoa(p)
		}
		sb.WriteString("Open ports: " + strings.Join(ports, ", ") + "\n")
	}

	// ── Banners ─────────────────────────────────────────────────────────────
	var banners []string
	for _, b := range []struct{ label, val string }{
		{"SSH", r.Banner.SSH}, {"HTTP", r.Banner.HTTP}, {"HTTPS", r.Banner.HTTPS},
		{"FTP", r.Banner.FTP}, {"SMTP", r.Banner.SMTP}, {"Telnet", r.Banner.Telnet},
	} {
		if b.val != "" {
			banners = append(banners, fmt.Sprintf("  %-8s %s", b.label+":", b.val))
		}
	}
	if len(banners) > 0 {
		sb.WriteString("\n── Banners ─────────────────────────────────────────────\n")
		for _, b := range banners {
			sb.WriteString(b + "\n")
		}
	}

	// ── SNMP ────────────────────────────────────────────────────────────────
	if r.SNMP != nil {
		sb.WriteString("\n── SNMP ────────────────────────────────────────────────\n")
		if r.SNMP.SysName != "" {
			sb.WriteString("  SysName:    " + r.SNMP.SysName + "\n")
		}
		if r.SNMP.SysDescr != "" {
			sb.WriteString("  SysDescr:   " + r.SNMP.SysDescr + "\n")
		}
		if r.SNMP.SysLocation != "" {
			sb.WriteString("  Location:   " + r.SNMP.SysLocation + "\n")
		}
	}

	// ── DHCP ────────────────────────────────────────────────────────────────
	if len(e.DHCPEvents) > 0 {
		sb.WriteString("\n── DHCP ────────────────────────────────────────────────\n")
		for _, evt := range e.DHCPEvents {
			line := fmt.Sprintf("  %s  %-12s", evt.Time.Format("15:04:05"), evt.Type.String())
			if evt.Hostname != "" {
				line += "  hostname=" + evt.Hostname
			}
			if evt.OfferedIP != "" && evt.OfferedIP != "0.0.0.0" {
				line += "  offered=" + evt.OfferedIP
			}
			if evt.ServerIP != "" {
				line += "  server=" + evt.ServerIP
			}
			sb.WriteString(line + "\n")
		}
	}

	// ── Services (mDNS / SSDP / WSD) ────────────────────────────────────────
	allSvcs := append([]scan.ServiceInfo{}, r.Services...)
	allSvcs = append(allSvcs, e.ExtraServices...)
	if len(allSvcs) > 0 {
		sb.WriteString("\n── Services ────────────────────────────────────────────\n")
		seen := make(map[string]bool)
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
			sb.WriteString(fmt.Sprintf("  [%-5s] %s\n", svc.Source, name))
		}
	}

	return strings.ReplaceAll(sb.String(), "\n", "\r\n")
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
		copyToClipboard(dlg, buildHostSummary(ip))
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
// Enter or select any IP address (known session hosts are pre-populated in the
// combo as shortcuts) and click OK to open the full host-detail/probe dialog.
// Works even when no scan has been run.

const (
	idPickHostEdit   = 710
	idPickHostList   = 713
	idPickHostOK     = 711
	idPickHostCancel = 712
)

var (
	hwndPickEdit HWND
	hwndPickList HWND
)

// pickHostRepopulate filters hwndPickList to rows matching filter and
// auto-selects the first result so Enter immediately works.
func pickHostRepopulate(filter string) {
	hostsListViewRepopulate(hwndPickList, filter)
	listViewSelectFirst(hwndPickList)
}

// pickHostSelectedIP returns the IP of the selected row, or "".
func pickHostSelectedIP() string {
	return listViewSelectedText(hwndPickList, 0)
}

// pickHostConfirm resolves the best IP from the dialog: selected list row
// first, then the typed text (which may be a raw IP not in the registry).
func pickHostConfirm(hwnd HWND) {
	ip := pickHostSelectedIP()
	if ip == "" {
		ip = strings.TrimSpace(getWindowText(hwndPickEdit))
	}
	if ip == "" {
		return
	}
	closeModal(HWND(hwnd))
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
		const btnH int32 = 26

		// Filter / freeform edit field at the top.
		hwndPickEdit, _ = createWindowEx(
			WS_EX_CLIENTEDGE, "EDIT", "",
			WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL,
			pad, pad, cW-pad*2, editH, HWND(hwnd), HMENU(idPickHostEdit), inst)

		// Filtered listview fills the middle.
		listTop := pad + editH + pad/2
		listH := cH - listTop - pad - btnH - pad
		hwndPickList, _ = createWindowEx(0, WC_LISTVIEW, "",
			WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS|LVS_SINGLESEL,
			pad, listTop, cW-pad*2, listH, HWND(hwnd), HMENU(idPickHostList), inst)
		sendMessage(hwndPickList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
			LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER)
		listViewAddColumn(hwndPickList, 0, "IP", 140)
		listViewAddColumn(hwndPickList, 1, "Hostname", cW-pad*2-140-4)

		btnY, btnXs := dlgBottomRight(cW, cH, 2)
		createWindowEx(0, "BUTTON", "OK",
			WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON,
			btnXs[0], btnY, 100, btnH, HWND(hwnd), HMENU(idPickHostOK), inst)
		createWindowEx(0, "BUTTON", "Cancel",
			WS_CHILD|WS_VISIBLE|WS_TABSTOP,
			btnXs[1], btnY, 100, btnH, HWND(hwnd), HMENU(idPickHostCancel), inst)

		// Populate list with all hosts on open; focus the edit field.
		pickHostRepopulate("")
		setFocus(hwndPickEdit)
		return 0

	case WM_COMMAND:
		switch loword(wParam) {
		case idPickHostOK:
			pickHostConfirm(HWND(hwnd))
		case idPickHostCancel:
			closeModal(HWND(hwnd))
		case idPickHostEdit:
			if hiword(wParam) == EN_CHANGE {
				pickHostRepopulate(getWindowText(hwndPickEdit))
			}
		}
		return 0

	case WM_NOTIFY:
		hdr := (*NMHDR)(unsafe.Pointer(lParam)) //nolint:govet
		if hdr.IdFrom == idPickHostList {
			if hdr.Code == NM_DBLCLK {
				pickHostConfirm(HWND(hwnd))
			}
			if hdr.Code == LVN_KEYDOWN {
				kd := (*NMLVKEYDOWN)(unsafe.Pointer(lParam)) //nolint:govet
				if kd.WVKey == VK_RETURN {
					pickHostConfirm(HWND(hwnd))
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
		"NetScopePickHost", "Query Host",
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
