//go:build windows

package guiwin

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/demicloud/net-sweep/internal/sweep"
)

// ---------------------------------------------------------------------------
// Host detail dialog
// ---------------------------------------------------------------------------
//
// Opened by double-clicking a row in the Hosts listview, or via right-click
// "View details…". Shows a consolidated summary of everything known about the
// selected host, plus an on-demand probe panel.
//
// Layout (fixed 700 × 540):
//
//  ┌─ Host detail: [192.168.1.42 ▾────────────────────────────────────]  ─┐
//  │ Summary (readonly multiline EDIT, ~150px)                             │
//  ├───────────────────────────────────────────────────────────────────────│
//  │ Port: [____] Type: [SSH ▾] [Run]  [Run all common probes]            │
//  │ ┌────────┬────────┬─────────────────────────────────────────────┐    │
//  │ │ Port   │ Type   │ Result                                       │    │
//  │ └────────┴────────┴─────────────────────────────────────────────┘    │
//  ├───────────────────────────────────────────────────────────────────────│
//  │                                         [Copy report]   [Close]      │
//  └───────────────────────────────────────────────────────────────────────┘

const (
	idHostClose      = 601
	idHostRunProbe   = 602
	idHostRunAll     = 603
	idHostCopyReport = 604
	idHostIPCombo    = 605
	idHostPortEdit   = 606
	idHostTypeCombo  = 607
	idHostProbeList  = 608
)

// Dialog-local handles (valid while dialog is open).
var (
	hwndHostIPCombo   HWND
	hwndHostSummary   HWND
	hwndHostPortEdit  HWND
	hwndHostTypeCombo HWND
	hwndHostRunBtn    HWND
	hwndHostRunAllBtn HWND
	hwndHostProbeList HWND
	hwndHostCopyBtn   HWND
	hwndHostCloseBtn  HWND

	// currentDetailIP is the IP shown in the dialog right now.
	currentDetailIP string

	// pendingProbeResults: goroutines append, UI thread reads via WM_PROBE_RESULT.
	pendingProbeResults   []sweep.ProbeResult
	pendingProbeResultsMu sync.Mutex

	// activeProbes is the count of probe goroutines still running.
	activeProbes int32

	// dialogProbeCancel cancels all in-flight probes when the dialog closes.
	dialogProbeCancel func()

	// dialogProbeCtx is the context passed to all probe goroutines.
	dialogProbeCtx context.Context

	registerHostDetailOnce sync.Once
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
		hdc := wParam
		setBkMode(hdc, TRANSPARENT)
		setTextColor(hdc, 0x00000000)
		return uintptr(getSysColorBrush(COLOR_BTNFACE))

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
		case idHostIPCombo:
			if hiword(wParam) == CBN_SELCHANGE {
				hostDetailSelectIP(HWND(hwnd))
			}
		}
		return 0

	case WM_PROBE_RESULT:
		pendingProbeResultsMu.Lock()
		var pr sweep.ProbeResult
		if int(wParam) < len(pendingProbeResults) {
			pr = pendingProbeResults[int(wParam)]
		}
		pendingProbeResultsMu.Unlock()
		if pr.Type != "" {
			hostDetailAddProbeRow(HWND(hwnd), pr)
		}
		// Re-enable "Run all" when the last probe finishes.
		if atomic.LoadInt32(&activeProbes) == 0 {
			enableWindow(hwndHostRunAllBtn, true)
			setWindowText(hwndHostRunAllBtn, "Run all common probes")
		}
		return 0

	case WM_CLOSE:
		hostDetailClose(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

func hostDetailClose(hwnd HWND) {
	if dialogProbeCancel != nil {
		dialogProbeCancel()
		dialogProbeCancel = nil
	}
	closeModal(hwnd)
}

// ensureHostDetailClass registers the window class once per process.
func ensureHostDetailClass() {
	registerHostDetailOnce.Do(func() {
		cn := utf16("NetSweepHostDetail")
		wc := WNDCLASSEX{
			CbSize:        uint32(unsafe.Sizeof(WNDCLASSEX{})),
			LpfnWndProc:   hostDetailWndProc,
			HInstance:     getModuleHandle(),
			HbrBackground: HBRUSH(COLOR_BTNFACE + 1),
			HCursor:       loadCursor(IDC_ARROW),
			LpszClassName: cn,
		}
		registerClassEx(&wc)
	})
}

// showHostDetailDialog opens the host detail modal for the given IP.
func showHostDetailDialog(parent HWND, ip string) {
	ensureHostDetailClass()

	// Reset probe state.
	pendingProbeResultsMu.Lock()
	pendingProbeResults = pendingProbeResults[:0]
	pendingProbeResultsMu.Unlock()
	atomic.StoreInt32(&activeProbes, 0)
	currentDetailIP = ip
	// Create a fresh context for this dialog session.
	ctx, cancel := context.WithCancel(context.Background())
	dialogProbeCtx = ctx
	dialogProbeCancel = cancel

	const dlgW, dlgH int32 = 740, 600
	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetSweepHostDetail", "Host detail — "+ip,
		WS_POPUP|WS_CAPTION|WS_SYSMENU|WS_CLIPCHILDREN,
		0, 0, dlgW, dlgH,
		parent, 0, getModuleHandle(),
	)
	if err != nil || dlg == 0 {
		return
	}
	centerOnParent(dlg, parent, dlgW, dlgH)

	// Populate the IP combo with all known IPs.
	for _, knownIP := range allHostIPs() {
		p, _ := syscall.UTF16PtrFromString(knownIP)
		sendMessage(hwndHostIPCombo, CB_ADDSTRING, 0, uintptr(unsafe.Pointer(p)))
	}
	// Select the requested IP.
	p, _ := syscall.UTF16PtrFromString(ip)
	idx := sendMessage(hwndHostIPCombo, CB_FINDSTRINGEXACT, ^uintptr(0), uintptr(unsafe.Pointer(p)))
	if idx != ^uintptr(0) {
		sendMessage(hwndHostIPCombo, CB_SETCURSEL, idx, 0)
	}

	// Populate probe type combo.
	for _, t := range probeTypeLabels {
		pt, _ := syscall.UTF16PtrFromString(t)
		sendMessage(hwndHostTypeCombo, CB_ADDSTRING, 0, uintptr(unsafe.Pointer(pt)))
	}
	sendMessage(hwndHostTypeCombo, CB_SETCURSEL, 1, 0) // default: SSH

	// Fill summary.
	setWindowText(hwndHostSummary, buildHostSummary(ip))

	setFontAllChildren(dlg, appFont)
	runModal(dlg, parent)
}

// createHostDetailControls builds all child controls for the dialog.
// All positions are derived from the actual client rect so they are
// correct regardless of caption-bar height, border size, or DPI.
func createHostDetailControls(hwnd HWND) {
	inst := getModuleHandle()
	r := getClientRect(hwnd)
	cW := r.Right  // actual client width
	cH := r.Bottom // actual client height
	const pad int32 = 10

	// Row 1: Host label + IP combo (full width minus label)
	y := pad
	createCtrl("STATIC", "Host:", WS_CHILD|WS_VISIBLE,
		pad, y+4, 36, 16, hwnd, 0, inst)
	hwndHostIPCombo, _ = createWindowEx(0, "COMBOBOX", "",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_VSCROLL|CBS_DROPDOWN|CBS_AUTOHSCROLL|CBS_SORT,
		pad+40, y, cW-pad*2-40, 240, hwnd, HMENU(idHostIPCombo), inst)

	// Summary readonly edit (1/3 of client height)
	y += 28
	summaryH := cH / 3
	hwndHostSummary, _ = createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
		pad, y, cW-pad*2, summaryH, hwnd, 0, inst)

	// Section label
	y += summaryH + 8
	createCtrl("STATIC", "On-demand probes:", WS_CHILD|WS_VISIBLE,
		pad, y+2, 140, 16, hwnd, 0, inst)

	// Probe controls bar: left-to-right, Run-all gets remaining width
	y += 22
	const (
		portLblW  int32 = 32
		portEditW int32 = 52
		typeLblW  int32 = 36
		typeComboW int32 = 110
		runBtnW   int32 = 60
		gap       int32 = 8
	)
	x := pad
	createCtrl("STATIC", "Port:", WS_CHILD|WS_VISIBLE,
		x, y+4, portLblW, 16, hwnd, 0, inst)
	x += portLblW
	hwndHostPortEdit, _ = createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "22",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL,
		x, y, portEditW, 22, hwnd, HMENU(idHostPortEdit), inst)
	x += portEditW + gap
	createCtrl("STATIC", "Type:", WS_CHILD|WS_VISIBLE,
		x, y+4, typeLblW, 16, hwnd, 0, inst)
	x += typeLblW
	hwndHostTypeCombo, _ = createWindowEx(0, "COMBOBOX", "",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|CBS_DROPDOWNLIST,
		x, y, typeComboW, 200, hwnd, HMENU(idHostTypeCombo), inst)
	x += typeComboW + gap
	hwndHostRunBtn, _ = createWindowEx(0, "BUTTON", "Run",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		x, y, runBtnW, 24, hwnd, HMENU(idHostRunProbe), inst)
	x += runBtnW + gap*2
	runAllW := cW - pad - x
	if runAllW < 130 {
		runAllW = 130
	}
	hwndHostRunAllBtn, _ = createWindowEx(0, "BUTTON", "Run all common probes",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		x, y, runAllW, 24, hwnd, HMENU(idHostRunAll), inst)

	// Probe results listview: fill all space above the button row
	y += 30
	const btnRowH int32 = 28 + pad*2
	probeListH := cH - y - btnRowH
	if probeListH < 60 {
		probeListH = 60
	}
	hwndHostProbeList, _ = createWindowEx(0, WC_LISTVIEW, "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
		pad, y, cW-pad*2, probeListH, hwnd, HMENU(idHostProbeList), inst)
	sendMessage(hwndHostProbeList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER)
	listViewAddColumn(hwndHostProbeList, 0, "Port", 60)
	listViewAddColumn(hwndHostProbeList, 1, "Type", 80)
	listViewAddColumn(hwndHostProbeList, 2, "Result", cW-pad*2-60-80-4)

	// Bottom button row pinned to client bottom
	btnY := cH - pad - 26
	hwndHostCopyBtn, _ = createWindowEx(0, "BUTTON", "Copy report",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		cW-pad-210, btnY, 100, 26, hwnd, HMENU(idHostCopyReport), inst)
	hwndHostCloseBtn, _ = createWindowEx(0, "BUTTON", "Close",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		cW-pad-100, btnY, 100, 26, hwnd, HMENU(idHostClose), inst)
}

// hostDetailSelectIP updates the summary when the user picks a different IP.
func hostDetailSelectIP(hwnd HWND) {
	idx := sendMessage(hwndHostIPCombo, CB_GETCURSEL, 0, 0)
	if idx == ^uintptr(0) {
		return
	}
	tlen := sendMessage(hwndHostIPCombo, CB_GETLBTEXTLEN, idx, 0)
	if int32(tlen) <= 0 {
		return
	}
	buf := make([]uint16, tlen+1)
	sendMessage(hwndHostIPCombo, CB_GETLBTEXT, idx, uintptr(unsafe.Pointer(&buf[0])))
	ip := syscall.UTF16ToString(buf)
	if ip == "" || ip == currentDetailIP {
		return
	}
	currentDetailIP = ip
	setWindowText(hwnd, "Host detail — "+ip) // update title bar
	setWindowText(hwndHostSummary, buildHostSummary(ip))
	// Clear the probe list for the new host.
	sendMessage(hwndHostProbeList, LVM_DELETEALLITEMS, 0, 0)
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
	spec := sweep.ProbeSpec{Port: port, Type: probeType}
	startProbe(hwnd, currentDetailIP, spec)
}

// hostDetailRunAll fires probes for all CommonProbes in parallel.
func hostDetailRunAll(hwnd HWND) {
	enableWindow(hwndHostRunAllBtn, false)
	setWindowText(hwndHostRunAllBtn, "Running…")
	for _, spec := range sweep.CommonProbes {
		startProbe(hwnd, currentDetailIP, spec)
	}
}

// startProbe launches one probe goroutine. Results arrive via WM_PROBE_RESULT.
func startProbe(hwnd HWND, ip string, spec sweep.ProbeSpec) {
	atomic.AddInt32(&activeProbes, 1)
	ctx := dialogProbeCtx
	go func() {
		defer atomic.AddInt32(&activeProbes, -1)
		res := sweep.RunProbe(ctx, ip, spec, 3*time.Second)
		pendingProbeResultsMu.Lock()
		idx := len(pendingProbeResults)
		pendingProbeResults = append(pendingProbeResults, res)
		pendingProbeResultsMu.Unlock()
		if hwnd != 0 {
			postMessage(hwnd, WM_PROBE_RESULT, uintptr(idx), 0)
		}
	}()
}

// hostDetailAddProbeRow inserts one probe result into the probe listview.
func hostDetailAddProbeRow(hwnd HWND, pr sweep.ProbeResult) {
	_ = hwnd
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
	probes := append([]sweep.ProbeResult{}, pendingProbeResults...)
	pendingProbeResultsMu.Unlock()
	if len(probes) > 0 {
		sb.WriteString("\n── On-demand probes ───────────────────────────────────\n")
		for _, pr := range probes {
			sb.WriteString(fmt.Sprintf("  %-6d %-8s %s\n", pr.Port, pr.Type, pr.Result))
		}
	}
	copyToClipboard(hwnd, sb.String())
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
	allSvcs := append([]sweep.ServiceInfo{}, r.Services...)
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
			name := svc.Name
			if name == "" {
				name = svc.Type
			}
			sb.WriteString(fmt.Sprintf("  [%-5s] %s\n", svc.Source, name))
		}
	}

	return strings.ReplaceAll(sb.String(), "\n", "\r\n")
}
