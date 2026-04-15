//go:build windows

package guiwin

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/demicloud/net-scope/internal/scan"
)

// ---------------------------------------------------------------------------
// Port Scan dialog control IDs
// ---------------------------------------------------------------------------

const (
	idPScanIP       = 2100
	idPScanMode     = 2101 // combobox: Default / Specific / All
	idPScanPorts    = 2102 // edit: port list for Specific mode
	idPScanList     = 2103 // ListView: open ports
	idPScanScan     = 2104 // Scan / Stop button
	idPScanCopy     = 2105 // Copy Results button
	idPScanClose    = 2106 // Close button
	idPScanStatus   = 2107 // static status label
	idPScanThrottle = 2108 // combobox: Aggressive / Balanced / Polite

	// Combobox item indices for the Mode selector.
	pScanModeDefault  = 0
	pScanModeSpecific = 1
	pScanModeAll      = 2
)

// ---------------------------------------------------------------------------
// Port Scan dialog state  (UI thread only, except hwndPortScanDlgAtomic)
// ---------------------------------------------------------------------------

var (
	hwndPortScanDlg HWND // UI-thread tracking var for the modeless dialog

	hwndPScanIP       HWND
	hwndPScanMode     HWND
	hwndPScanPorts    HWND
	hwndPScanThrottle HWND
	hwndPScanList     HWND
	hwndPScanScan     HWND
	hwndPScanStatus   HWND

	pScanIPLocked   bool
	pScanRunID      string
	pScanRunning    bool
	pScanFound      int       // open ports found in the current run
	pScanTotal      int       // total ports scanned (final count from service)
	pScanScanned    int       // ports scanned so far (live progress counter)
	pScanTotalPorts int       // total ports to scan (known at start)
	pScanMode       int       // current combobox selection (pScanModeDefault etc.)
	pScanThrottle   string    // current throttle preset
	pScanStartTime  time.Time // when the current scan started
)

// ---------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------

var portScanDlgWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createPortScanDialogControls(HWND(hwnd))
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_CTLCOLOREDIT:
		return ctlColorEdit(wParam)

	case WM_COMMAND:
		switch loword(wParam) {
		case idPScanMode:
			if hiword(wParam) == CBN_SELCHANGE {
				pScanMode = int(sendMessage(hwndPScanMode, CB_GETCURSEL, 0, 0))
				enableWindow(hwndPScanPorts, pScanMode == pScanModeSpecific)
			}
		case idPScanThrottle:
			if hiword(wParam) == CBN_SELCHANGE {
				presets := []string{scan.ThrottleAggressive, scan.ThrottleBalanced, scan.ThrottlePolite}
				if idx := int(sendMessage(hwndPScanThrottle, CB_GETCURSEL, 0, 0)); idx >= 0 && idx < len(presets) {
					pScanThrottle = presets[idx]
				}
			}
		case idPScanScan:
			if pScanRunning {
				portScanDlgStop()
			} else {
				portScanDlgStart(HWND(hwnd))
			}
		case idPScanCopy:
			portScanDlgCopy()
		case idPScanClose:
			if pScanRunning {
				portScanDlgStop()
			}
			closePortScanDialog()
		}
		return 0

	case WM_PORT_SCAN_PROGRESS:
		pendingPortScanProgressMu.Lock()
		var prog scan.PortScanProgress
		if int(wParam) < len(pendingPortScanProgress) {
			prog = pendingPortScanProgress[int(wParam)]
		}
		pendingPortScanProgressMu.Unlock()
		if prog.RunID != pScanRunID {
			return 0 // stale
		}
		pScanScanned = prog.Scanned
		if pScanTotalPorts == 0 {
			pScanTotalPorts = prog.Total
		}
		if pScanRunning {
			portScanUpdateStatus()
		}
		return 0

	case WM_PORT_SCAN_ENTRY:
		pendingPortScanEntriesMu.Lock()
		var entry scan.PortScanEntry
		if int(wParam) < len(pendingPortScanEntries) {
			entry = pendingPortScanEntries[int(wParam)]
		}
		pendingPortScanEntriesMu.Unlock()
		if entry.RunID != pScanRunID {
			return 0 // stale result from a superseded run
		}
		pScanFound++
		listViewAppendRow(hwndPScanList, []string{
			fmt.Sprintf("%d", entry.Port),
			portScanServiceName(entry.Port),
		})
		if pScanRunning {
			portScanUpdateStatus()
		}
		return 0

	case WM_PORT_SCAN_DONE:
		pendingPortScanEntriesMu.Lock()
		var entry scan.PortScanEntry
		if int(wParam) < len(pendingPortScanEntries) {
			entry = pendingPortScanEntries[int(wParam)]
		}
		pendingPortScanEntriesMu.Unlock()
		if entry.RunID != pScanRunID {
			return 0 // stale
		}
		pScanRunning = false
		setWindowText(hwndPScanScan, "Scan")
		if entry.Total > 0 {
			pScanTotal = entry.Total
		}
		elapsed := portScanFormatElapsed(time.Since(pScanStartTime))
		switch pScanFound {
		case 0:
			setWindowText(hwndPScanStatus, fmt.Sprintf("Scan complete \u2014 no open ports \u00b7 %d scanned \u00b7 %s", pScanTotal, elapsed))
		case 1:
			setWindowText(hwndPScanStatus, fmt.Sprintf("Scan complete \u2014 1 open port \u00b7 %d/%d scanned \u00b7 %s", pScanTotal, pScanTotal, elapsed))
		default:
			setWindowText(hwndPScanStatus, fmt.Sprintf("Scan complete \u2014 %d open ports \u00b7 %d/%d scanned \u00b7 %s", pScanFound, pScanTotal, pScanTotal, elapsed))
		}
		return 0

	case WM_CLOSE:
		if pScanRunning {
			portScanDlgStop()
		}
		closePortScanDialog()
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

// ---------------------------------------------------------------------------
// Control creation
// ---------------------------------------------------------------------------

func createPortScanDialogControls(hwnd HWND) {
	inst := getModuleHandle()
	r := getClientRect(hwnd)
	cW := r.Right
	cH := r.Bottom
	const (
		pad  int32 = 10
		btnH int32 = 26
	)

	// ── Row 1: IP field · Mode combobox · Speed combobox · Scan button ──────
	createCtrl("STATIC", "IP:", WS_CHILD|WS_VISIBLE, pad, 14, 18, 16, hwnd, 0, inst)
	hwndPScanIP, _ = createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL,
		32, 11, 130, 20, hwnd, HMENU(idPScanIP), inst)
	if pScanIPLocked {
		sendMessage(hwndPScanIP, EM_SETREADONLY, 1, 0)
	}

	createCtrl("STATIC", "Mode:", WS_CHILD|WS_VISIBLE, 172, 14, 36, 16, hwnd, 0, inst)
	hwndPScanMode, _ = createWindowEx(0, "COMBOBOX", "",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|CBS_DROPDOWNLIST|WS_VSCROLL,
		212, 11, 116, 120, hwnd, HMENU(idPScanMode), inst)
	sendMessage(hwndPScanMode, CB_ADDSTRING, 0, uintptr(unsafe.Pointer(utf16("Default ports"))))
	sendMessage(hwndPScanMode, CB_ADDSTRING, 0, uintptr(unsafe.Pointer(utf16("Specific ports"))))
	sendMessage(hwndPScanMode, CB_ADDSTRING, 0, uintptr(unsafe.Pointer(utf16("All ports"))))
	sendMessage(hwndPScanMode, CB_SETCURSEL, 0, 0)

	createCtrl("STATIC", "Speed:", WS_CHILD|WS_VISIBLE, 334, 14, 40, 16, hwnd, 0, inst)
	hwndPScanThrottle, _ = createWindowEx(0, "COMBOBOX", "",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|CBS_DROPDOWNLIST|WS_VSCROLL,
		378, 11, 90, 120, hwnd, HMENU(idPScanThrottle), inst)
	sendMessage(hwndPScanThrottle, CB_ADDSTRING, 0, uintptr(unsafe.Pointer(utf16("Aggressive"))))
	sendMessage(hwndPScanThrottle, CB_ADDSTRING, 0, uintptr(unsafe.Pointer(utf16("Balanced"))))
	sendMessage(hwndPScanThrottle, CB_ADDSTRING, 0, uintptr(unsafe.Pointer(utf16("Polite"))))
	// Select the initial preset from global config.
	switch pScanThrottle {
	case scan.ThrottleAggressive:
		sendMessage(hwndPScanThrottle, CB_SETCURSEL, 0, 0)
	case scan.ThrottlePolite:
		sendMessage(hwndPScanThrottle, CB_SETCURSEL, 2, 0)
	default: // balanced
		sendMessage(hwndPScanThrottle, CB_SETCURSEL, 1, 0)
	}

	scanBtnW := int32(55)
	hwndPScanScan = createCtrl("BUTTON", "Scan",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP, cW-pad-scanBtnW, 10, scanBtnW, 22, hwnd, idPScanScan, inst)

	// ── Row 2: Specific ports edit ────────────────────────────────────────
	createCtrl("STATIC", "Ports:", WS_CHILD|WS_VISIBLE, pad, 40, 34, 16, hwnd, 0, inst)
	hwndPScanPorts, _ = createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL,
		48, 37, cW-pad-48, 20, hwnd, HMENU(idPScanPorts), inst)
	enableWindow(hwndPScanPorts, false) // enabled only in Specific mode

	// ── Results list ──────────────────────────────────────────────────────
	createCtrl("STATIC", "Open ports:", WS_CHILD|WS_VISIBLE, pad, 66, 80, 16, hwnd, 0, inst)
	const listY int32 = 84
	const btnRowH int32 = pad + btnH + pad
	const statusH int32 = 18
	listH := cH - listY - btnRowH - statusH - pad
	if listH < 60 {
		listH = 60
	}
	hwndPScanList, _ = createWindowEx(
		WS_EX_CLIENTEDGE,
		"SysListView32", "",
		WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SINGLESEL|LVS_SHOWSELALWAYS,
		pad, listY, cW-pad*2, listH, hwnd, HMENU(idPScanList), inst)
	sendMessage(hwndPScanList, LVM_SETEXTENDEDLISTVIEWSTYLE,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER,
		LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER)
	listViewAddColumn(hwndPScanList, 0, "Port", 70)
	listViewAddColumn(hwndPScanList, 1, "Service", 200)

	// ── Status label ──────────────────────────────────────────────────────
	statusY := listY + listH + pad
	hwndPScanStatus = createCtrl("STATIC", "Ready",
		WS_CHILD|WS_VISIBLE, pad, statusY, cW-pad*2, statusH, hwnd, idPScanStatus, inst)

	// ── Bottom buttons ────────────────────────────────────────────────────
	btnY := cH - pad - btnH
	createCtrl("BUTTON", "Copy Results",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP, pad, btnY, 100, btnH, hwnd, idPScanCopy, inst)
	createCtrl("BUTTON", "Close",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP, cW-pad-70, btnY, 70, btnH, hwnd, idPScanClose, inst)
}

// ---------------------------------------------------------------------------
// Scan / Stop
// ---------------------------------------------------------------------------

func portScanDlgStart(dlg HWND) {
	ip := getWindowText(hwndPScanIP)
	if net.ParseIP(ip) == nil {
		showInfo(dlg, "Enter a valid IP address.", "Port Scan")
		return
	}

	// Build explicit port list for Specific mode.
	var specificPorts []int
	if pScanMode == pScanModeSpecific {
		portsStr := getWindowText(hwndPScanPorts)
		var err error
		specificPorts, err = parsePortList(portsStr)
		if err != nil {
			showInfo(dlg, "Invalid port list: "+err.Error()+
				"\n\nEnter comma- or space-separated port numbers, e.g.:\n22, 80, 443, 3389",
				"Port Scan")
			return
		}
	}

	serviceMu.Lock()
	enc := serviceEnc
	serviceMu.Unlock()
	if enc == nil {
		showInfo(dlg, "\u26a0  Sensor is not running \u2014 please wait a moment and try again.", "Port Scan")
		return
	}

	modes := []string{"default", "specific", "all"}
	runID := fmt.Sprintf("portscan-%d", time.Now().UnixNano())
	pScanRunID = runID
	pScanRunning = true
	pScanFound = 0
	pScanTotal = 0
	pScanScanned = 0
	pScanTotalPorts = 0
	pScanStartTime = time.Now()
	// Pre-compute the total port count for the chosen mode so we can display
	// "x/y scanned" immediately before the first progress message arrives.
	switch pScanMode {
	case pScanModeAll:
		pScanTotalPorts = 65535
	case pScanModeSpecific:
		pScanTotalPorts = len(specificPorts)
	default: // "default" — read from scanner defaults
		pScanTotalPorts = len(scan.DefaultConfig().Ports)
	}

	// Clear previous results.
	sendMessage(hwndPScanList, LVM_DELETEALLITEMS, 0, 0)
	setWindowText(hwndPScanStatus, "Scanning\u2026")
	setWindowText(hwndPScanScan, "Stop")

	cmd := scan.ServiceCmd{
		Cmd:    "port-scan",
		Target: ip,
		PortScan: &scan.PortScanSpec{
			Mode:           modes[pScanMode],
			Ports:          specificPorts,
			RunID:          runID,
			ThrottlePreset: pScanThrottle,
		},
	}
	serviceEncMu.Lock()
	err := enc.Encode(cmd)
	serviceEncMu.Unlock()
	if err != nil {
		pScanRunning = false
		setWindowText(hwndPScanScan, "Scan")
		setWindowText(hwndPScanStatus, "Ready")
		showInfo(dlg, "Failed to send port scan command: "+err.Error(), "Port Scan")
	}
}

func portScanDlgStop() {
	pScanRunning = false
	setWindowText(hwndPScanScan, "Scan")
	elapsed := portScanFormatElapsed(time.Since(pScanStartTime))
	if pScanFound > 0 {
		setWindowText(hwndPScanStatus, fmt.Sprintf("Stopped \u2014 %d open port(s) found \u00b7 %s", pScanFound, elapsed))
	} else {
		setWindowText(hwndPScanStatus, fmt.Sprintf("Stopped \u00b7 %s", elapsed))
	}

	serviceMu.Lock()
	enc := serviceEnc
	serviceMu.Unlock()
	if enc != nil {
		serviceEncMu.Lock()
		_ = enc.Encode(scan.ServiceCmd{Cmd: "port-scan-stop"})
		serviceEncMu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// Status helpers
// ---------------------------------------------------------------------------

// portScanUpdateStatus refreshes the status label with the current progress.
// Must be called on the UI thread while pScanRunning is true.
func portScanUpdateStatus() {
	elapsed := portScanFormatElapsed(time.Since(pScanStartTime))
	var msg string
	if pScanTotalPorts > 0 {
		msg = fmt.Sprintf("Scanning\u2026 %d/%d scanned \u00b7 %d open \u00b7 %s",
			pScanScanned, pScanTotalPorts, pScanFound, elapsed)
	} else {
		msg = fmt.Sprintf("Scanning\u2026 %d scanned \u00b7 %d open \u00b7 %s",
			pScanScanned, pScanFound, elapsed)
	}
	setWindowText(hwndPScanStatus, msg)
}

// portScanFormatElapsed formats a duration as "Xs" or "Xm Ys".
func portScanFormatElapsed(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	m := int(d.Minutes())
	s := int(d.Seconds()) - m*60
	if s == 0 {
		return fmt.Sprintf("%dm", m)
	}
	return fmt.Sprintf("%dm %ds", m, s)
}

// ---------------------------------------------------------------------------
// Copy Results
// ---------------------------------------------------------------------------

func portScanDlgCopy() {
	n := int32(sendMessage(hwndPScanList, LVM_GETITEMCOUNT, 0, 0))
	if n == 0 {
		return
	}
	var sb strings.Builder
	sb.WriteString("Port\tService\r\n")
	for i := int32(0); i < n; i++ {
		port := listViewGetCellText(hwndPScanList, i, 0)
		svc := listViewGetCellText(hwndPScanList, i, 1)
		sb.WriteString(port)
		sb.WriteByte('\t')
		sb.WriteString(svc)
		sb.WriteString("\r\n")
	}
	copyToClipboard(hwndPScanList, sb.String())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// parsePortList parses a comma- or space-separated list of port numbers.
// Duplicates are silently removed. Returns a sorted, de-duplicated slice.
func parsePortList(s string) ([]int, error) {
	s = strings.ReplaceAll(s, ",", " ")
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return nil, fmt.Errorf("no ports specified")
	}
	seen := make(map[int]bool, len(fields))
	var ports []int
	for _, f := range fields {
		p, err := strconv.Atoi(f)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port: %q (must be 1\u201365535)", f)
		}
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	sort.Ints(ports)
	return ports, nil
}

// portScanServiceName returns the well-known service name for a port, or "".
func portScanServiceName(port int) string {
	switch port {
	case 20:
		return "FTP Data"
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "Telnet"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 67, 68:
		return "DHCP"
	case 80:
		return "HTTP"
	case 88:
		return "Kerberos"
	case 110:
		return "POP3"
	case 111:
		return "RPC"
	case 119:
		return "NNTP"
	case 123:
		return "NTP"
	case 135:
		return "MSRPC"
	case 137, 138:
		return "NetBIOS-NS"
	case 139:
		return "NetBIOS-SSN"
	case 143:
		return "IMAP"
	case 161, 162:
		return "SNMP"
	case 389:
		return "LDAP"
	case 443:
		return "HTTPS"
	case 445:
		return "SMB"
	case 465:
		return "SMTPS"
	case 514:
		return "Syslog"
	case 515:
		return "LPD"
	case 587:
		return "SMTP/TLS"
	case 636:
		return "LDAPS"
	case 993:
		return "IMAPS"
	case 995:
		return "POP3S"
	case 1194:
		return "OpenVPN"
	case 1433:
		return "MSSQL"
	case 1521:
		return "Oracle"
	case 1883:
		return "MQTT"
	case 3268:
		return "LDAP-GC"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	case 5432:
		return "PostgreSQL"
	case 5900:
		return "VNC"
	case 5985:
		return "WinRM-HTTP"
	case 5986:
		return "WinRM-HTTPS"
	case 6379:
		return "Redis"
	case 8080:
		return "HTTP-Alt"
	case 8443:
		return "HTTPS-Alt"
	case 8888:
		return "HTTP-Alt"
	case 9200:
		return "Elasticsearch"
	case 27017:
		return "MongoDB"
	case 51820:
		return "WireGuard"
	default:
		return ""
	}
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

// closePortScanDialog destroys the modeless Port Scan dialog.
func closePortScanDialog() {
	if hwndPortScanDlg == 0 {
		return
	}
	atomic.StoreUintptr(&hwndPortScanDlgAtomic, 0)
	h := hwndPortScanDlg
	hwndPortScanDlg = 0
	hwndPScanIP = 0
	hwndPScanMode = 0
	hwndPScanPorts = 0
	hwndPScanThrottle = 0
	hwndPScanList = 0
	hwndPScanScan = 0
	hwndPScanStatus = 0
	destroyWindow(h)
}

// showPortScanDialog opens the Port Scan dialog.
//   - parent: the owner window.
//   - ip: pre-filled IP address; may be empty.
//   - ipLocked: when true the IP field is read-only (opened from a host row).
func showPortScanDialog(parent HWND, ip string, ipLocked bool) {
	if hwndPortScanDlg != 0 {
		setForegroundWindow(hwndPortScanDlg)
		return
	}

	pScanIPLocked = ipLocked
	pScanRunID = ""
	pScanRunning = false
	pScanFound = 0
	pScanTotal = 0
	pScanScanned = 0
	pScanTotalPorts = 0
	pScanMode = pScanModeDefault
	pScanThrottle = appConfig.Scan.ThrottlePreset
	if pScanThrottle == "" {
		pScanThrottle = scan.ThrottleBalanced
	}

	title := "Port Scan"
	if ip != "" {
		title = "Port Scan \u2014 " + ip
	}

	registerDialogClass("NetScopePortScanDialog", portScanDlgWndProc)
	dlg := createDialogForClient("NetScopePortScanDialog", title, 540, 450, portScanDlgWndProc, parent)
	if dlg == 0 {
		return
	}
	if ip != "" {
		setWindowText(hwndPScanIP, ip)
	}
	setFontAllChildren(dlg, appFont)

	hwndPortScanDlg = dlg
	atomic.StoreUintptr(&hwndPortScanDlgAtomic, uintptr(dlg))
	showWindow(dlg, SW_SHOW)
	updateWindow(dlg)
}
