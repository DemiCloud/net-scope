//go:build windows

package main

import (
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/demicloud/net-sweep/internal/config"
)

// ---------------------------------------------------------------------------
// Modal loop
//
// Win32 has no built-in "make this popup window modal" call for dynamically-
// created windows (only for resource-template DialogBox). We simulate it:
//   1. Disable the parent so it can't be interacted with.
//   2. Run a nested message loop until closeModal() sets modalActive=false.
//   3. closeModal() destroys the dialog and posts WM_NULL to parent so
//      getMessage() returns and the loop condition is re-evaluated.
// ---------------------------------------------------------------------------

var (
	modalActive bool
	modalParent HWND
)

func runModal(dlg, parent HWND) {
	modalActive = true
	modalParent = parent
	enableWindow(parent, false)
	showWindow(dlg, SW_SHOW)
	updateWindow(dlg)

	var msg MSG
	for modalActive && getMessage(&msg) {
		translateMessage(&msg)
		dispatchMessage(&msg)
	}

	enableWindow(parent, true)
	modalActive = false
	modalParent = 0
}

// closeModal is safe to call from inside a dialog WndProc.
func closeModal(dlg HWND) {
	parent := modalParent
	modalActive = false
	destroyWindow(dlg)
	postMessage(parent, WM_NULL, 0, 0) // wake up getMessage
}

// ---------------------------------------------------------------------------
// Settings Dialog
// ---------------------------------------------------------------------------

const (
	idSettOK        = 501
	idSettCancel    = 502
	idSettPingFirst = 503
)

var (
	hwndSettTimeout   HWND
	hwndSettConcur    HWND
	hwndSettPorts     HWND
	hwndSettSNMP      HWND
	hwndSettIface     HWND
	hwndSettBcast     HWND
	hwndSettPingFirst HWND
	hwndSettPath      HWND

	registerSettingsOnce sync.Once
)

var settingsWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createSettingsControls(HWND(hwnd))
		return 0
	case WM_COMMAND:
		switch loword(wParam) {
		case idSettOK:
			if applySettings(HWND(hwnd)) {
				closeModal(HWND(hwnd))
			}
		case idSettCancel:
			closeModal(HWND(hwnd))
		}
		return 0
	case WM_CLOSE:
		closeModal(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

func ensureSettingsClass() {
	registerSettingsOnce.Do(func() {
		cn := utf16("NetSweepSettings")
		wc := WNDCLASSEX{
			CbSize:        uint32(unsafe.Sizeof(WNDCLASSEX{})),
			LpfnWndProc:   settingsWndProc,
			HInstance:     getModuleHandle(),
			HbrBackground: HBRUSH(COLOR_WINDOW + 1),
			HCursor:       loadCursor(IDC_ARROW),
			LpszClassName: cn,
		}
		registerClassEx(&wc)
	})
}

func showSettingsDialog(parent HWND) {
	ensureSettingsClass()

	const dlgW, dlgH int32 = 490, 320
	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetSweepSettings", "Settings",
		WS_POPUP|WS_CAPTION|WS_SYSMENU|WS_CLIPCHILDREN,
		0, 0, dlgW, dlgH,
		parent, 0, getModuleHandle(),
	)
	if err != nil || dlg == 0 {
		return
	}
	centerOnParent(dlg, parent, dlgW, dlgH)

	// Populate fields from the current config.
	cfg, cfgPath, _ := config.Load()
	setWindowText(hwndSettTimeout, cfg.Scan.Timeout)
	setWindowText(hwndSettConcur, strconv.Itoa(cfg.Scan.Concurrency))
	setWindowText(hwndSettPorts, joinInts(cfg.Scan.Ports))
	setWindowText(hwndSettSNMP, cfg.Scan.SNMPCommunity)
	setWindowText(hwndSettIface, cfg.Scan.Interface)
	setWindowText(hwndSettBcast, cfg.Scan.BroadcastListen)
	if cfg.Scan.PingFirst {
		sendMessage(hwndSettPingFirst, BM_SETCHECK, BST_CHECKED, 0)
	}
	if cfgPath == "" {
		cfgPath = config.ConfigPath()
	}
	if cfgPath != "" {
		setWindowText(hwndSettPath, "Saved to: "+cfgPath)
	}

	setFontAllChildren(dlg, appFont)
	runModal(dlg, parent)
}

func createSettingsControls(hwnd HWND) {
	inst := getModuleHandle()
	const (
		lx, lw int32 = 12, 150  // label: left x, width
		ex, ew int32 = 166, 304 // edit:  left x, width
		rh     int32 = 30       // row pitch
		y0     int32 = 12       // first row top
	)

	fields := []struct {
		label string
		dst   *HWND
	}{
		{"Timeout:", &hwndSettTimeout},
		{"Concurrency:", &hwndSettConcur},
		{"Ports:", &hwndSettPorts},
		{"SNMP Community:", &hwndSettSNMP},
		{"Interface:", &hwndSettIface},
		{"Broadcast Listen:", &hwndSettBcast},
	}

	for i, f := range fields {
		y := y0 + int32(i)*rh
		createCtrl("STATIC", f.label, WS_CHILD|WS_VISIBLE, lx, y+4, lw, 16, hwnd, 0, inst)
		*f.dst, _ = createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
			WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL,
			ex, y, ew, 22, hwnd, 0, inst)
	}

	// Ping First checkbox
	checkY := y0 + int32(len(fields))*rh + 4
	hwndSettPingFirst, _ = createWindowEx(0, "BUTTON",
		"Ping First  (ICMP fallback when ARP misses a host)",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX,
		lx, checkY, lw+ew, 22, hwnd, HMENU(idSettPingFirst), inst)

	// Config file path (informational)
	hwndSettPath, _ = createWindowEx(0, "STATIC", "",
		WS_CHILD|WS_VISIBLE,
		lx, checkY+28, lw+ew, 14, hwnd, 0, inst)

	// OK / Cancel
	btnY := checkY + 50
	createCtrl("BUTTON", "OK", WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		306, btnY, 78, 26, hwnd, idSettOK, inst)
	createCtrl("BUTTON", "Cancel", WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		392, btnY, 78, 26, hwnd, idSettCancel, inst)
}

// applySettings reads, validates, and saves the dialog values.
// Returns true on success (dialog may close), false on validation error.
func applySettings(hwnd HWND) bool {
	timeout := strings.TrimSpace(getWindowText(hwndSettTimeout))
	concurStr := strings.TrimSpace(getWindowText(hwndSettConcur))
	portsStr := getWindowText(hwndSettPorts)
	snmp := strings.TrimSpace(getWindowText(hwndSettSNMP))
	iface := strings.TrimSpace(getWindowText(hwndSettIface))
	bcast := strings.TrimSpace(getWindowText(hwndSettBcast))
	pingFirst := sendMessage(hwndSettPingFirst, BM_GETCHECK, 0, 0) == BST_CHECKED

	if _, err := time.ParseDuration(timeout); err != nil {
		messageBox(hwnd, `Timeout must be a Go duration string, e.g. "1s" or "500ms".`, "Invalid Input", 0)
		return false
	}

	concur, err := strconv.Atoi(concurStr)
	if err != nil || concur < 1 {
		messageBox(hwnd, "Concurrency must be a positive integer.", "Invalid Input", 0)
		return false
	}

	var ports []int
	for _, token := range strings.Split(portsStr, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		p, err := strconv.Atoi(token)
		if err != nil || p < 1 || p > 65535 {
			messageBox(hwnd, "Ports must be comma-separated integers between 1 and 65535.", "Invalid Input", 0)
			return false
		}
		ports = append(ports, p)
	}

	if bcast != "" {
		if _, err := time.ParseDuration(bcast); err != nil {
			messageBox(hwnd, `Broadcast Listen must be a Go duration string, e.g. "3s".`, "Invalid Input", 0)
			return false
		}
	}

	cfg := config.Config{
		Scan: config.ScanConfig{
			Timeout:         timeout,
			Concurrency:     concur,
			Ports:           ports,
			PingFirst:       pingFirst,
			BroadcastListen: bcast,
			SNMPCommunity:   snmp,
			Interface:       iface,
		},
	}

	if err := config.Save(cfg); err != nil {
		messageBox(hwnd, "Could not save settings:\n"+err.Error(), "Error", 0)
		return false
	}
	return true
}

func joinInts(vals []int) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------------------
// FAQ / Help Dialog
// ---------------------------------------------------------------------------

const idFAQClose = 601

var registerFAQOnce sync.Once

var faqWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_COMMAND:
		closeModal(HWND(hwnd))
		return 0
	case WM_CLOSE:
		closeModal(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

func ensureFAQClass() {
	registerFAQOnce.Do(func() {
		cn := utf16("NetSweepFAQ")
		wc := WNDCLASSEX{
			CbSize:        uint32(unsafe.Sizeof(WNDCLASSEX{})),
			LpfnWndProc:   faqWndProc,
			HInstance:     getModuleHandle(),
			HbrBackground: HBRUSH(COLOR_WINDOW + 1),
			HCursor:       loadCursor(IDC_ARROW),
			LpszClassName: cn,
		}
		registerClassEx(&wc)
	})
}

func showFAQDialog(parent HWND) {
	ensureFAQClass()

	const dlgW, dlgH int32 = 580, 540
	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetSweepFAQ", "Help — Frequently Asked Questions",
		WS_POPUP|WS_CAPTION|WS_SYSMENU|WS_CLIPCHILDREN,
		0, 0, dlgW, dlgH,
		parent, 0, getModuleHandle(),
	)
	if err != nil || dlg == 0 {
		return
	}
	centerOnParent(dlg, parent, dlgW, dlgH)

	inst := getModuleHandle()

	// Scrollable readonly text area fills the dialog body.
	createWindowEx(
		WS_EX_CLIENTEDGE, "EDIT", faqText,
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
		8, 8, dlgW-24, dlgH-62, dlg, 0, inst,
	)

	createCtrl("BUTTON", "Close", WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		dlgW-100, dlgH-46, 82, 28, dlg, idFAQClose, inst)

	setFontAllChildren(dlg, appFont)
	runModal(dlg, parent)
}

const faqText = `net-sweep — Frequently Asked Questions

Q: Why doesn't the MAC address column populate?
A: MAC addresses are obtained via ARP (Address Resolution Protocol), which only works within a single subnet. If you are scanning a remote subnet — connected through a router rather than being directly on that network — ARP requests cannot reach the targets.

   Elevation (Administrator) helps on locally-attached interfaces, but cannot bridge subnet boundaries.

   Solutions:
     • Run net-sweep from a machine physically on the same subnet as the targets.
     • For remote devices, SNMP can sometimes report the MAC via ifPhysAddress if the device has SNMP enabled.

Q: Why does net-sweep recommend running as Administrator?
A: Batch ARP scanning uses a raw Ethernet socket, which Windows restricts to Administrator accounts. Port scanning, ICMP ping, and reverse DNS all work without elevation — you simply won't get MAC or vendor information.

Q: How do I change which ports are scanned?
A: Open Options → Settings. Edit the "Ports" field with a comma-separated list. Click OK to save; the new list takes effect on the next scan.

Q: Why is the Broadcast tab empty?
A: Broadcast discovery (mDNS/SSDP) passively listens for devices that advertise themselves. If nothing is advertising during the scan window, the tab stays empty. Increase "Broadcast Listen" in Options → Settings, or check that multicast traffic is not being blocked on your network.

Q: What does the SNMP / Model column show?
A: If a device responds to SNMP v2c queries, net-sweep reads sysDescr, sysName, and sysLocation. This commonly includes the device model and firmware version — useful for identifying switches and routers before you re-IP them. Change the community string in Options → Settings (default: "public").

Q: Hostnames show as "—" for some hosts — why?
A: Hostname resolution uses reverse DNS (PTR lookup). Hosts without a PTR record, or whose DNS server does not expose reverse lookups, will show no hostname. This is normal on flat home or SMB networks.

Q: How do I scan a single host instead of a whole subnet?
A: Enter a single IP address (e.g. 10.1.10.5) in the Target box. CIDR notation (10.1.10.0/24) and dash ranges (10.1.10.1-50) are also supported.

Q: Why does scanning a /24 pre-populate 254 rows immediately?
A: net-sweep inserts a placeholder row for every IP in the subnet before the scan starts. This keeps results in sorted IP order and gives you a live view of which addresses are still pending. Each row updates in place as the host is probed.

Q: Settings were saved — when do they take effect?
A: Settings take effect the next time you click Scan. Any scan already in progress continues with the configuration it started with.`
