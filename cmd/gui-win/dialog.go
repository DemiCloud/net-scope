//go:build windows

package guiwin

import (
	"os"
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
	setForegroundWindow(dlg)

	var msg MSG
	for modalActive && getMessage(&msg) {
		translateMessage(&msg)
		dispatchMessage(&msg)
	}

	// closeModal already re-enabled the parent and set focus;
	// clear state here in case we exited the loop another way.
	enableWindow(parent, true)
	modalActive = false
	modalParent = 0
}

// closeModal is safe to call from inside a dialog WndProc.
func closeModal(dlg HWND) {
	parent := modalParent
	modalActive = false
	destroyWindow(dlg)
	// Re-enable and bring the parent back to the foreground before posting
	// WM_NULL, so it doesn't disappear behind other windows.
	enableWindow(parent, true)
	setForegroundWindow(parent)
	setFocus(parent)
	postMessage(parent, WM_NULL, 0, 0) // wake up getMessage
}

// ---------------------------------------------------------------------------
// Settings Dialog
// ---------------------------------------------------------------------------

const (
	idSettOK            = 501
	idSettCancel        = 502
	idSettPingFirst     = 503
	idSettBannerGrab    = 504
	idSettNetBIOS       = 505
	idSettDefaultTarget = 506
)

var (
	hwndSettTimeout   HWND
	hwndSettConcur    HWND
	hwndSettPorts     HWND
	hwndSettSNMP      HWND
	hwndSettIface     HWND
	hwndSettBcast     HWND
	hwndSettPingFirst HWND
	hwndSettBanner    HWND
	hwndSettNetBIOS       HWND
	hwndSettPath          HWND
	hwndSettDefaultTarget HWND

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

	// Populate fields from the current in-memory config (appConfig), which
	// reflects any changes already made this session.
	cfg, cfgPath, _ := config.Load()
	_ = cfg // we'll use appConfig below if it's been modified

	// Build a descriptive title: show the config file being edited, or
	// indicate these are runtime-only settings if no file exists.
	var titleSuffix string
	if cfgPath != "" {
		titleSuffix = "Editing: " + cfgPath
	} else {
		titleSuffix = "First Run — settings apply this session; use OK to save"
	}

	const dlgW, dlgH int32 = 560, 400
	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetSweepSettings", "Settings — "+titleSuffix,
		WS_POPUP|WS_CAPTION|WS_SYSMENU|WS_CLIPCHILDREN,
		0, 0, dlgW, dlgH,
		parent, 0, getModuleHandle(),
	)
	if err != nil || dlg == 0 {
		return
	}
	centerOnParent(dlg, parent, dlgW, dlgH)

	// Populate fields from the current config.
	setWindowText(hwndSettTimeout, appConfig.Scan.Timeout)
	setWindowText(hwndSettConcur, strconv.Itoa(appConfig.Scan.Concurrency))
	setWindowText(hwndSettPorts, joinInts(appConfig.Scan.Ports))
	setWindowText(hwndSettSNMP, appConfig.Scan.SNMPCommunity)
	setWindowText(hwndSettIface, appConfig.Scan.Interface)
	setWindowText(hwndSettBcast, appConfig.Scan.BroadcastListen)
	setWindowText(hwndSettDefaultTarget, appConfig.Scan.DefaultTarget)
	if appConfig.Scan.PingFirst {
		sendMessage(hwndSettPingFirst, BM_SETCHECK, BST_CHECKED, 0)
	}
	if appConfig.Scan.BannerGrab {
		sendMessage(hwndSettBanner, BM_SETCHECK, BST_CHECKED, 0)
	}
	if appConfig.Scan.NetBIOS {
		sendMessage(hwndSettNetBIOS, BM_SETCHECK, BST_CHECKED, 0)
	}

	// Status line at the bottom of the dialog.
	if cfgPath != "" {
		setWindowText(hwndSettPath, "Config file: "+cfgPath)
	} else {
		setWindowText(hwndSettPath, "No config file found — saving will prompt for a location.")
	}

	setFontAllChildren(dlg, appFont)
	runModal(dlg, parent)
}

func createSettingsControls(hwnd HWND) {
	inst := getModuleHandle()
	const (
		lx, lw int32 = 12, 150  // label: left x, width
		ex, ew int32 = 166, 374 // edit:  left x, width
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
		{"Default Target:", &hwndSettDefaultTarget},
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

	hwndSettBanner, _ = createWindowEx(0, "BUTTON",
		"Banner Grab  (HTTP Server header, SSH version, FTP/SMTP greeting)",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX,
		lx, checkY+28, lw+ew, 22, hwnd, HMENU(idSettBannerGrab), inst)

	hwndSettNetBIOS, _ = createWindowEx(0, "BUTTON",
		"NetBIOS Queries  (Windows computer names via UDP 137)",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX,
		lx, checkY+56, lw+ew, 22, hwnd, HMENU(idSettNetBIOS), inst)

	// Config file path (informational)
	hwndSettPath, _ = createWindowEx(0, "STATIC", "",
		WS_CHILD|WS_VISIBLE,
		lx, checkY+84, lw+ew, 28, hwnd, 0, inst)

	// OK / Cancel
	btnY := checkY + 110
	createCtrl("BUTTON", "OK", WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		306, btnY, 78, 26, hwnd, idSettOK, inst)
	createCtrl("BUTTON", "Cancel", WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		392, btnY, 78, 26, hwnd, idSettCancel, inst)
}

// applySettings reads and validates the dialog values, applies them to memory,
// and saves to the config file if one was loaded at startup.
// Returns true if values were valid (dialog should close).
func applySettings(hwnd HWND) bool {
	timeout := strings.TrimSpace(getWindowText(hwndSettTimeout))
	concurStr := strings.TrimSpace(getWindowText(hwndSettConcur))
	portsStr := getWindowText(hwndSettPorts)
	snmp := strings.TrimSpace(getWindowText(hwndSettSNMP))
	iface := strings.TrimSpace(getWindowText(hwndSettIface))
	bcast := strings.TrimSpace(getWindowText(hwndSettBcast))
	defaultTarget := strings.TrimSpace(getWindowText(hwndSettDefaultTarget))
	pingFirst := sendMessage(hwndSettPingFirst, BM_GETCHECK, 0, 0) == BST_CHECKED
	bannerGrab := sendMessage(hwndSettBanner, BM_GETCHECK, 0, 0) == BST_CHECKED
	netBIOS := sendMessage(hwndSettNetBIOS, BM_GETCHECK, 0, 0) == BST_CHECKED

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
			BannerGrab:      bannerGrab,
			NetBIOS:         netBIOS,
			DefaultTarget:   defaultTarget,
		},
	}

	appConfig = cfg // always apply in-memory

	// Determine save path: use the file we loaded, or prompt for a location.
	_, cfgPath, _ := config.Load()
	if cfgPath == "" {
		cfgPath = chooseConfigSavePath(hwnd)
	}
	if cfgPath != "" {
		if err := config.SaveTo(cfg, cfgPath); err != nil {
			messageBox(hwnd, "Could not save settings:\n"+err.Error(), "Error", 0)
			return false
		}
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

// chooseConfigSavePath returns the path to save the config to.
// If a config file already exists at either known location, it uses that path
// without prompting. On first save it shows a dialog with three options:
//   - AppData  (e.g. %APPDATA%\demicloud\net-sweep\config.toml)
//   - Beside exe (same directory as net-sweep.exe)
//   - Neither  (keep in memory; returns "")
func chooseConfigSavePath(hwnd HWND) string {
	appDataPath := config.ConfigPath()
	exePath := config.ExeLocalPath()

	// If a config already exists, save back to the same place — no prompt.
	if fileExists(appDataPath) {
		return appDataPath
	}
	if fileExists(exePath) {
		return exePath
	}

	// First save: ask the user.
	return showConfigLocationDialog(hwnd, appDataPath, exePath)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ---------------------------------------------------------------------------
// Config Location Dialog (first save)
// ---------------------------------------------------------------------------

const (
	idCfgAppData = 701
	idCfgExeDir  = 702
	idCfgNeither = 703
)

var (
	registerCfgLocOnce sync.Once
	cfgLocResult       string // set by the dialog before closeModal
)

var cfgLocWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_COMMAND:
		switch loword(wParam) {
		case idCfgAppData:
			cfgLocResult = "appdata"
			closeModal(HWND(hwnd))
		case idCfgExeDir:
			cfgLocResult = "exedir"
			closeModal(HWND(hwnd))
		case idCfgNeither:
			cfgLocResult = "neither"
			closeModal(HWND(hwnd))
		}
		return 0
	case WM_CLOSE:
		cfgLocResult = "neither"
		closeModal(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

func ensureCfgLocClass() {
	registerCfgLocOnce.Do(func() {
		cn := utf16("NetSweepCfgLoc")
		wc := WNDCLASSEX{
			CbSize:        uint32(unsafe.Sizeof(WNDCLASSEX{})),
			LpfnWndProc:   cfgLocWndProc,
			HInstance:     getModuleHandle(),
			HbrBackground: HBRUSH(COLOR_WINDOW + 1),
			HCursor:       loadCursor(IDC_ARROW),
			LpszClassName: cn,
		}
		registerClassEx(&wc)
	})
}

func showConfigLocationDialog(parent HWND, appDataPath, exePath string) string {
	ensureCfgLocClass()
	cfgLocResult = "neither"

	const dlgW, dlgH int32 = 520, 310
	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetSweepCfgLoc", "Where should net-sweep save its config?",
		WS_POPUP|WS_CAPTION|WS_SYSMENU|WS_CLIPCHILDREN,
		0, 0, dlgW, dlgH,
		parent, 0, getModuleHandle(),
	)
	if err != nil || dlg == 0 {
		return ""
	}
	centerOnParent(dlg, parent, dlgW, dlgH)

	inst := getModuleHandle()
	y := int32(14)

	createCtrl("STATIC",
		"No config file found. Choose where net-sweep should save its settings.",
		WS_CHILD|WS_VISIBLE, 14, y, dlgW-28, 20, dlg, 0, inst)
	y += 30

	createCtrl("STATIC", "Option 1 — User profile (recommended):",
		WS_CHILD|WS_VISIBLE, 14, y, dlgW-28, 18, dlg, 0, inst)
	y += 18
	createCtrl("STATIC", "  "+appDataPath,
		WS_CHILD|WS_VISIBLE, 14, y, dlgW-28, 18, dlg, 0, inst)
	y += 22
	createCtrl("BUTTON", "Save to AppData",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		14, y, 160, 26, dlg, idCfgAppData, inst)
	y += 38

	createCtrl("STATIC", "Option 2 — Beside the executable (portable):",
		WS_CHILD|WS_VISIBLE, 14, y, dlgW-28, 18, dlg, 0, inst)
	y += 18
	createCtrl("STATIC", "  "+exePath,
		WS_CHILD|WS_VISIBLE, 14, y, dlgW-28, 18, dlg, 0, inst)
	y += 22
	createCtrl("BUTTON", "Save beside exe",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		14, y, 160, 26, dlg, idCfgExeDir, inst)
	y += 38

	createCtrl("STATIC", "Option 3 — Don't save (settings apply this session only):",
		WS_CHILD|WS_VISIBLE, 14, y, dlgW-28, 18, dlg, 0, inst)
	y += 22
	createCtrl("BUTTON", "Don't save",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		14, y, 160, 26, dlg, idCfgNeither, inst)

	setFontAllChildren(dlg, appFont)
	runModal(dlg, parent)

	switch cfgLocResult {
	case "appdata":
		return appDataPath
	case "exedir":
		return exePath
	default:
		return ""
	}
}

// ---------------------------------------------------------------------------
// FAQ / Help Dialog
// ---------------------------------------------------------------------------

const idFAQClose = 601

var registerFAQOnce sync.Once

var faqWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_COMMAND:
		if loword(wParam) == idFAQClose {
			closeModal(HWND(hwnd))
		}
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

	const dlgW, dlgH int32 = 600, 560
	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME|WS_EX_TOPMOST,
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

	// Win32 EDIT controls require \r\n for line breaks.
	displayText := strings.ReplaceAll(faqText, "\n", "\r\n")

	hwndEdit, _ := createWindowEx(
		WS_EX_CLIENTEDGE, "EDIT", displayText,
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
		8, 8, dlgW-24, dlgH-62, dlg, 0, inst,
	)
	monoFont := createMonoFont()
	sendMessage(hwndEdit, WM_SETFONT, uintptr(monoFont), 1)

	_, _ = createWindowEx(0, "BUTTON", "Close",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		dlgW-100, dlgH-46, 82, 28, dlg, HMENU(idFAQClose), inst)

	setFontAllChildren(dlg, appFont)
	sendMessage(hwndEdit, WM_SETFONT, uintptr(monoFont), 1) // restore after setFontAllChildren

	// Run a self-contained modal loop scoped to the dialog.
	// We do NOT disable the parent — instead WS_EX_TOPMOST keeps the dialog
	// above the main window without stealing its message pump, which avoids
	// the "disappears behind other windows" bug.
	showWindow(dlg, SW_SHOW)
	updateWindow(dlg)
	setForegroundWindow(dlg)

	var msg MSG
	for {
		if !getMessage(&msg) {
			break
		}
		if msg.HWnd == dlg || isChild(dlg, msg.HWnd) {
			translateMessage(&msg)
			dispatchMessage(&msg)
			if !isWindow(dlg) {
				break // dialog was destroyed
			}
		} else {
			// Let the main window handle its own messages normally.
			translateMessage(&msg)
			dispatchMessage(&msg)
		}
	}
	setForegroundWindow(parent)
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
A: Settings take effect the next time you click Scan. Any scan already in progress continues with the configuration it started with.

Q: What is Admin Mode, and what features require it?
A: "Admin Mode" means running net-sweep as a Windows Administrator (or with root privileges on Linux).

   Features that REQUIRE elevation:
     • MAC address discovery — raw Ethernet (ARP) sockets are restricted to administrators.
     • Vendor lookup — depends on MAC, so also requires elevation.
     • ICMP ping (traditional raw-socket ping) — requires a raw IP socket on many systems.

   Features that work WITHOUT elevation:
     • TCP port scanning
     • Reverse DNS / hostname resolution
     • NetBIOS name queries (UDP 137)
     • SNMP queries
     • mDNS / SSDP broadcast discovery
     • Banner grabbing (SSH, HTTP, FTP, SMTP, Telnet)
     • OS hint (inferred from banners, TTL, SNMP)

   In short: you will always get port-level host discovery without elevation, but you won't
   see MAC addresses or vendor names. For full results, right-click the net-sweep executable
   and choose "Run as administrator".`

// ---------------------------------------------------------------------------
// Version Info Dialog
// ---------------------------------------------------------------------------

func showVersionDialog(parent HWND) {
	body := "net-sweep " + version + "\n\n" +
		"Build information\n" +
		"─────────────────\n" +
		"  Version : " + version + "\n" +
		"  Source  : https://github.com/demicloud/net-sweep\n\n" +
		"Command-line equivalent\n" +
		"────────────────────────\n" +
		"  net-sweep --version\n"

	messageBox(parent, body, "Version — net-sweep", 0)
}

