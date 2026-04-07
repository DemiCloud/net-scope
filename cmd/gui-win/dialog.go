//go:build windows

package guiwin

import (
	"bytes"
	"image/color"
	"image/png"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
	"github.com/demicloud/net-scope/internal/config"
	"github.com/demicloud/net-scope/internal/sweep"
)

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
	hwndSettTimeout       HWND
	hwndSettConcur        HWND
	hwndSettPorts         HWND
	hwndSettSNMP          HWND
	hwndSettIface         HWND
	hwndSettBcast         HWND
	hwndSettPingFirst     HWND
	hwndSettBanner        HWND
	hwndSettNetBIOS       HWND
	hwndSettPath          HWND
	hwndSettDefaultTarget HWND
)

var settingsWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createSettingsControls(HWND(hwnd))
		return 0
	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)
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

func showSettingsDialog(parent HWND) {
	registerDialogClass("NetSweepSettings", settingsWndProc)

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

	const dlgW, dlgH int32 = 560, 440
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
		createCtrl("STATIC", f.label, WS_CHILD|WS_VISIBLE, lx, y+4, lw, 18, hwnd, 0, inst)
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

	// Config file path (informational) — allow 3 lines for long paths
	hwndSettPath, _ = createWindowEx(0, "STATIC", "",
		WS_CHILD|WS_VISIBLE,
		lx, checkY+84, lw+ew, 40, hwnd, 0, inst)

	// OK / Cancel — below path label (checkY+84+40) + 8px gap
	btnY := checkY + 132
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
//   - AppData  (e.g. %APPDATA%\demicloud\net-scope\config.toml)
//   - Beside exe (same directory as net-scope.exe)
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

var cfgLocResult string // set by the dialog before closeModal

var cfgLocWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)
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

func showConfigLocationDialog(parent HWND, appDataPath, exePath string) string {
	registerDialogClass("NetSweepCfgLoc", cfgLocWndProc)
	cfgLocResult = "neither"

	const dlgW, dlgH int32 = 520, 360
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
				"No config file found. Choose where NetScope should save its settings.",
		WS_CHILD|WS_VISIBLE, 14, y, dlgW-28, 20, dlg, 0, inst)
	y += 30

	createCtrl("STATIC", "Option 1 — User profile (recommended):",
		WS_CHILD|WS_VISIBLE, 14, y, dlgW-28, 18, dlg, 0, inst)
	y += 20
	createCtrl("STATIC", "  "+appDataPath,
		WS_CHILD|WS_VISIBLE, 14, y, dlgW-28, 28, dlg, 0, inst)
	y += 32
	createCtrl("BUTTON", "Save to AppData",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		14, y, 160, 26, dlg, idCfgAppData, inst)
	y += 38

	createCtrl("STATIC", "Option 2 — Beside the executable (portable):",
		WS_CHILD|WS_VISIBLE, 14, y, dlgW-28, 18, dlg, 0, inst)
	y += 20
	createCtrl("STATIC", "  "+exePath,
		WS_CHILD|WS_VISIBLE, 14, y, dlgW-28, 28, dlg, 0, inst)
	y += 32
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

var faqWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)
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

func showFAQDialog(parent HWND) {
	registerDialogClass("NetSweepFAQ", faqWndProc)

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
	body := "NetScope " + version + "\n" +
		"Network inspection and reconnaissance — active probing, passive signal analysis, change detection.\n\n" +
		"Build information\n" +
		"─────────────────\n" +
		"  Version : " + version + "\n" +
		"  Source  : https://github.com/demicloud/net-scope\n\n" +
		"Command-line equivalent\n" +
		"────────────────────────\n" +
		"  net-scope --version\n"

	messageBox(parent, body, "Version — NetScope", 0)
}

// ---------------------------------------------------------------------------
// Databases Dialog  (Options > Databases…)
// ---------------------------------------------------------------------------

const (
	idDBClose      = 701
	idDBDownload   = 702
	idDBStatusText = 703
)

var (
	hwndDBStatus   HWND
	hwndDBDownload HWND
)

var databasesWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createDatabasesControls(HWND(hwnd))
		return 0
	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)
	case WM_COMMAND:
		switch loword(wParam) {
		case idDBDownload:
			setWindowText(hwndDBStatus, "Downloading… this may take up to 60 seconds.")
			enableWindow(hwndDBDownload, false)
			parent := HWND(hwnd)
			go func() {
				dataDir := config.DataDir()
				_, err := sweep.DownloadOUIDB(dataDir)
				if err != nil {
					postMessage(parent, WM_APP+20, 0, 0) // failure
				} else {
					postMessage(parent, WM_APP+21, 0, 0) // success
				}
			}()
		case idDBClose:
			closeModal(HWND(hwnd))
		}
		return 0
	case WM_APP + 20: // download failed
		setWindowText(hwndDBStatus, "Download failed — check your internet connection and try again.")
		return 0
	case WM_APP + 21: // download succeeded
		dataDir := config.DataDir()
		setWindowText(hwndDBStatus, sweep.OUIStatus(dataDir))
		return 0
	case WM_CLOSE:
		closeModal(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

func showDatabasesDialog(parent HWND) {
	registerDialogClass("NetSweepDatabases", databasesWndProc)
	const dlgW, dlgH int32 = 560, 330
	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetSweepDatabases", "Databases",
		WS_POPUP|WS_CAPTION|WS_SYSMENU|WS_CLIPCHILDREN,
		0, 0, dlgW, dlgH,
		parent, 0, getModuleHandle(),
	)
	if err != nil || dlg == 0 {
		return
	}
	centerOnParent(dlg, parent, dlgW, dlgH)

	// Populate the OUI status now that the HWND exists.
	dataDir := config.DataDir()
	setWindowText(hwndDBStatus, sweep.OUIStatus(dataDir))

	setFontAllChildren(dlg, appFont)
	runModal(dlg, parent)
}

func createDatabasesControls(hwnd HWND) {
	inst := getModuleHandle()
	const lx int32 = 14
	const cw int32 = 532

	y := int32(14)

	// ── Section: MAC Vendor (OUI) Database ──────────────────────────────────
	createCtrl("STATIC", "MAC Vendor (OUI) Database",
		WS_CHILD|WS_VISIBLE, lx, y, cw, 18, hwnd, 0, inst)
	y += 22

	createCtrl("STATIC",
		"Maps MAC address prefixes to manufacturer names. Used in the Hosts tab Vendor column.",
		WS_CHILD|WS_VISIBLE, lx, y, cw, 32, hwnd, 0, inst)
	y += 36

	// Status line — multiline so long strings wrap rather than scroll
	hwndDBStatus, _ = createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "Checking…",
		WS_CHILD|WS_VISIBLE|ES_READONLY|ES_MULTILINE,
		lx, y, cw, 40, hwnd, idDBStatusText, inst)
	y += 50

	// Data directory info — allow two lines for long paths
	dataDir := config.DataDir()
	dirLabel := "Data directory: " + dataDir
	createCtrl("STATIC", dirLabel,
		WS_CHILD|WS_VISIBLE, lx, y, cw, 36, hwnd, 0, inst)
	y += 44

	createCtrl("STATIC",
		"Download a fresh copy from maclookup.app (~7 MB). If the file exists it\r\n"+
			"is used instead of the built-in data; delete it to revert to the built-in copy.",
		WS_CHILD|WS_VISIBLE, lx, y, cw, 36, hwnd, 0, inst)
	y += 46

	hwndDBDownload, _ = createWindowEx(0, "BUTTON", "Download updated database",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		lx, y, 210, 26, hwnd, idDBDownload, inst)

	// ── Close button — same right margin as Download has left margin ─────────
	createCtrl("BUTTON", "Close",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		cw-80, y, 80, 26, hwnd, idDBClose, inst)
}

// ---------------------------------------------------------------------------
// About Dialog
// ---------------------------------------------------------------------------

const idAboutOK = 901

var aboutHIcon HICON // 96×96 programmatic icon kept alive during the dialog

// aboutIconWndProc is the WndProc for the small icon child window inside the
// About dialog.  WM_PAINT draws the icon; WM_RBUTTONUP shows a context menu
// with "Copy Image", which puts a CF_DIB bitmap onto the clipboard.
var aboutIconWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_PAINT:
		var ps PAINTSTRUCT
		hdc := beginPaint(HWND(hwnd), &ps)
		if aboutHIcon != 0 {
			drawIconEx(hdc, 0, 0, aboutHIcon, 96, 96, 0, 0, DI_NORMAL)
		}
		endPaint(HWND(hwnd), &ps)
		return 0
	case WM_RBUTTONUP:
		pt := getCursorPos()
		menu := createPopupMenu()
		appendMenu(menu, MF_STRING, IDM_CTX_COPY_ICON, "Copy Image")
		// TPM_RETURNCMD: TrackPopupMenu returns the command ID directly
		// instead of posting WM_COMMAND, which is more reliable for child windows.
		cmd := trackPopupMenu(menu, TPM_RIGHTBUTTON|TPM_RETURNCMD, pt.X, pt.Y, HWND(hwnd))
		destroyMenu(menu)
		if int(cmd) == IDM_CTX_COPY_ICON {
			copyIconToClipboard(HWND(hwnd), 256)
		}
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

var aboutWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		inst := getModuleHandle()
		cW, cH := int32(390), int32(190)

		registerDialogClass("NSAboutIcon", aboutIconWndProc)
		createWindowEx(0, "NSAboutIcon", "",
			WS_CHILD|WS_VISIBLE,
			14, 14, 96, 96,
			HWND(hwnd), 0, inst)

		text := "NetScope  " + version + "\r\n\r\n" +
			"Network inspection & reconnaissance\r\n" +
			"for LAN environments.\r\n\r\n" +
			"Active probing · Passive signal analysis\r\n" +
			"Change detection across scans\r\n\r\n" +
			"github.com/demicloud/net-scope"
		createWindowEx(0, "STATIC", text,
			WS_CHILD|WS_VISIBLE|SS_LEFT,
			126, 14, cW-126-14, 130,
			HWND(hwnd), 0, inst)

		btnY, btnXs := dlgBottomRight(cW, cH, 1)
		createWindowEx(0, "BUTTON", "OK",
			WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON,
			btnXs[0], btnY, 100, 26,
			HWND(hwnd), HMENU(idAboutOK), inst)

		dpi := getDpiForWindow(HWND(hwnd))
		setFontAllChildren(HWND(hwnd), createUIFont(dpi))
		return 0
	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)
	case WM_COMMAND:
		if loword(wParam) == idAboutOK {
			closeModal(HWND(hwnd))
		}
		return 0
	case WM_CLOSE:
		closeModal(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

func showAboutDialog(parent HWND) {
	aboutHIcon = createAppIcon(96)

	registerDialogClass("NSAbout", aboutWndProc)

	dlgW, dlgH := int32(390), int32(190)
	inst := getModuleHandle()
	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NSAbout", "About NetScope",
		WS_POPUP|WS_CAPTION|WS_SYSMENU,
		CW_USEDEFAULT, CW_USEDEFAULT, dlgW, dlgH,
		parent, 0, inst,
	)
	if err != nil || dlg == 0 {
		destroyIcon(aboutHIcon)
		aboutHIcon = 0
		return
	}

	// Center over parent
	pr := getWindowRect(parent)
	dr := getWindowRect(dlg)
	x := pr.Left + (pr.Right-pr.Left-(dr.Right-dr.Left))/2
	y := pr.Top + (pr.Bottom-pr.Top-(dr.Bottom-dr.Top))/2
	setWindowPos(dlg, 0, x, y, 0, 0, SWP_NOZORDER|SWP_NOSIZE|SWP_NOACTIVATE)

	runModal(dlg, parent)

	destroyIcon(aboutHIcon)
	aboutHIcon = 0
}

// copyIconToClipboard renders the icon at sz×sz pixels and puts it on the
// clipboard in two formats:
//
//   - "PNG"  (registered format) — lossless RGBA; consumed by Teams, Copilot,
//     browsers, and most modern apps.
//   - CF_DIB — 32-bpp BGR; fallback for older Win32 apps (e.g. Paint).
//
// CF_DIB alone fails in modern apps because the alpha byte is 0 (fully
// transparent) in BI_RGB mode, so receivers see an empty image.
func copyIconToClipboard(owner HWND, sz int) {
	img := drawIcon(sz)

	// Composite the circular icon over the solid dark-navy background so the
	// pasted image has no transparent (white) corners in destination apps.
	bgR, bgG, bgB := uint8(10), uint8(20), uint8(40)
	for y := 0; y < sz; y++ {
		for x := 0; x < sz; x++ {
			c := img.RGBAAt(x, y)
			if c.A == 255 {
				continue
			}
			a := float64(c.A) / 255.0
			img.SetRGBA(x, y, color.RGBA{
				R: uint8(float64(c.R)*a + float64(bgR)*(1-a)),
				G: uint8(float64(c.G)*a + float64(bgG)*(1-a)),
				B: uint8(float64(c.B)*a + float64(bgB)*(1-a)),
				A: 255,
			})
		}
	}

	// ── PNG encoding ────────────────────────────────────────────────────────
	var pngBuf bytes.Buffer
	if err := png.Encode(&pngBuf, img); err == nil {
		pngBytes := pngBuf.Bytes()
		hPNG := globalAlloc(GMEM_MOVEABLE, uintptr(len(pngBytes)))
		if hPNG != 0 {
			if ptr := globalLock(hPNG); ptr != 0 {
				dst := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), len(pngBytes))
				copy(dst, pngBytes)
				globalUnlock(hPNG)
			}
		}
		cfPNG := registerClipboardFormat("PNG")

		// ── CF_DIB (BITMAPINFOHEADER + 32-bpp BGR rows) ────────────────────
		const hdrSize = 40
		total := hdrSize + sz*sz*4
		hDIB := globalAlloc(GMEM_MOVEABLE, uintptr(total))
		if hDIB != 0 {
			if ptr := globalLock(hDIB); ptr != 0 {
				buf := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), total)
				for i := range buf {
					buf[i] = 0
				}
				pu32 := func(off int, v uint32) {
					buf[off], buf[off+1], buf[off+2], buf[off+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
				}
				pu16 := func(off int, v uint16) { buf[off], buf[off+1] = byte(v), byte(v>>8) }
				pu32(0, 40)                   // biSize
				pu32(4, uint32(sz))           // biWidth
				pu32(8, uint32(-int32(sz)))   // biHeight (negative = top-down)
				pu16(12, 1)                   // biPlanes
				pu16(14, 32)                  // biBitCount
				pu32(20, uint32(sz*sz*4))     // biSizeImage
				off := hdrSize
				for row := 0; row < sz; row++ {
					for col := 0; col < sz; col++ {
						c := img.RGBAAt(col, row)
						buf[off+0] = c.B
						buf[off+1] = c.G
						buf[off+2] = c.R
						buf[off+3] = 0
						off += 4
					}
				}
				globalUnlock(hDIB)
			}
		}

		// Open clipboard and set both formats in one session.
		openClipboard(owner)
		emptyClipboard()
		if cfPNG != 0 && hPNG != 0 {
			setClipboardData(cfPNG, hPNG)
		}
		if hDIB != 0 {
			setClipboardData(CF_DIB, hDIB)
		}
		closeClipboard()
	}
}

// ---------------------------------------------------------------------------
// Edit Columns dialog
// ---------------------------------------------------------------------------

// editColsChecks holds the HWND of each column's checkbox (indexed by col).
// Col 0 (Status) is always visible and has no checkbox.
var editColsChecks [10]HWND

func showEditColumnsDialog(parent HWND) {
	registerDialogClass("NetScopeEditCols", syscall.NewCallback(editColsWndProc))

	const w, h = 270, 330
	aw, ah := scale(w), scale(h)
	dlg, _ := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetScopeEditCols", "Edit Columns",
		WS_POPUP|WS_CAPTION|WS_SYSMENU,
		0, 0, aw, ah, parent, 0, getModuleHandle(),
	)
	centerWindowOver(dlg, parent)
	runModal(dlg, parent)
}

func editColsWndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		sendMessage(HWND(hwnd), WM_SETFONT, uintptr(appFont), 1)

		// One checkbox per column 1–9 (col 0 "Status" is always visible).
		for col := int32(1); col <= 9; col++ {
			y := scale(12) + (col-1)*scale(26)
			editColsChecks[col], _ = createWindowEx(0, "BUTTON", hostsColTitles[col],
				WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX,
				scale(12), y, scale(240), scale(22),
				HWND(hwnd), HMENU(IDC_EDITCOLS_COL_BASE+int(col)), getModuleHandle())
			sendMessage(editColsChecks[col], WM_SETFONT, uintptr(appFont), 1)
			check := BST_UNCHECKED
			if colVisible[col] {
				check = BST_CHECKED
			}
			sendMessage(editColsChecks[col], BM_SETCHECK, uintptr(check), 0)
		}

		// Button row: Restore Defaults left, Cancel + OK right.
		cr := getClientRect(HWND(hwnd))
		btnY, xs := dlgBottomRight(cr.Right-cr.Left, cr.Bottom-cr.Top, 2)
		// OK (xs[0]) and Cancel (xs[1])
		okHwnd, _ := createWindowEx(0, "BUTTON", "OK",
			WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,
			xs[0], btnY, scale(100), scale(26),
			HWND(hwnd), HMENU(IDC_EDITCOLS_OK), getModuleHandle())
		sendMessage(okHwnd, WM_SETFONT, uintptr(appFont), 1)
		cancelHwnd, _ := createWindowEx(0, "BUTTON", "Cancel",
			WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
			xs[1], btnY, scale(100), scale(26),
			HWND(hwnd), HMENU(IDC_EDITCOLS_CANCEL), getModuleHandle())
		sendMessage(cancelHwnd, WM_SETFONT, uintptr(appFont), 1)
		// Restore Defaults — left side
		restoreHwnd, _ := createWindowEx(0, "BUTTON", "Restore Defaults",
			WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
			scale(10), btnY, scale(120), scale(26),
			HWND(hwnd), HMENU(IDC_EDITCOLS_RESTORE), getModuleHandle())
		sendMessage(restoreHwnd, WM_SETFONT, uintptr(appFont), 1)
		return 0

	case WM_COMMAND:
		id := int32(wParam & 0xFFFF)
		switch id {
		case IDC_EDITCOLS_OK:
			// Apply checkbox states to column visibility.
			for col := int32(1); col <= 9; col++ {
				if editColsChecks[col] != 0 {
					chk := sendMessage(editColsChecks[col], BM_GETCHECK, 0, 0)
					setColumnVisible(col, chk == BST_CHECKED)
				}
			}
			closeModal(HWND(hwnd))
		case IDC_EDITCOLS_CANCEL:
			closeModal(HWND(hwnd))
		case IDC_EDITCOLS_RESTORE:
			// Check all checkboxes (UI only; not applied until OK).
			for col := int32(1); col <= 9; col++ {
				if editColsChecks[col] != 0 {
					sendMessage(editColsChecks[col], BM_SETCHECK, BST_CHECKED, 0)
				}
			}
		}
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_CLOSE:
		closeModal(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
}

