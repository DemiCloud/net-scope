//go:build windows

package guiwin

import (
	"bytes"
	"fmt"
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
	idSettProtoHandlers = 507
	idSettSOCKSProxy    = 508
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
	hwndSettSOCKS         HWND
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
		case idSettProtoHandlers:
			showProtocolHandlersDialog(HWND(hwnd))
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

	const dlgW, dlgH int32 = 560, 470
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
	setWindowText(hwndSettSOCKS, appConfig.Scan.SOCKSProxy)
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
		{"SOCKS5 Proxy:", &hwndSettSOCKS},
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

	// Protocol Handlers button + OK / Cancel — below path label + 8px gap
	btnY := checkY + 132
	createCtrl("BUTTON", "Protocol Handlers\u2026", WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		lx, btnY, 140, 26, hwnd, idSettProtoHandlers, inst)
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
	socksProxy := strings.TrimSpace(getWindowText(hwndSettSOCKS))
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

	if socksProxy != "" {
		if _, err := sweep.MakeDialFunc(socksProxy); err != nil {
			messageBox(hwnd, "SOCKS5 Proxy address is invalid:\n"+err.Error(), "Invalid Input", 0)
			return false
		}
	}

	cfg := config.Config{
		Scan: config.ScanConfig{
			Timeout:          timeout,
			Concurrency:      concur,
			Ports:            ports,
			PingFirst:        pingFirst,
			BroadcastListen:  bcast,
			SNMPCommunity:    snmp,
			Interface:        iface,
			BannerGrab:       bannerGrab,
			NetBIOS:          netBIOS,
			DefaultTarget:    defaultTarget,
			SOCKSProxy:       socksProxy,
			ProtocolHandlers: appConfig.Scan.ProtocolHandlers, // edited separately
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
// FAQ / Help — opens the GitHub Wiki in the default browser
// ---------------------------------------------------------------------------

func showFAQDialog(_ HWND) {
	shellExecute(0, "open", "https://github.com/demicloud/net-scope/wiki/FAQ", "", "", SW_SHOWNORMAL)
}

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

// editColsChecks holds the HWND of each checkbox (indexed by column number).
// Col 0 has no checkbox; it is always visible.  The array is large enough for
// the widest tab (10 columns for the Hosts tab).
var editColsChecks [10]HWND

// editColsDlgState holds the parameters for the currently-open Edit Columns
// dialog.  Set by showEditColumnsDialog before runModal; read by the WndProc.
var editColsDlgState struct {
	hwndLV    HWND
	colTitles []string
	colVis    []bool  // slice into the tab's actual visibility array; mutated in-place
	defWidths []int32 // 96-DPI logical widths
}

// showEditColumnsDialog opens the generic Edit Columns dialog for any tab.
// hwndLV is the listview to manage; colTitles, colVis, defWidths describe its
// columns.  colVis is mutated when the user presses OK.
func showEditColumnsDialog(parent, hwndLV HWND, colTitles []string, colVis []bool, defWidths []int32) {
	editColsDlgState.hwndLV = hwndLV
	editColsDlgState.colTitles = colTitles
	editColsDlgState.colVis = colVis
	editColsDlgState.defWidths = defWidths

	registerDialogClass("NetScopeEditCols", syscall.NewCallback(editColsWndProc))

	// Height: 12px top padding + one 26px row per checkbox (cols 1..n-1) +
	// 80px footer (title bar + button row + padding).
	n := int32(len(colTitles))
	const dlgW int32 = 360
	dlgH := 12 + (n-1)*26 + 80
	dlg, _ := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetScopeEditCols", "Edit Columns",
		WS_POPUP|WS_CAPTION|WS_SYSMENU,
		0, 0, scale(dlgW), scale(dlgH), parent, 0, getModuleHandle(),
	)
	centerWindowOver(dlg, parent)
	runModal(dlg, parent)
}

func editColsWndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		sendMessage(HWND(hwnd), WM_SETFONT, uintptr(appFont), 1)
		n := int32(len(editColsDlgState.colTitles))

		// One checkbox per column 1..n-1 (col 0 is always visible).
		for col := int32(1); col < n; col++ {
			y := scale(12) + (col-1)*scale(26)
			editColsChecks[col], _ = createWindowEx(0, "BUTTON", editColsDlgState.colTitles[col],
				WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX,
				scale(12), y, scale(240), scale(22),
				HWND(hwnd), HMENU(IDC_EDITCOLS_COL_BASE+int(col)), getModuleHandle())
			sendMessage(editColsChecks[col], WM_SETFONT, uintptr(appFont), 1)
			check := BST_UNCHECKED
			if editColsDlgState.colVis[col] {
				check = BST_CHECKED
			}
			sendMessage(editColsChecks[col], BM_SETCHECK, uintptr(check), 0)
		}
		// Clear any stale handles from a previous invocation with more columns.
		for i := int(n); i < len(editColsChecks); i++ {
			editColsChecks[i] = 0
		}

		// Button row: Restore Defaults left, Cancel + OK right.
		cr := getClientRect(HWND(hwnd))
		btnY, leftXs, rightXs := dlgButtonRowSplit(cr.Right-cr.Left, cr.Bottom-cr.Top, 1, 2)
		okHwnd, _ := createWindowEx(0, "BUTTON", "OK",
			WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,
			rightXs[0], btnY, 100, 26,
			HWND(hwnd), HMENU(IDC_EDITCOLS_OK), getModuleHandle())
		sendMessage(okHwnd, WM_SETFONT, uintptr(appFont), 1)
		cancelHwnd, _ := createWindowEx(0, "BUTTON", "Cancel",
			WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
			rightXs[1], btnY, 100, 26,
			HWND(hwnd), HMENU(IDC_EDITCOLS_CANCEL), getModuleHandle())
		sendMessage(cancelHwnd, WM_SETFONT, uintptr(appFont), 1)
		restoreHwnd, _ := createWindowEx(0, "BUTTON", "Restore Defaults",
			WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
			leftXs[0], btnY, 100, 26,
			HWND(hwnd), HMENU(IDC_EDITCOLS_RESTORE), getModuleHandle())
		sendMessage(restoreHwnd, WM_SETFONT, uintptr(appFont), 1)
		return 0

	case WM_COMMAND:
		id := int32(wParam & 0xFFFF)
		n := int32(len(editColsDlgState.colTitles))
		switch id {
		case IDC_EDITCOLS_OK:
			for col := int32(1); col < n; col++ {
				if editColsChecks[col] != 0 {
					chk := sendMessage(editColsChecks[col], BM_GETCHECK, 0, 0)
					setLVColumnVisible(
						editColsDlgState.hwndLV,
						editColsDlgState.defWidths,
						editColsDlgState.colVis,
						col, chk == BST_CHECKED,
					)
				}
			}
			closeModal(HWND(hwnd))
		case IDC_EDITCOLS_CANCEL:
			closeModal(HWND(hwnd))
		case IDC_EDITCOLS_RESTORE:
			// Tick all checkboxes in the UI; actual reset happens on OK.
			for col := int32(1); col < n; col++ {
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

// ---------------------------------------------------------------------------
// Protocol Handlers Dialog
// ---------------------------------------------------------------------------

// protoHandlerRow defines one row in the protocol handler table.
type protoHandlerRow struct {
	key      string // config key: "http", "https", etc.
	label    string // display label
	port     int    // associated port (informational)
	hwndEdit HWND   // custom-command edit field
}

// protoHandlerRows is populated in createProtoHandlerControls and read in
// applyProtoHandlers.
var protoHandlerRows = []protoHandlerRow{
	{key: "http", label: "HTTP", port: 80},
	{key: "https", label: "HTTPS", port: 443},
	{key: "ssh", label: "SSH", port: 22},
	{key: "rdp", label: "RDP", port: 3389},
	{key: "ftp", label: "FTP", port: 21},
	{key: "telnet", label: "Telnet", port: 23},
	{key: "smb", label: "SMB / File Share", port: 445},
}

const (
	idProtoOK     = 801
	idProtoCancel = 802
)

var protoHandlersWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createProtoHandlerControls(HWND(hwnd))
		return 0
	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)
	case WM_COMMAND:
		switch loword(wParam) {
		case idProtoOK:
			applyProtoHandlers()
			closeModal(HWND(hwnd))
		case idProtoCancel:
			closeModal(HWND(hwnd))
		}
		return 0
	case WM_CLOSE:
		closeModal(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

// exeNameFromCommand extracts the executable filename from a shell command
// string (which may be quoted). Returns "" for empty input.
func exeNameFromCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	if cmd[0] == '"' {
		end := strings.IndexByte(cmd[1:], '"')
		if end >= 0 {
			cmd = cmd[1 : end+1]
		} else {
			cmd = cmd[1:]
		}
	} else {
		if idx := strings.IndexByte(cmd, ' '); idx > 0 {
			cmd = cmd[:idx]
		}
	}
	if idx := strings.LastIndexAny(cmd, `/\`); idx >= 0 {
		cmd = cmd[idx+1:]
	}
	return cmd
}

// effectiveHandlerLabel returns the exe name that will actually be launched
// for the given protocol key. Custom config overrides are shown first; for
// URL schemes the lookup follows the Windows UserChoice path (HKCU) so the
// result matches ShellExecute rather than the system-level fallback.
func effectiveHandlerLabel(key string) string {
	if custom := appConfig.Scan.ProtocolHandlers[key]; custom != "" {
		name := exeNameFromCommand(strings.SplitN(custom, " ", 2)[0])
		if name == "" {
			name = custom
		}
		return name + " (custom)"
	}
	switch key {
	case "rdp":
		return "mstsc.exe"
	case "smb":
		return "explorer.exe"
	}
	raw := regReadOpenCommand(key)
	if raw == "" {
		return "(not registered)"
	}
	name := exeNameFromCommand(raw)
	if name == "" {
		return "(registered)"
	}
	return name
}

// osDefaultLabel is an alias used by the Settings > Protocol Handlers dialog
// to show what the OS default is regardless of any custom config override.
func osDefaultLabel(key string) string {
	switch key {
	case "rdp":
		return "mstsc.exe"
	case "smb":
		return "explorer.exe"
	}
	raw := regReadOpenCommand(key)
	if raw == "" {
		return "(not registered)"
	}
	name := exeNameFromCommand(raw)
	if name == "" {
		return "(registered)"
	}
	return name
}

func createProtoHandlerControls(hwnd HWND) {
	inst := getModuleHandle()
	r := getClientRect(hwnd)
	cW := r.Right
	const (
		pad     int32 = 12
		rowH    int32 = 30
		keyW    int32 = 130 // "HTTP (80):" column
		statusW int32 = 190 // OS default app column
		y0      int32 = 36  // first row starts below header
	)
	editX := pad + keyW + statusW + 8
	editW := cW - editX - pad

	// Header labels.
	createCtrl("STATIC", "Protocol", WS_CHILD|WS_VISIBLE,
		pad, 10, keyW, 16, hwnd, 0, inst)
	createCtrl("STATIC", "OS Default (actual)", WS_CHILD|WS_VISIBLE,
		pad+keyW, 10, statusW, 16, hwnd, 0, inst)
	createCtrl("STATIC", "Custom Command (%s = IP)", WS_CHILD|WS_VISIBLE,
		editX, 10, editW, 16, hwnd, 0, inst)

	for i := range protoHandlerRows {
		row := &protoHandlerRows[i]
		y := y0 + int32(i)*rowH
		lbl := fmt.Sprintf("%s (port %d):", row.label, row.port)
		createCtrl("STATIC", lbl, WS_CHILD|WS_VISIBLE,
			pad, y+5, keyW, 18, hwnd, 0, inst)
		createCtrl("STATIC", osDefaultLabel(row.key), WS_CHILD|WS_VISIBLE,
			pad+keyW+4, y+5, statusW-4, 18, hwnd, 0, inst)
		row.hwndEdit, _ = createWindowEx(WS_EX_CLIENTEDGE, "EDIT",
			appConfig.Scan.ProtocolHandlers[row.key],
			WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL,
			editX, y+2, editW, 22, hwnd, 0, inst)
	}

	// Hint line.
	hintY := y0 + int32(len(protoHandlerRows))*rowH + 4
	createCtrl("STATIC",
		"Leave blank to use the OS default. Example: putty.exe -ssh %s",
		WS_CHILD|WS_VISIBLE,
		pad, hintY, cW-pad*2, 16, hwnd, 0, inst)

	// Buttons.
	btnY := hintY + 26
	createCtrl("BUTTON", "OK", WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		cW-pad-174, btnY, 78, 26, hwnd, idProtoOK, inst)
	createCtrl("BUTTON", "Cancel", WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		cW-pad-86, btnY, 78, 26, hwnd, idProtoCancel, inst)
}

// applyProtoHandlers reads the edit fields and stores non-empty values into
// appConfig. Empty fields remove any existing override for that protocol.
func applyProtoHandlers() {
	handlers := appConfig.Scan.ProtocolHandlers
	if handlers == nil {
		handlers = make(map[string]string)
	}
	for _, row := range protoHandlerRows {
		val := strings.TrimSpace(getWindowText(row.hwndEdit))
		if val == "" {
			delete(handlers, row.key)
		} else {
			handlers[row.key] = val
		}
	}
	if len(handlers) == 0 {
		handlers = nil
	}
	appConfig.Scan.ProtocolHandlers = handlers

	// Persist immediately.
	_, cfgPath, _ := config.Load()
	if cfgPath == "" {
		return // no config file yet; changes held in memory until Settings OK
	}
	_ = config.SaveTo(appConfig, cfgPath)
}

func showProtocolHandlersDialog(parent HWND) {
	registerDialogClass("NetSweepProtoHandlers", protoHandlersWndProc)

	n := int32(len(protoHandlerRows))
	const (
		pad  int32 = 12
		rowH int32 = 30
		y0   int32 = 36
	)
	const (
		dlgStyle   uint32 = WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN
		dlgExStyle uint32 = WS_EX_DLGMODALFRAME
	)
	clientW := int32(640)
	clientH := y0 + n*rowH + 4 + 26 + 26 + pad
	outer := adjustWindowRectEx(RECT{0, 0, clientW, clientH}, dlgStyle, dlgExStyle, false)
	dlgW := outer.Right - outer.Left
	dlgH := outer.Bottom - outer.Top

	dlg, err := createWindowEx(
		dlgExStyle,
		"NetSweepProtoHandlers", "Protocol Handlers",
		dlgStyle,
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
// Connection Handlers info dialog  (Help > Connection Handlers…)
// ---------------------------------------------------------------------------
//
// Read-only table: Protocol | Port | Will launch.
// "Will launch" = custom command from config if set, else the actual OS
// default resolved via UserChoice (HKCU), not the system-level fallback.

const (
	idConnHandlersConfigure = 811
	idConnHandlersClose     = 812
)

var connHandlersWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createConnHandlersControls(HWND(hwnd))
		return 0
	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)
	case WM_COMMAND:
		switch loword(wParam) {
		case idConnHandlersConfigure:
			closeModal(HWND(hwnd))
			showSettingsDialog(hwndMain)
		case idConnHandlersClose:
			closeModal(HWND(hwnd))
		}
		return 0
	case WM_CLOSE:
		closeModal(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

func createConnHandlersControls(hwnd HWND) {
	inst := getModuleHandle()
	r := getClientRect(hwnd)
	cW := r.Right
	const (
		pad    int32 = 12
		rowH   int32 = 22
		protoW int32 = 120
		portW  int32 = 60
		y0     int32 = 32
	)
	launchW := cW - protoW - portW - pad*3

	// Column headers.
	createCtrl("STATIC", "Protocol", WS_CHILD|WS_VISIBLE, pad, 10, protoW, 16, hwnd, 0, inst)
	createCtrl("STATIC", "Port", WS_CHILD|WS_VISIBLE, pad+protoW, 10, portW, 16, hwnd, 0, inst)
	createCtrl("STATIC", "Will launch", WS_CHILD|WS_VISIBLE, pad+protoW+portW, 10, launchW, 16, hwnd, 0, inst)

	for i, row := range protoHandlerRows {
		y := y0 + int32(i)*rowH
		createCtrl("STATIC", row.label, WS_CHILD|WS_VISIBLE, pad, y, protoW, 16, hwnd, 0, inst)
		createCtrl("STATIC", fmt.Sprintf("%d", row.port), WS_CHILD|WS_VISIBLE, pad+protoW, y, portW, 16, hwnd, 0, inst)
		createCtrl("STATIC", effectiveHandlerLabel(row.key), WS_CHILD|WS_VISIBLE, pad+protoW+portW, y, launchW, 16, hwnd, 0, inst)
	}

	hintY := y0 + int32(len(protoHandlerRows))*rowH + 8
	createCtrl("STATIC", "Custom overrides are set in Options \u2192 Settings \u2192 Protocol Handlers\u2026",
		WS_CHILD|WS_VISIBLE, pad, hintY, cW-pad*2, 16, hwnd, 0, inst)

	btnY := hintY + 28
	createCtrl("BUTTON", "Configure\u2026", WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		pad, btnY, 110, 26, hwnd, idConnHandlersConfigure, inst)
	createCtrl("BUTTON", "Close", WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		cW-pad-86, btnY, 78, 26, hwnd, idConnHandlersClose, inst)
}

func showConnHandlersDialog(parent HWND) {
	registerDialogClass("NetSweepConnHandlers", connHandlersWndProc)

	n := int32(len(protoHandlerRows))
	const (
		pad  int32 = 12
		rowH int32 = 22
		y0   int32 = 32
	)
	dlgW := int32(500)
	dlgH := y0 + n*rowH + 8 + 16 + 28 + pad*2

	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetSweepConnHandlers", "Connection Handlers",
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

