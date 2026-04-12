//go:build windows

// Deprecated: package guiwin is the legacy Win32 GUI.
// New GUI development belongs in cmd/gui-gio (Gio-based, Windows + Linux).
// This package is kept for reference and regression comparison only.
// Do not add new features here.
package guiwin

import (
	"path/filepath"
	"runtime"
	"unsafe"

	"github.com/demicloud/net-scope/internal/config"
	"github.com/demicloud/net-scope/internal/netinfo"
	"github.com/demicloud/net-scope/internal/scan"
)

// version and initialTarget are set by Run() before any window is created.
var version string
var initialTarget string

// appConfig is loaded once at startup and used to populate UI defaults.
var appConfig config.Config

// appState is loaded once at startup from state.json (if a config file was found).
var appState config.State

// stateDirPath is the directory where state.json lives.
// Empty when no config file was found at startup — state is not persisted.
var stateDirPath string

// noConfigFile is true when no config file was found at startup.
var noConfigFile bool

// Run starts the GUI. v is the version string; target is the initial scan target.
// Must be called from the main goroutine (LockOSThread is called internally).
func Run(v, target string) {
	version = v

	// Win32 windows have thread affinity: the message loop must run on the
	// same OS thread that created the window.
	runtime.LockOSThread()

	defer func() {
		if p := recover(); p != nil {
			writeCrashLog(hwndMain, p)
		}
	}()

	// Hide the console window that Windows allocated when the binary was
	// launched by double-clicking (SUBSYSTEM:CONSOLE binaries always get one).
	if hwndConsole := getConsoleWindow(); hwndConsole != 0 {
		showWindow(hwndConsole, SW_HIDE)
	}

	scan.InitVendorDB(config.DataDir())

	// Enable Per-Monitor V2 DPI awareness before any window is created.
	// This ensures controls and fonts scale correctly on high-DPI monitors
	// and when the window is moved between monitors with different scaling.
	setProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)

	var cfgPath string
	var cfgErr error
	appConfig, cfgPath, cfgErr = config.Load()
	if cfgErr != nil {
		_ = cfgErr // non-fatal, defaults used
	}
	noConfigFile = (cfgPath == "")
	if cfgPath != "" {
		stateDirPath = filepath.Dir(cfgPath)
		appState = config.LoadState(stateDirPath)
	}

	// Proxy mode is session-only but defaults to active when a proxy address
	// is already saved in settings, so the user's intent is preserved on relaunch.
	proxyEnabled = appConfig.Scan.SOCKSProxy != ""

	if target != "" {
		initialTarget = target
	} else if appConfig.Scan.DefaultTarget != "" {
		initialTarget = appConfig.Scan.DefaultTarget
	} else if detected := netinfo.DetectLocalSubnets(); len(detected) > 0 {
		initialTarget = detected[0] // best guess; user can click ⟲ to see all
	} else {
		initialTarget = "192.168.1.0/24"
	}
	_ = cfgPath // used later in settings dialog

	initCommonControls()

	inst := getModuleHandle()
	className := utf16("NetScopeWnd")

	wc := WNDCLASSEX{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEX{})),
		Style:         CS_HREDRAW | CS_VREDRAW,
		LpfnWndProc:   wndProcCallback,
		HInstance:     inst,
		HIcon:         createAppIcon(32),
		HIconSm:       createAppIcon(16),
		HCursor:       loadCursor(IDC_ARROW),
		HbrBackground: HBRUSH(COLOR_WINDOW + 1),
		LpszClassName: className,
	}
	if _, err := registerClassEx(&wc); err != nil {
		messageBox(0, "RegisterClassEx failed: "+err.Error(), "NetScope", 0)
		return
	}

	// Determine initial window position/size from saved state.
	// Validate the saved position against current monitors so we never place
	// the window off-screen (e.g. after a monitor is disconnected).
	winX, winY := CW_USEDEFAULT, CW_USEDEFAULT
	winW, winH := int32(1160), int32(700)
	if ws := appState.Window; ws.Width > 0 {
		rc := RECT{
			Left:   int32(ws.X),
			Top:    int32(ws.Y),
			Right:  int32(ws.X + ws.Width),
			Bottom: int32(ws.Y + ws.Height),
		}
		if monitorFromRect(&rc, MONITOR_DEFAULTTONULL) != 0 {
			winX, winY = int32(ws.X), int32(ws.Y)
			winW, winH = int32(ws.Width), int32(ws.Height)
		}
	}

	hwnd, err := createWindowEx(
		0,
		"NetScopeWnd",
		"NetScope",
		WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
		winX, winY,
		winW, winH,
		0, 0, inst,
	)
	if err != nil {
			messageBox(0, "CreateWindowEx failed: "+err.Error(), "NetScope", 0)
		return
	}
	hwndMain = hwnd

	// Build menu bar: File | Options | Help
	hMenu := createMenu()

	hFile := createPopupMenu()
	appendMenu(hFile, MF_STRING, IDM_FILE_EXPORT_JSON, "Export &All Hosts as JSON…")
	appendMenu(hFile, MF_STRING, IDM_FILE_EXPORT_CSV, "Export A&ll Hosts as CSV…")
	appendMenu(hFile, MF_SEPARATOR, 0, "")
	appendMenu(hFile, MF_STRING, IDM_FILE_EXPORT_SCAN_JSON, "Export C&urrent Scan as JSON…")
	appendMenu(hFile, MF_STRING, IDM_FILE_EXPORT_SCAN_CSV, "Export Cu&rrent Scan as CSV…")
	appendMenu(hFile, MF_SEPARATOR, 0, "")
	appendMenu(hFile, MF_STRING, IDM_FILE_EXIT, "E&xit")
	appendMenu(hMenu, MF_POPUP, uintptr(hFile), "&File")

	hOptions := createPopupMenu()
	appendMenu(hOptions, MF_STRING, IDM_OPT_SETTINGS, "&Settings…")
	hDatabases := createPopupMenu()
	appendMenu(hDatabases, MF_STRING, IDM_OPT_DATABASES, "&Mac Vendors…")
	appendMenu(hOptions, MF_POPUP, uintptr(hDatabases), "&Databases")
	appendMenu(hMenu, MF_POPUP, uintptr(hOptions), "&Options")

	hHosts := createPopupMenu()
	appendMenu(hHosts, MF_STRING, IDM_HOSTS_VIEW_HOST, "&Hosts\u2026")
	appendMenu(hHosts, MF_STRING, IDM_SERVICES_VIEW_ALL, "&Services\u2026")
	appendMenu(hHosts, MF_SEPARATOR, 0, "")
	appendMenu(hHosts, MF_STRING, IDM_TOOLS_MAC_LOOKUP, "&MAC Vendor Lookup\u2026")
	appendMenu(hHosts, MF_SEPARATOR, 0, "")
	// Cache submenu (ephemeral OS caches: ARP + DNS)
	hCache := createPopupMenu()
	appendMenu(hCache, MF_STRING, IDM_TOOLS_ARP_CACHE, "&ARP Cache\u2026")
	appendMenu(hCache, MF_STRING, IDM_TOOLS_DNS_CACHE, "&DNS Cache\u2026")
	appendMenu(hHosts, MF_POPUP, uintptr(hCache), "Cache")
	appendMenu(hHosts, MF_SEPARATOR, 0, "")
	appendMenu(hHosts, MF_STRING, IDM_TOOLS_ROUTE_TABLE, "&Route Table\u2026")
	appendMenu(hHosts, MF_STRING, IDM_TOOLS_CONNECTIONS, "Active &Connections\u2026")
	appendMenu(hHosts, MF_STRING, IDM_TOOLS_HOSTS, "&Hosts File\u2026")
	appendMenu(hHosts, MF_STRING, IDM_TOOLS_INTERFACES, "Local &Interfaces\u2026")
	appendMenu(hHosts, MF_SEPARATOR, 0, "")
	appendMenu(hHosts, MF_STRING, IDM_TOOLS_PROBE, "&Probe\u2026")
	appendMenu(hHosts, MF_SEPARATOR, 0, "")
	appendMenu(hHosts, MF_STRING, IDM_TOOLS_WORKER_QUEUE, "&Background Workers\u2026")
	appendMenu(hMenu, MF_POPUP, uintptr(hHosts), "&Tools")

	hHelp := createPopupMenu()
	appendMenu(hHelp, MF_STRING, IDM_HELP_FAQ, "&Help / FAQ…")
	appendMenu(hHelp, MF_STRING, IDM_HELP_CONN_HANDLERS, "&Connection Handlers…")
	appendMenu(hHelp, MF_SEPARATOR, 0, "")
	appendMenu(hHelp, MF_STRING, IDM_HELP_VERSION, "&Version Info")
	appendMenu(hHelp, MF_STRING, IDM_HELP_ABOUT, "&About")
	appendMenu(hHelp, MF_SEPARATOR, 0, "")
	appendMenu(hHelp, MF_STRING, IDM_HELP_CRASHLOG, "View &Crash Log…")
	appendMenu(hMenu, MF_POPUP, uintptr(hHelp), "&Help")

	setMenu(hwnd, hMenu)

	if appState.Window.State == "maximized" {
		showWindow(hwnd, SW_SHOWMAXIMIZED)
	} else {
		showWindow(hwnd, SW_SHOWNORMAL)
	}
	updateWindow(hwnd)

	var msg MSG
	for getMessage(&msg) {
		// Ctrl+A → select all in the focused control.
		// If a listview is focused, select all rows; otherwise select all text
		// in the focused edit box.
		if msg.Message == WM_KEYDOWN &&
			msg.WParam == VK_KEY_A &&
			getKeyState(VK_CONTROL) < 0 {
			switch msg.HWnd {
			case hwndList, hwndListMDNS, hwndListSSDP, hwndListWSD, hwndListDHCP:
				listViewSelectAll(msg.HWnd)
			default:
				sendMessage(msg.HWnd, EM_SETSEL, 0, ^uintptr(0))
			}
			continue
		}
		// Enter in the target box → trigger Scan (or Stop if scanning).
		if msg.Message == WM_KEYDOWN && msg.WParam == VK_RETURN &&
			getFocus() == hwndTarget {
			postMessage(hwndMain, WM_COMMAND, IDC_SCAN, 0)
			continue
		}
		// Escape → stop an active scan.
		if msg.Message == WM_KEYDOWN && msg.WParam == VK_ESCAPE && isScanning {
			postMessage(hwndMain, WM_COMMAND, IDC_SCAN, 0)
			continue
		}
		translateMessage(&msg)
		dispatchMessage(&msg)
	}
}
