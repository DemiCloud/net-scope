//go:build windows

package guiwin

import (
	"runtime"
	"unsafe"

	"github.com/demicloud/net-sweep/internal/config"
	"github.com/demicloud/net-sweep/internal/sweep"
)

// version and initialTarget are set by Run() before any window is created.
var version string
var initialTarget string

// appConfig is loaded once at startup and used to populate UI defaults.
var appConfig config.Config

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

	sweep.InitVendorDB(config.DataDir())

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

	if target != "" {
		initialTarget = target
	} else if appConfig.Scan.DefaultTarget != "" {
		initialTarget = appConfig.Scan.DefaultTarget
	} else if detected := sweep.DetectLocalSubnets(); len(detected) > 0 {
		initialTarget = detected[0] // best guess; user can click ⟲ to see all
	} else {
		initialTarget = "192.168.1.0/24"
	}
	_ = cfgPath // used later in settings dialog

	initCommonControls()

	inst := getModuleHandle()
	className := utf16("NetSweepWnd")

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
		messageBox(0, "RegisterClassEx failed: "+err.Error(), "net-sweep", 0)
		return
	}

	hwnd, err := createWindowEx(
		0,
		"NetSweepWnd",
		"net-sweep",
		WS_OVERLAPPEDWINDOW,
		int32(CW_USEDEFAULT), int32(CW_USEDEFAULT),
		1160, 700,
		0, 0, inst,
	)
	if err != nil {
		messageBox(0, "CreateWindowEx failed: "+err.Error(), "net-sweep", 0)
		return
	}
	hwndMain = hwnd

	// Build menu bar: File | Options | Help
	hMenu := createMenu()

	hFile := createPopupMenu()
	appendMenu(hFile, MF_STRING, IDM_FILE_EXPORT_JSON, "Export as &JSON…")
	appendMenu(hFile, MF_STRING, IDM_FILE_EXPORT_CSV, "Export as &CSV…")
	appendMenu(hFile, MF_SEPARATOR, 0, "")
	appendMenu(hFile, MF_STRING, IDM_FILE_EXIT, "E&xit")
	appendMenu(hMenu, MF_POPUP, uintptr(hFile), "&File")

	hOptions := createPopupMenu()
	appendMenu(hOptions, MF_STRING, IDM_OPT_SETTINGS, "&Settings…")
	appendMenu(hOptions, MF_STRING, IDM_OPT_DATABASES, "&Databases…")
	appendMenu(hMenu, MF_POPUP, uintptr(hOptions), "&Options")

	hHosts := createPopupMenu()
	appendMenu(hHosts, MF_STRING, IDM_HOSTS_VIEW_ALL, "View &All Hosts…")
	appendMenu(hHosts, MF_STRING, IDM_HOSTS_VIEW_HOST, "View &Host…")
	appendMenu(hMenu, MF_POPUP, uintptr(hHosts), "H&osts")

	hHelp := createPopupMenu()
	appendMenu(hHelp, MF_STRING, IDM_HELP_FAQ, "&Help / FAQ…")
	appendMenu(hHelp, MF_SEPARATOR, 0, "")
	appendMenu(hHelp, MF_STRING, IDM_HELP_VERSION, "&Version Info")
	appendMenu(hHelp, MF_STRING, IDM_HELP_ABOUT, "&About")
	appendMenu(hHelp, MF_SEPARATOR, 0, "")
	appendMenu(hHelp, MF_STRING, IDM_HELP_CRASHLOG, "View &Crash Log…")
	appendMenu(hMenu, MF_POPUP, uintptr(hHelp), "&Help")

	setMenu(hwnd, hMenu)

	showWindow(hwnd, SW_SHOWNORMAL)
	updateWindow(hwnd)

	var msg MSG
	for getMessage(&msg) {
		// Ctrl+A → select all in whichever edit box is focused.
		if msg.Message == WM_KEYDOWN &&
			msg.WParam == VK_KEY_A &&
			getKeyState(VK_CONTROL) {
			sendMessage(msg.HWnd, EM_SETSEL, 0, ^uintptr(0))
			// Don't dispatch — we've handled it.
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
