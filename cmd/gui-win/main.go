//go:build windows

package main

import (
	"os"
	"runtime"
	"unsafe"

	"github.com/demicloud/net-sweep/internal/config"
	"github.com/demicloud/net-sweep/internal/sweep"
)

func init() {
	// Win32 windows have thread affinity: the message loop must run on the
	// same OS thread that created the window. Without this, the Go scheduler
	// can silently move the goroutine to a different thread between CreateWindowEx
	// and GetMessage, leaving the window permanently unresponsive.
	runtime.LockOSThread()
}

// appConfig is loaded once at startup and used to populate UI defaults.
var appConfig config.Config

// initialTarget is the default text for the Target input box.
// Overridden by os.Args[1] when relaunching elevated.
var initialTarget = "192.168.1.0/24"

func main() {
	if len(os.Args) > 1 {
		initialTarget = os.Args[1]
	}

	sweep.InitVendorDB()

	var err error
	appConfig, _, err = config.Load()
	if err != nil {
		// Non-fatal — defaults will be used.
		_ = err
	}

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
	appendMenu(hFile, MF_STRING, IDM_FILE_EXIT, "E&xit")
	appendMenu(hMenu, MF_POPUP, uintptr(hFile), "&File")

	hOptions := createPopupMenu()
	appendMenu(hOptions, MF_STRING, IDM_OPT_SETTINGS, "&Settings…")
	appendMenu(hMenu, MF_POPUP, uintptr(hOptions), "&Options")

	hHelp := createPopupMenu()
	appendMenu(hHelp, MF_STRING, IDM_HELP_FAQ, "&FAQ")
	appendMenu(hHelp, MF_SEPARATOR, 0, "")
	appendMenu(hHelp, MF_STRING, IDM_HELP_ABOUT, "&About")
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
		translateMessage(&msg)
		dispatchMessage(&msg)
	}
}
