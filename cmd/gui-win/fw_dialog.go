//go:build windows

// Win32 framework — modal dialog helpers.
//
// This file is part of the Win32 framework layer (see fw_win32.go).
// It provides three reusable building blocks consumed by every dialog in the
// application:
//
//   - runModal / closeModal   — simulate a Win32 modal loop for dynamically
//     created (non-resource-template) windows.
//
//   - registerDialogClass     — register a standard dialog window class in one
//     call, eliminating the six sync.Once boilerplate blocks that previously
//     existed across dialog.go and dialog_host.go.
//
//   - ctlColorDialog          — canonical WM_CTLCOLORSTATIC handler body for
//     dialog panels (transparent label text on COLOR_BTNFACE background).

package guiwin

import "unsafe"

// ---------------------------------------------------------------------------
// Modal loop
//
// Win32 has no built-in modal mechanism for dynamically-created windows (only
// for resource-template DialogBox).  We simulate it:
//   1. Disable the parent so it cannot be interacted with.
//   2. Run a nested message loop until closeModal sets modalActive = false.
//   3. closeModal destroys the dialog and posts WM_NULL to the parent so
//      getMessage returns and the loop condition is re-evaluated.
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

	// closeModal already re-enabled the parent and restored focus;
	// clear state here in case the loop exited another way.
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
// Window class registration
// ---------------------------------------------------------------------------

// registerDialogClass registers a standard popup dialog window class.
//
// Background is COLOR_BTNFACE (the system dialog gray), cursor is IDC_ARROW.
// Safe to call multiple times for the same name — Win32 returns
// ERROR_CLASS_ALREADY_EXISTS on subsequent calls, which is silently ignored.
//
// This replaces the six identical sync.Once / ensureXxxClass patterns that
// previously existed across dialog.go and dialog_host.go.
func registerDialogClass(name string, wndProc uintptr) {
	cn := utf16(name)
	wc := WNDCLASSEX{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEX{})),
		LpfnWndProc:   wndProc,
		HInstance:     getModuleHandle(),
		HbrBackground: HBRUSH(COLOR_BTNFACE + 1),
		HCursor:       loadCursor(IDC_ARROW),
		LpszClassName: cn,
	}
	registerClassEx(&wc) // error (class already exists) is intentionally ignored
}

// ---------------------------------------------------------------------------
// WM_CTLCOLORSTATIC handler
// ---------------------------------------------------------------------------

// ctlColorDialog handles WM_CTLCOLORSTATIC for standard dialog panels.
// Returns the COLOR_BTNFACE system brush with transparent text background so
// STATIC labels blend into the dialog background.
//
// Usage inside a WndProc switch:
//
//	case WM_CTLCOLORSTATIC:
//	    return ctlColorDialog(wParam)
func ctlColorDialog(hdc uintptr) uintptr {
	setBkMode(hdc, TRANSPARENT)
	setTextColor(hdc, 0x00000000)
	return uintptr(getSysColorBrush(COLOR_BTNFACE))
}
