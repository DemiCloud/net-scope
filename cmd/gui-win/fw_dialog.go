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

// runModal supports nesting: a dialog opened from inside a modal WndProc
// (e.g. a Probes sub-dialog from a Host Detail dialog) works correctly because
// the outer loop only checks modalActive BEFORE and AFTER dispatchMessage —
// never concurrently. Save/restore preserves the outer state.
func runModal(dlg, parent HWND) {
	prevActive := modalActive
	prevParent := modalParent
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
	// Restore outer modal state so the enclosing loop can continue.
	modalActive = prevActive
	modalParent = prevParent
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
// Dialog creation
// ---------------------------------------------------------------------------

// createAndCenterDialog registers className, creates a standard modal-style
// popup window of dimensions (w×h), and centers it over parent.
// Returns the HWND on success, 0 on failure. The caller is responsible for
// any per-dialog control creation, applying fonts, and calling runModal.
//
// The window is created with the standard application dialog style:
//   - exStyle: WS_EX_DLGMODALFRAME
//   - style:   WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN
//
// Note: w and h are outer (window) dimensions. To derive them from a desired
// client area, use adjustWindowRectEx first, or call createDialogForClient.
func createAndCenterDialog(className, title string, w, h int32, wndProc uintptr, parent HWND) HWND {
	registerDialogClass(className, wndProc)
	dlg, err := createWindowEx(
		WS_EX_DLGMODALFRAME,
		className, title,
		WS_POPUP|WS_CAPTION|WS_SYSMENU|WS_CLIPCHILDREN,
		0, 0, w, h,
		parent, 0, getModuleHandle(),
	)
	if err != nil || dlg == 0 {
		return 0
	}
	centerWindowOver(dlg, parent)
	return dlg
}

// createDialogForClient is the preferred dialog creation function.
// It takes the desired CLIENT area dimensions (cW × cH) and automatically
// calls adjustWindowRectEx to compute the correct outer frame size, so
// controls placed anywhere within (0,0)→(cW,cH) are never clipped by the
// caption bar or dialog border regardless of DPI scale or Windows version.
//
// Use this in preference to createAndCenterDialog whenever the dialog has
// a fixed or content-derived client size. Dialogs that derive all control
// positions from getClientRect(hwnd) at WM_CREATE also benefit: the window
// is guaranteed to be the right outer size for exactly the client area the
// layout code expects.
func createDialogForClient(className, title string, cW, cH int32, wndProc uintptr, parent HWND) HWND {
	const (
		dlgStyle   uint32 = WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN
		dlgExStyle uint32 = WS_EX_DLGMODALFRAME
	)
	outer := adjustWindowRectEx(RECT{0, 0, cW, cH}, dlgStyle, dlgExStyle, false)
	return createAndCenterDialog(className, title, outer.Right-outer.Left, outer.Bottom-outer.Top, wndProc, parent)
}

// ---------------------------------------------------------------------------
// WM_CTLCOLORSTATIC handler
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Button layout helper
// ---------------------------------------------------------------------------

// dlgBottomRight calculates positions for n equal-width buttons in a
// right-aligned row at the bottom of a dialog client area.
//
// Standard metrics used throughout the app:
//   - button width  : 100 px
//   - button height : 26 px
//   - gap between   : 8 px
//   - right / bottom padding: 10 px
//
// Returns the shared y position and slice of x positions (left-to-right,
// so xs[0] is the leftmost / "OK" button and xs[n-1] is "Cancel").
//
// Usage:
//
//	y, xs := dlgBottomRight(cW, cH, 2)
//	createWindowEx(..., xs[0], y, 100, 26, ..., HMENU(idOK), ...)
//	createWindowEx(..., xs[1], y, 100, 26, ..., HMENU(idCancel), ...)
func dlgBottomRight(cW, cH int32, n int) (y int32, xs []int32) {
	const (
		btnW int32 = 100
		btnH int32 = 26
		gap  int32 = 8
		pad  int32 = 10
	)
	y = cH - pad - btnH
	xs = make([]int32, n)
	for i := 0; i < n; i++ {
		xs[i] = cW - pad - btnW - int32(n-1-i)*(btnW+gap)
	}
	return
}

// ---------------------------------------------------------------------------
// Read-only body text helpers
// ---------------------------------------------------------------------------

// createDlgSeparator creates a thin horizontal etched rule (SS_ETCHEDHORZ).
// Use it to visually divide a title area from body content.
//
//	createDlgSeparator(hwnd, inst, pad, titleY+titleH+gap, cW-pad*2)
func createDlgSeparator(parent HWND, inst HINSTANCE, x, y, w int32) {
	createWindowEx(0, "STATIC", "",
		WS_CHILD|WS_VISIBLE|SS_ETCHEDHORZ,
		x, y, w, 2, parent, 0, inst)
}

// createDlgBodyEdit creates a borderless, read-only, multiline EDIT control
// for displaying info text. No WS_EX_CLIENTEDGE — pair with ctlColorDlgBody
// in WM_CTLCOLOREDIT to render it with a clean white background.
//
//	hwndBody = createDlgBodyEdit(hwnd, inst, text, pad, bodyY, cW-pad*2, bodyH)
func createDlgBodyEdit(parent HWND, inst HINSTANCE, text string, x, y, w, h int32) HWND {
	hw, _ := createWindowEx(0, "EDIT", text,
		WS_CHILD|WS_VISIBLE|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
		x, y, w, h, parent, 0, inst)
	return hw
}

// ctlColorDlgBody handles WM_CTLCOLOREDIT for borderless read-only body-text
// EDIT controls: white background, black text, opaque mode.
//
// Usage inside a WndProc switch:
//
//	case WM_CTLCOLOREDIT:
//	    return ctlColorDlgBody(wParam)
func ctlColorDlgBody(hdc uintptr) uintptr {
	setBkMode(hdc, OPAQUE)
	setTextColor(hdc, 0x00000000)
	setBkColor(hdc, 0x00FFFFFF)
	return uintptr(getSysColorBrush(COLOR_WINDOW))
}

// ---------------------------------------------------------------------------
// Button factories
// ---------------------------------------------------------------------------

// makePushButton creates a WS_TABSTOP|BS_PUSHBUTTON child button, applies
// appFont, and returns the HWND. Callers do not need a separate WM_SETFONT
// call.
func makePushButton(parent HWND, text string, id HMENU, x, y, w, h int32) HWND {
	hw, _ := createWindowEx(0, "BUTTON", text,
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON,
		x, y, w, h, parent, id, getModuleHandle())
	sendMessage(hw, WM_SETFONT, uintptr(appFont), 1)
	return hw
}

// makeDefPushButton creates a WS_TABSTOP|BS_DEFPUSHBUTTON child button.
// The default button is activated by the Enter key inside the dialog.
// appFont is applied immediately.
func makeDefPushButton(parent HWND, text string, id HMENU, x, y, w, h int32) HWND {
	hw, _ := createWindowEx(0, "BUTTON", text,
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON,
		x, y, w, h, parent, id, getModuleHandle())
	sendMessage(hw, WM_SETFONT, uintptr(appFont), 1)
	return hw
}

// makeCheckBox creates a WS_TABSTOP|BS_AUTOCHECKBOX child button and applies
// appFont. Use BM_SETCHECK / BM_GETCHECK to read and write the toggle state.
func makeCheckBox(parent HWND, text string, id HMENU, x, y, w, h int32) HWND {
	hw, _ := createWindowEx(0, "BUTTON", text,
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX,
		x, y, w, h, parent, id, getModuleHandle())
	sendMessage(hw, WM_SETFONT, uintptr(appFont), 1)
	return hw
}

// ---------------------------------------------------------------------------
// Button layout helpers
// ---------------------------------------------------------------------------

// dlgButtonRowClientWidth returns the minimum client-area width needed so that
// a dlgButtonRowSplit layout with the given left button widths and rightN
// standard (100 px) right buttons can render without the two groups
// overlapping.  The formula accounts for left/right padding and the gap that
// separates the groups.
//
// Usage — determine window width before calling createWindowEx, or call
// dlgEnsureClientWidth inside WM_CREATE:
//
//	minCW := dlgButtonRowClientWidth([]int32{130}, 2)   // "Restore Defaults" + OK + Cancel
func dlgButtonRowClientWidth(leftWidths []int32, rightN int) int32 {
	const (
		btnW int32 = 100
		gap  int32 = 8
		pad  int32 = 10
	)
	cW := pad * 2
	for _, w := range leftWidths {
		cW += w + gap // gap doubles as the gutter between the two groups
	}
	cW += int32(rightN)*btnW + int32(rightN-1)*gap
	return cW
}

// dlgEnsureClientWidth widens the dialog window so its client area is at
// least minClientW pixels wide.  Call this at the very top of WM_CREATE,
// before creating any layout-dependent child controls, passing the value
// returned by dlgButtonRowClientWidth.  The window position and height are
// left unchanged; centerWindowOver can then be called after createWindowEx as
// usual because the resize happens while the window is still hidden.
func dlgEnsureClientWidth(hwnd HWND, minClientW int32) {
	cr := getClientRect(hwnd)
	clientW := cr.Right - cr.Left
	if clientW >= minClientW {
		return
	}
	wr := getWindowRect(hwnd)
	newW := (wr.Right - wr.Left) + (minClientW - clientW)
	setWindowPos(hwnd, 0, 0, 0, newW, wr.Bottom-wr.Top, SWP_NOMOVE|SWP_NOZORDER)
}

// dlgButtonRowSplit calculates footer button positions for dialogs that have
// buttons on both sides: left buttons flush-left (e.g. "Restore Defaults")
// and rightN equal-width (100 px) buttons flush-right (e.g. OK + Cancel).
//
// leftWidths contains the actual pixel width of each left button.  Passing
// the real widths lets the layout engine keep the two groups from colliding
// even when a label is wider than the 100 px standard.  Pair with
// dlgButtonRowClientWidth + dlgEnsureClientWidth so the dialog is always wide
// enough before children are created.
//
// Returns the shared y position, leftXs (index 0 = leftmost), rightXs (index
// 0 = leftmost of the right group, which is the primary action button).
func dlgButtonRowSplit(cW, cH int32, leftWidths []int32, rightN int) (y int32, leftXs, rightXs []int32) {
	const (
		btnW int32 = 100
		btnH int32 = 26
		gap  int32 = 8
		pad  int32 = 10
	)
	y = cH - pad - btnH
	leftXs = make([]int32, len(leftWidths))
	x := pad
	for i, w := range leftWidths {
		leftXs[i] = x
		x += w + gap
	}
	rightXs = make([]int32, rightN)
	for i := 0; i < rightN; i++ {
		rightXs[i] = cW - pad - btnW - int32(rightN-1-i)*(btnW+gap)
	}
	return
}

// ---------------------------------------------------------------------------
// Dropdown-button popup helper
// ---------------------------------------------------------------------------

// popupMenuFromButton displays a popup menu anchored to the bottom-left of
// anchor and handles the toggle-close race condition: when the user clicks the
// anchor button while the menu is already visible, TrackPopupMenu dismisses
// the menu but then the button fires WM_COMMAND again which would immediately
// reopen it.  The fix: after TrackPopupMenu returns with cmd==0, check
// GetAsyncKeyState(VK_LBUTTON).  If LButton is still physically held the
// dismiss was caused by clicking the button — record the anchor HWND and let
// shouldSuppressDropdown() absorb the spurious WM_COMMAND.
//
// Usage in WM_COMMAND:
//
//	case idMyButton:
//	    if shouldSuppressDropdown(HWND(lParam)) { return 0 }
//	    menu := createPopupMenu()
//	    // … populate menu …
//	    cmd := popupMenuFromButton(hwnd, menu, HWND(lParam))
//	    destroyMenu(menu)
//	    // … handle cmd …
func popupMenuFromButton(parent HWND, menu HMENU, anchor HWND) int32 {
	br := getWindowRect(anchor)
	cmd := trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD,
		br.Left, br.Bottom, parent)
	// When the menu is dismissed by a click on the anchor button, LButton is
	// still physically held at this point (LBUTTONUP has not been processed yet).
	// Mark anchor as suppressed so the pending BN_CLICKED is absorbed.
	if cmd == 0 && getAsyncKeyState(VK_LBUTTON) < 0 {
		dropdownSuppressHWND = anchor
	}
	return cmd
}

// dropdownSuppressHWND is set by popupMenuFromButton when a spurious
// WM_COMMAND is expected.  Cleared by shouldSuppressDropdown.
var dropdownSuppressHWND HWND

// shouldSuppressDropdown returns true (and clears the flag) when the
// WM_COMMAND for the given button HWND is a spurious re-open caused by the
// dismiss click.  Pass lParam from WM_COMMAND as the HWND.
func shouldSuppressDropdown(btn HWND) bool {
	if dropdownSuppressHWND != 0 && dropdownSuppressHWND == btn {
		dropdownSuppressHWND = 0
		return true
	}
	return false
}
