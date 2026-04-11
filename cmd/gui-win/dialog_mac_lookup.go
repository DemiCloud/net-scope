//go:build windows

package guiwin

import (
	"net"
	"strings"
	"syscall"

	"github.com/demicloud/net-scope/internal/scan"
)

// ---------------------------------------------------------------------------
// MAC Vendor Lookup Dialog  (Tools > MAC Vendor Lookup…)
// ---------------------------------------------------------------------------

const (
	idMACEdit   = 1301
	idMACLookup = 1302
	idMACResult = 1303
)

var (
	hwndMACEdit      HWND
	hwndMACResult    HWND
	macEditOrigProc  uintptr
)

// macEditSubclassCb intercepts VK_ESCAPE so pressing Escape closes the dialog.
var macEditSubclassCb = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	if uint32(msg) == WM_KEYDOWN && wParam == VK_ESCAPE {
		closeModal(getParent(HWND(hwnd)))
		return 0
	}
	return callWindowProc(macEditOrigProc, HWND(hwnd), uint32(msg), wParam, lParam)
})

var macLookupWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createMACLookupControls(HWND(hwnd))
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_CTLCOLOREDIT:
		return ctlColorDlgBody(wParam)

	case WM_COMMAND:
		switch loword(wParam) {
		case idMACLookup:
			doMACLookup(HWND(hwnd))
		}
		return 0

	case WM_CLOSE:
		closeModal(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

func createMACLookupControls(hwnd HWND) {
	inst := getModuleHandle()
	const (
		pad    int32 = 14
		cw     int32 = 380 // client width
		lblW   int32 = 90
		btnW   int32 = 70
		gapLbl int32 = 6 // label → edit
		gapBtn int32 = 8 // edit → button
	)
	// Edit fills the space between label and button, with pad on both sides.
	editX := pad + lblW + gapLbl
	btnX := cw - pad - btnW
	editW := btnX - gapBtn - editX

	y := pad

	// ── Row 1: MAC input ────────────────────────────────────────────────────
	createCtrl("STATIC", "MAC address:", WS_CHILD|WS_VISIBLE,
		pad, y+4, lblW, 18, hwnd, 0, inst)

	hwndMACEdit, _ = createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL,
		editX, y, editW, 22, hwnd, HMENU(idMACEdit), inst)

	createCtrl("BUTTON", "Look Up",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON,
		btnX, y, btnW, 22, hwnd, idMACLookup, inst)

	y += 32

	// ── Separator ───────────────────────────────────────────────────────────
	createDlgSeparator(hwnd, inst, pad, y, cw-pad*2)
	y += 14

	// ── Row 2: Vendor result ─────────────────────────────────────────────────
	createCtrl("STATIC", "Vendor:", WS_CHILD|WS_VISIBLE,
		pad, y, lblW, 18, hwnd, 0, inst)
	y += 22

	hwndMACResult, _ = createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|WS_VISIBLE|ES_READONLY|ES_MULTILINE|ES_AUTOVSCROLL,
		pad, y, cw-pad*2, 28, hwnd, HMENU(idMACResult), inst)

	// Subclass edit to close on Escape.
	macEditOrigProc = setWindowLongPtr(hwndMACEdit, GWLP_WNDPROC, macEditSubclassCb)
}

func doMACLookup(hwnd HWND) {
	raw := getWindowText(hwndMACEdit)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		setWindowText(hwndMACResult, "Enter a MAC address first.")
		return
	}

	// Accept XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, and XXXXXXXXXXXX (no sep).
	// net.ParseMAC handles the first two; normalise the third.
	normalised := raw
	if len(raw) == 12 {
		// No separators — insert colons.
		var b strings.Builder
		for i, c := range raw {
			if i > 0 && i%2 == 0 {
				b.WriteByte(':')
			}
			b.WriteRune(c)
		}
		normalised = b.String()
	}

	mac, err := net.ParseMAC(normalised)
	if err != nil {
		setWindowText(hwndMACResult, "Invalid MAC address — use format AA:BB:CC:DD:EE:FF.")
		return
	}

	vendor := scan.LookupVendor(mac)
	if vendor == "" {
		setWindowText(hwndMACResult, "Unknown vendor (OUI not found in database).")
	} else {
		setWindowText(hwndMACResult, vendor)
	}
	_ = hwnd
}

// showMACLookupDialog opens the MAC Vendor Lookup tool dialog.
func showMACLookupDialog(parent HWND) {
	const (
		clientW int32 = 380
		clientH int32 = 132 // pad + input row + sep section + vendor label + result box + pad
		dlgStyle   uint32 = WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN
		dlgExStyle uint32 = WS_EX_DLGMODALFRAME
	)
	outer := adjustWindowRectEx(RECT{0, 0, clientW, clientH}, dlgStyle, dlgExStyle, false)
	dlg := createAndCenterDialog("NetScopeMACLookup", "MAC Vendor Lookup",
		outer.Right-outer.Left, outer.Bottom-outer.Top, macLookupWndProc, parent)
	if dlg == 0 {
		return
	}
	setFontAllChildren(dlg, appFont)
	setFocus(hwndMACEdit)
	runModal(dlg, parent)
}
