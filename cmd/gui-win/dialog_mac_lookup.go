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
	idMACClose  = 1304
)

var (
	hwndMACEdit   HWND
	hwndMACResult HWND
)

var macLookupWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createMACLookupControls(HWND(hwnd))
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_COMMAND:
		switch loword(wParam) {
		case idMACLookup:
			doMACLookup(HWND(hwnd))
		case idMACClose:
			closeModal(HWND(hwnd))
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
		pad  int32 = 14
		cw   int32 = 352 // client width
		lblW int32 = 90
		editW int32 = 170
		btnW  int32 = 70
	)

	y := pad

	// Row 1: label + edit + Look Up button
	createCtrl("STATIC", "MAC address:", WS_CHILD|WS_VISIBLE,
		pad, y+4, lblW, 18, hwnd, 0, inst)

	hwndMACEdit, _ = createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL,
		pad+lblW+4, y, editW, 22, hwnd, HMENU(idMACEdit), inst)

	createCtrl("BUTTON", "Look Up",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON,
		pad+lblW+4+editW+6, y, btnW, 22, hwnd, idMACLookup, inst)

	y += 32

	// Row 2: result label (spans full width)
	hwndMACResult, _ = createWindowEx(0, "STATIC", "",
		WS_CHILD|WS_VISIBLE,
		pad, y, cw-pad*2, 36, hwnd, HMENU(idMACResult), inst)

	y += 46

	// Close button — right-aligned
	createCtrl("BUTTON", "Close",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON,
		cw-pad-btnW, y, btnW, 24, hwnd, idMACClose, inst)
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
		clientW int32 = 352
		clientH int32 = 110
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
