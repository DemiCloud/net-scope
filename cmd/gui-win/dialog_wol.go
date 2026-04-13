//go:build windows

// dialog_wol.go — Wake on LAN dialog  (Tools > Wake on LAN…)
//
// Sends a standard 102-byte magic packet (6 × 0xFF + 16 × target-MAC) as a
// UDP broadcast on port 9.  No elevation required.
//
// Layout:
//   ┌──────────────────────────────────────────────┐
//   │  MAC address: [ aa:bb:cc:dd:ee:ff ] [ Wake ] │
//   │  Broadcast:   [ 192.168.1.255     ]          │
//   │  ──────────────────────────────────────────  │
//   │  [ result text                            ]  │
//   └──────────────────────────────────────────────┘
//
// MAC is pre-populated from the selected Scanner row when available.
// Broadcast defaults to 255.255.255.255 and can be overridden to a directed
// subnet broadcast (e.g. 192.168.1.255) for switches that block limited bcasts.

package guiwin

import (
	"strings"
	"syscall"
)

// ---------------------------------------------------------------------------
// Control IDs
// ---------------------------------------------------------------------------

const (
	idWolMAC       = 1400
	idWolBroadcast = 1401
	idWolSend      = 1402
	idWolResultCtl = 1403
)

// ---------------------------------------------------------------------------
// Dialog state
// ---------------------------------------------------------------------------

var (
	hwndWolMACEdit   HWND
	hwndWolBcastEdit HWND
	hwndWolResultLbl HWND

	wolMACOrigProc uintptr
)

// ---------------------------------------------------------------------------
// Edit subclass — Escape closes; Enter triggers Wake.
// ---------------------------------------------------------------------------

var wolEditSubclass = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_KEYDOWN:
		switch wParam {
		case VK_ESCAPE:
			closeModal(getParent(HWND(hwnd)))
			return 0
		case VK_RETURN:
			doSendWoL(getParent(HWND(hwnd)))
			return 0
		}
	}
	return callWindowProc(wolMACOrigProc, HWND(hwnd), uint32(msg), wParam, lParam)
})

// ---------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------

var wolWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		createWoLControls(HWND(hwnd))
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_CTLCOLOREDIT:
		return ctlColorDlgBody(wParam)

	case WM_COMMAND:
		switch loword(wParam) {
		case idWolSend:
			doSendWoL(HWND(hwnd))
		}
		return 0

	case WM_CLOSE:
		closeModal(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

// ---------------------------------------------------------------------------
// Control creation
// ---------------------------------------------------------------------------

func createWoLControls(hwnd HWND) {
	inst := getModuleHandle()
	const (
		pad    int32 = 14
		cw     int32 = 400
		lblW   int32 = 90
		btnW   int32 = 70
		gapLbl int32 = 6
		gapBtn int32 = 8
	)
	editX := pad + lblW + gapLbl
	btnX := cw - pad - btnW
	editW := btnX - gapBtn - editX

	y := pad

	// ── Row 1: MAC address ──────────────────────────────────────────────────
	createCtrl("STATIC", "MAC address:", WS_CHILD|WS_VISIBLE,
		pad, y+4, lblW, 18, hwnd, 0, inst)

	hwndWolMACEdit, _ = createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL,
		editX, y, editW, 22, hwnd, HMENU(idWolMAC), inst)

	makeDefPushButton(hwnd, "Wake", HMENU(idWolSend), btnX, y, btnW, 22)

	y += 32

	// ── Row 2: Broadcast IP ─────────────────────────────────────────────────
	createCtrl("STATIC", "Broadcast:", WS_CHILD|WS_VISIBLE,
		pad, y+4, lblW, 18, hwnd, 0, inst)

	hwndWolBcastEdit, _ = createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL,
		editX, y, editW, 22, hwnd, HMENU(idWolBroadcast), inst)

	y += 36

	// ── Separator ────────────────────────────────────────────────────────────
	createDlgSeparator(hwnd, inst, pad, y, cw-pad*2)
	y += 14

	// ── Result label ─────────────────────────────────────────────────────────
	hwndWolResultLbl, _ = createWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|WS_VISIBLE|ES_READONLY|ES_MULTILINE|ES_AUTOVSCROLL,
		pad, y, cw-pad*2, 28, hwnd, HMENU(idWolResultCtl), inst)

	// Subclass the MAC edit to handle Escape/Enter.
	wolMACOrigProc = setWindowLongPtr(hwndWolMACEdit, GWLP_WNDPROC, wolEditSubclass)
}

// ---------------------------------------------------------------------------
// Logic
// ---------------------------------------------------------------------------

func doSendWoL(hwnd HWND) {
	mac := strings.TrimSpace(getWindowText(hwndWolMACEdit))
	if mac == "" {
		setWindowText(hwndWolResultLbl, "Enter a MAC address first.")
		return
	}
	bcast := strings.TrimSpace(getWindowText(hwndWolBcastEdit))
	if bcast == "" {
		bcast = "255.255.255.255"
		setWindowText(hwndWolBcastEdit, bcast)
	}

	setWindowText(hwndWolResultLbl, "Sending\u2026")
	if !requestWakeOnLAN(mac, bcast) {
		setWindowText(hwndWolResultLbl, "Error: sensor service not running.")
	}
	_ = hwnd
}

// wolDialogHandleResult is called from the main WndProc's WM_WOL_RESULT handler
// on the UI thread.  It updates the result label and the main-window status bar.
func wolDialogHandleResult(mac, errStr string) {
	if hwndWolResultLbl == 0 {
		return
	}
	if errStr == "" {
		setWindowText(hwndWolResultLbl, "Magic packet sent to "+mac+".")
		setStatusPart(0, "WoL \u2192 "+mac)
	} else {
		setWindowText(hwndWolResultLbl, "Error: "+errStr)
	}
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

// showWoLDialog opens the Wake on LAN dialog.
// prefillMAC is pre-populated from the selected scanner row; may be empty.
// prefillBcast is the suggested broadcast address; defaults to 255.255.255.255.
func showWoLDialog(parent HWND, prefillMAC, prefillBcast string) {
	const (
		clientW int32 = 400
		clientH int32 = 148
	)
	registerDialogClass("NetScopeWoL", wolWndProc)
	dlg := createDialogForClient("NetScopeWoL", "Wake on LAN",
		clientW, clientH, wolWndProc, parent)
	if dlg == 0 {
		return
	}
	setFontAllChildren(dlg, appFont)

	if prefillMAC != "" {
		setWindowText(hwndWolMACEdit, prefillMAC)
	}
	bcast := prefillBcast
	if bcast == "" {
		bcast = "255.255.255.255"
	}
	setWindowText(hwndWolBcastEdit, bcast)

	setFocus(hwndWolMACEdit)
	runModal(dlg, parent)

	// Clear dialog-level globals after the dialog is destroyed.
	hwndWolMACEdit = 0
	hwndWolBcastEdit = 0
	hwndWolResultLbl = 0
}
