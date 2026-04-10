//go:build windows

package guiwin

import (
	"fmt"
	"sort"
	"strings"
	"syscall"
)

// ---------------------------------------------------------------------------
// Service detail dialog
//
// Opened by double-clicking a row in the Services tab.  Shows all available
// data for the selected port service: product, version, banner, TLS cert,
// confidence, protocol details, and the owning host.
//
// The «View Host» button opens the host detail dialog for the owning IP.
// ---------------------------------------------------------------------------

const (
	idSvcDetailClose    = 740
	idSvcDetailViewHost = 741
)

// currentSvcDetail holds the entry being shown in the service detail dialog.
// Set before the dialog is created; valid until the dialog is closed.
var currentSvcDetail svcTabEntry

// svcDetailWndProc is the window procedure for the service detail modal.
var svcDetailWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		inst := getModuleHandle()
		r := getClientRect(HWND(hwnd))
		cW, cH := r.Right, r.Bottom

		const pad int32 = 10
		const btnH int32 = 28

		editH := cH - pad*2 - pad - btnH - pad

		createWindowEx(
			WS_EX_CLIENTEDGE, "EDIT", svcDetailBodyText(currentSvcDetail),
			WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
			pad, pad, cW-pad*2, editH, HWND(hwnd), 0, inst)

		makePushButton(HWND(hwnd), "View Host", idSvcDetailViewHost,
			pad, cH-pad-btnH, scale(100), btnH)
		makePushButton(HWND(hwnd), "Close", idSvcDetailClose,
			cW-pad-scale(100), cH-pad-btnH, scale(100), btnH)
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_CTLCOLOREDIT:
		return ctlColorDlgBody(wParam)

	case WM_COMMAND:
		switch loword(wParam) {
		case idSvcDetailClose:
			closeModal(HWND(hwnd))
		case idSvcDetailViewHost:
			ip := currentSvcDetail.ip
			closeModal(HWND(hwnd))
			if ip != "" {
				showHostDetailDialog(hwndMain, ip)
			}
		}
		return 0

	case WM_CLOSE:
		closeModal(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

// showServiceDetailDialog opens the modal service detail dialog for e.
func showServiceDetailDialog(parent HWND, e svcTabEntry) {
	currentSvcDetail = e

	name := e.ps.Product
	if name == "" {
		name = fmt.Sprintf("port/%d", e.ps.Port)
	}
	title := fmt.Sprintf("Service — %s on %s:%d", name, e.ip, e.ps.Port)

	registerDialogClass("NetScopeSvcDetail", svcDetailWndProc)
	dlg := createAndCenterDialog("NetScopeSvcDetail", title, 560, 400, svcDetailWndProc, parent)
	if dlg == 0 {
		return
	}
	setFontAllChildren(dlg, appFont)
	runModal(dlg, parent)
}

// svcDetailBodyText formats all service data as a plain-text report for the
// read-only EDIT control.  Uses \r\n line endings (Win32 ES_MULTILINE style).
func svcDetailBodyText(e svcTabEntry) string {
	var b strings.Builder

	name := e.ps.Product
	if name == "" {
		name = "—"
	}
	hostname := e.hostname
	if hostname == "" {
		hostname = "—"
	}
	version := e.ps.Version
	if version == "" {
		version = "—"
	}
	banner := e.ps.Banner
	if banner == "" {
		banner = "—"
	}
	tlsCert := e.ps.TLSCert
	if tlsCert == "" {
		tlsCert = "—"
	}
	alpn := e.ps.ALPN
	if alpn == "" {
		alpn = "—"
	}

	fmt.Fprintf(&b, "Service Name:    %s\r\n", name)
	fmt.Fprintf(&b, "Port:            %d\r\n", e.ps.Port)
	fmt.Fprintf(&b, "Version:         %s\r\n", version)
	fmt.Fprintf(&b, "IP Address:      %s\r\n", e.ip)
	fmt.Fprintf(&b, "Hostname:        %s\r\n", hostname)
	fmt.Fprintf(&b, "Confidence:      %d%%\r\n", e.ps.Confidence)
	fmt.Fprintf(&b, "Banner:          %s\r\n", banner)
	fmt.Fprintf(&b, "TLS Certificate: %s\r\n", tlsCert)
	fmt.Fprintf(&b, "ALPN Protocol:   %s\r\n", alpn)
	fmt.Fprintf(&b, "Service ID:      %s\r\n", e.id)

	if len(e.ps.Details) > 0 {
		b.WriteString("\r\nProtocol Details:\r\n")
		keys := make([]string, 0, len(e.ps.Details))
		for k := range e.ps.Details {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "  %-20s %s\r\n", k+":", e.ps.Details[k])
		}
	}

	return b.String()
}
