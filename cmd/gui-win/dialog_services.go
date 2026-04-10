//go:build windows

package guiwin

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// ---------------------------------------------------------------------------
// View All Services dialog
//
// Lists every service identification across all scans and broadcast events
// that exceeds the configured confidence threshold. Mirrors the All Hosts
// dialog pattern exactly; double-click or Enter opens the Host Detail dialog
// for the owning host.
// ---------------------------------------------------------------------------

const (
	idAllSvcsClose = 730
)

var hwndAllSvcsList HWND // listview inside the All Services dialog

// allSvcsWndProc is the window procedure for the All Services modal.
var allSvcsWndProc = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		inst := getModuleHandle()
		r := getClientRect(HWND(hwnd))
		cW, cH := r.Right, r.Bottom
		const pad int32 = 10
		const hintH int32 = 16
		const btnH int32 = 26

		listH := cH - pad - hintH - pad - btnH - pad

		sv, _ := createWindowEx(0, WC_LISTVIEW, "",
			WS_CHILD|WS_VISIBLE|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS|LVS_SINGLESEL,
			pad, pad, cW-pad*2, listH, HWND(hwnd), HMENU(idAllSvcsClose+1), inst)
		sendMessage(sv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
			LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP)
		subclassListViewManaged(sv, allSvcsHeaders(), nil, nil, nil, nil)
		widths := allSvcsColWidths(cW - pad*2)
		for i, h := range allSvcsHeaders() {
			if i == 2 || i == 5 { // Port, Confidence: right-align
				listViewAddColumnFmt(sv, int32(i), h, widths[i], LVCFMT_RIGHT)
			} else {
				listViewAddColumn(sv, int32(i), h, widths[i])
			}
		}

		allSvcsPopulate(sv, "")

		hintY := pad + listH + pad/2
		createWindowEx(0, "STATIC",
			fmt.Sprintf("Double-click or Enter to view host details  ·  threshold: confidence > %d%%", svcTabMinConf),
			WS_CHILD|WS_VISIBLE,
			pad, hintY, cW-pad*2-110, hintH, HWND(hwnd), 0, inst)

		makePushButton(HWND(hwnd), "Close", idAllSvcsClose, cW-pad-100, cH-pad-btnH, 100, btnH)

		hwndAllSvcsList = sv
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_COMMAND:
		if loword(wParam) == idAllSvcsClose {
			closeModal(HWND(hwnd))
		}
		return 0

	case WM_KEYDOWN:
		if wParam == VK_RETURN {
			if ip := allSvcsSelectedIP(hwndAllSvcsList); ip != "" {
				closeModal(HWND(hwnd))
				showHostDetailDialog(hwndMain, ip)
			}
		}
		return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)

	case WM_NOTIFY:
		hdr := (*NMHDR)(unsafe.Pointer(lParam)) //nolint:govet
		if hdr.HwndFrom != uintptr(hwndAllSvcsList) {
			return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
		}
		if hdr.Code == NM_DBLCLK {
			if ip := allSvcsSelectedIP(hwndAllSvcsList); ip != "" {
				closeModal(HWND(hwnd))
				showHostDetailDialog(hwndMain, ip)
			}
		}
		return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)

	case WM_CLOSE:
		closeModal(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
})

// showAllServicesDialog opens the modal All Services dialog.
func showAllServicesDialog(parent HWND) {
	// Count qualifying services across all known hosts.
	count := 0
	for _, ip := range allHostIPs() {
		e, ok := hostRegistry[ip]
		if !ok || !e.HasResult {
			continue
		}
		for _, ps := range e.Result.PortServices {
			if ps.Confidence > svcTabMinConf {
				count++
			}
		}
	}
	if count == 0 {
		messageBox(parent,
			fmt.Sprintf(
				"No services with confidence > %d%% have been discovered yet.\n\n"+
					"Run a scan with Banner Grab enabled to populate service data.",
				svcTabMinConf),
			"All Services", MB_OK)
		return
	}

	registerDialogClass("NetScopeAllServices", allSvcsWndProc)
	dlg := createAndCenterDialog("NetScopeAllServices", "All Services — Identified Port Services",
		820, 480, allSvcsWndProc, parent)
	if dlg == 0 {
		return
	}
	setFontAllChildren(dlg, appFont)
	runModal(dlg, parent)
}

// allSvcsPopulate fills sv from hostRegistry, matching filter (case-insensitive).
func allSvcsPopulate(sv HWND, filter string) {
	filter = strings.ToLower(filter)
	sendMessage(sv, LVM_DELETEALLITEMS, 0, 0)

	for _, ip := range allHostIPs() {
		e, ok := hostRegistry[ip]
		if !ok || !e.HasResult {
			continue
		}
		hostname := e.Result.Hostname
		if hostname == "" {
			hostname = e.Result.NetBIOS
		}

		for _, ps := range e.Result.PortServices {
			if ps.Confidence <= svcTabMinConf {
				continue
			}
			if filter != "" {
				needle := strings.ToLower(ip + " " + hostname + " " + ps.Product + " " + ps.Version + " " + ps.Banner)
				if !strings.Contains(needle, filter) {
					continue
				}
			}
			p := utf16(ip)
			item := LVITEM{Mask: LVIF_TEXT, IItem: 0x7fffffff, PszText: p}
			row := int32(sendMessage(sv, LVM_INSERTITEM, 0, uintptr(unsafe.Pointer(&item))))
			if row < 0 {
				continue
			}
			hn := hostname
			if hn == "" {
				hn = "—"
			}
			setSubItem(sv, row, 1, hn)
			setSubItem(sv, row, 2, fmt.Sprintf("%d", ps.Port))
			prod := ps.Product
			if prod == "" {
				prod = "—"
			}
			setSubItem(sv, row, 3, prod)
			ver := ps.Version
			if ver == "" {
				ver = "—"
			}
			setSubItem(sv, row, 4, ver)
			setSubItem(sv, row, 5, fmt.Sprintf("%d%%", ps.Confidence))
			banner := ps.Banner
			if banner == "" {
				banner = "—"
			}
			setSubItem(sv, row, 6, banner)
		}
	}
}

// allSvcsSelectedIP returns the IP in column 0 of the currently selected row.
func allSvcsSelectedIP(sv HWND) string {
	return listViewSelectedText(sv, 0)
}

// allSvcsHeaders returns the column headers for the All Services dialog listview.
func allSvcsHeaders() []string {
	return []string{"IP", "Hostname", "Port", "Product", "Version", "Confidence", "Banner"}
}

// allSvcsColWidths distributes available width across the 7 columns.
func allSvcsColWidths(total int32) []int32 {
	// Fixed: Hostname(155) Port(58) Product(150) Version(90) Confidence(80) Banner(rest)
	fixed := int32(155 + 58 + 150 + 90 + 80)
	ipW := int32(120)
	bannerW := total - ipW - fixed - 6 // 6px for column borders
	if bannerW < 120 {
		bannerW = 120
	}
	return []int32{ipW, 155, 58, 150, 90, 80, bannerW}
}
