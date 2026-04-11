//go:build windows

// Win32 framework — split-pane info panel factory.
//
// This file is part of the Win32 framework layer (see fw_win32.go).
// It provides a generic two-section "info panel" widget used by the Network
// and Scan Report tabs:
//
//	┌──────────────────────────────┐
//	│  header pane  (EDIT, r/o)   │  ← fixed pixel height
//	├──────────────────────────────┤
//	│  body ListView  (optional)  │  ← fills remaining height; absent if nil cols
//	└──────────────────────────────┘
//
// Rule: zero NetScope application logic here. Control IDs, column keys,
// and placeholder text belong in application files.

package guiwin

// infoView is a vertically-split panel consisting of a read-only text header
// and an optional scrollable ListView body. Both controls are children of the
// same parent window and start hidden.
type infoView struct {
	hwndHeader      HWND // ES_MULTILINE | ES_READONLY EDIT pane
	hwndList        HWND // WC_LISTVIEW body; 0 if the panel is header-only
	hwndPlaceholder HWND // optional empty-state overlay; 0 if not needed
}

// createInfoView creates an infoView as hidden child windows of parent.
//
//   - headerID   — child control ID for the header EDIT; pass 0 to skip.
//   - listID     — child control ID for the ListView; ignored when colTitles is nil.
//   - colTitles  — column header strings for the body ListView. Pass nil for
//     a header-only panel (Scan Report tab).
//   - colWidths  — logical-pixel default widths for each column (before DPI
//     scaling); must be the same length as colTitles.
//   - placeholder — non-empty string creates an empty-state overlay that the
//     caller is responsible for showing/hiding; "" means none.
//   - placeholderY — vertical offset for the placeholder overlay within (x,y,w,h).
func createInfoView(
	parent HWND, inst HINSTANCE,
	headerID, listID HMENU,
	colTitles []string, colWidths []int32,
	placeholder string,
) infoView {
	v := infoView{}

	// Header: borderless, no scrollbar; callers set text via setInfoHeader.
	hw, _ := createWindowEx(
		WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|WS_VSCROLL,
		0, 0, 0, 0, parent, headerID, inst,
	)
	v.hwndHeader = hw

	// Optional ListView body.
	if len(colTitles) > 0 {
		lw, _ := createWindowEx(
			0, WC_LISTVIEW, "",
			WS_CHILD|WS_CLIPSIBLINGS|WS_VSCROLL|LVS_REPORT|LVS_SHOWSELALWAYS,
			0, 0, 0, 0, parent, listID, inst,
		)
		sendMessage(lw, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
			LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER)
		for i, title := range colTitles {
			w := int32(0)
			if i < len(colWidths) {
				w = colWidths[i]
			}
			listViewAddColumn(lw, int32(i), title, scale(w))
		}
		v.hwndList = lw
	}

	// Optional empty-state overlay.
	if placeholder != "" {
		v.hwndPlaceholder = createEmptyStateOverlay(parent, placeholder, 0, 0, 0, 0)
	}

	return v
}

// showInfoView shows the header pane and, when present, the body ListView.
// The placeholder (if any) is kept hidden — callers manage it explicitly.
func showInfoView(v infoView) {
	showWindow(v.hwndHeader, SW_SHOW)
	if v.hwndList != 0 {
		showWindow(v.hwndList, SW_SHOW)
	}
}

// hideInfoView hides all infoView controls including any placeholder.
func hideInfoView(v infoView) {
	showWindow(v.hwndHeader, SW_HIDE)
	if v.hwndList != 0 {
		showWindow(v.hwndList, SW_HIDE)
	}
	if v.hwndPlaceholder != 0 {
		showWindow(v.hwndPlaceholder, SW_HIDE)
	}
}

// resizeInfoView repositions the infoView to fill (x, y, w, h).
// headerH is the pixel height reserved for the header pane. The body
// ListView (when present) fills the remaining space below the header.
// If the panel is header-only, headerH is ignored and the header fills
// the entire area.
func resizeInfoView(v infoView, x, y, w, h, headerH int32) {
	if v.hwndList == 0 {
		// Header-only: fill the full area.
		moveWindow(v.hwndHeader, x, y, w, h)
		if v.hwndPlaceholder != 0 {
			moveWindow(v.hwndPlaceholder, x, y+(h-scale(20))/2, w, scale(20))
		}
		return
	}
	// Clamp headerH so the body always gets at least one row of height.
	if headerH < 0 {
		headerH = 0
	}
	bodyH := h - headerH
	if bodyH < scale(30) {
		bodyH = scale(30)
		headerH = h - bodyH
		if headerH < 0 {
			headerH = 0
		}
	}
	moveWindow(v.hwndHeader, x, y, w, headerH)
	moveWindow(v.hwndList, x, y+headerH, w, bodyH)
	if v.hwndPlaceholder != 0 {
		mid := y + headerH + (bodyH-scale(20))/2
		moveWindow(v.hwndPlaceholder, x, mid, w, scale(20))
	}
}

// setInfoHeader replaces the text of the header pane.
func setInfoHeader(v infoView, text string) {
	setWindowText(v.hwndHeader, text)
}

// infoViewSetFont applies fonts to the infoView controls.
// hdrFont is applied to the header (typically a monospaced font for aligned
// columns). listFont is applied to the ListView body; pass 0 to skip.
func infoViewSetFont(v infoView, hdrFont, listFont HFONT) {
	if hdrFont != 0 {
		sendMessage(v.hwndHeader, WM_SETFONT, uintptr(hdrFont), 1)
	}
	if v.hwndList != 0 && listFont != 0 {
		sendMessage(v.hwndList, WM_SETFONT, uintptr(listFont), 1)
	}
}
