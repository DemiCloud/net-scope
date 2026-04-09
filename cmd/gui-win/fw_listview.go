//go:build windows

// Win32 framework — ListView helpers.
//
// This file is part of the Win32 framework layer (see fw_win32.go).
// It provides generic, application-agnostic ListView operations: column
// management, row querying, selection, text formatting, sort-indicator
// management, and text-based column sorting.
//
// Rule: zero NetScope application logic here.  Any constant that appears in
// this file must be a Win32 constant defined in fw_win32.go.

package guiwin

import (
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

// ---------------------------------------------------------------------------
// Column management
// ---------------------------------------------------------------------------

// listViewAddColumnFmt inserts a column at index idx with explicit alignment.
func listViewAddColumnFmt(hwnd HWND, idx int32, title string, width, fmt int32) {
	col := LVCOLUMN{
		Mask:    LVCF_TEXT | LVCF_WIDTH | LVCF_FMT,
		Fmt:     fmt,
		Cx:      width,
		PszText: utf16(title),
	}
	sendMessage(hwnd, LVM_INSERTCOLUMN, uintptr(idx), uintptr(unsafe.Pointer(&col)))
}

// listViewAddColumn inserts a left-aligned column at index idx.
func listViewAddColumn(hwnd HWND, idx int32, title string, width int32) {
	listViewAddColumnFmt(hwnd, idx, title, width, LVCFMT_LEFT)
}

// listViewSetColumnHeader updates the header text for a single column.
func listViewSetColumnHeader(hwnd HWND, idx int32, title string) {
	col := LVCOLUMN{
		Mask:    LVCF_TEXT,
		PszText: utf16(title),
	}
	sendMessage(hwnd, LVM_SETCOLUMN, uintptr(idx), uintptr(unsafe.Pointer(&col)))
}

// ---------------------------------------------------------------------------
// Row / cell access
// ---------------------------------------------------------------------------

// setSubItem sets the text for column col of an existing row.
func setSubItem(hwnd HWND, row, col int32, text string) {
	t := utf16(text)
	item := LVITEM{
		Mask:     LVIF_TEXT,
		IItem:    row,
		ISubItem: col,
		PszText:  t,
	}
	sendMessage(hwnd, LVM_SETITEM, 0, uintptr(unsafe.Pointer(&item)))
}

// listViewGetCellText reads the text of a single cell via LVM_GETITEMTEXT.
func listViewGetCellText(hwnd HWND, row, col int32) string {
	buf := make([]uint16, 512)
	item := LVITEM{
		ISubItem:   col,
		PszText:    &buf[0],
		CchTextMax: int32(len(buf)),
	}
	sendMessage(hwnd, LVM_GETITEMTEXT, uintptr(row), uintptr(unsafe.Pointer(&item)))
	return syscall.UTF16ToString(buf)
}

// listViewGetRowTSV returns all visible columns of a row as a tab-separated string.
func listViewGetRowTSV(hwnd HWND, row, numCols int32) string {
	parts := make([]string, numCols)
	for c := int32(0); c < numCols; c++ {
		parts[c] = listViewGetCellText(hwnd, row, c)
	}
	return strings.Join(parts, "\t")
}

// ---------------------------------------------------------------------------
// Selection helpers
// ---------------------------------------------------------------------------

// listViewSelectAll selects every row in hwnd.
func listViewSelectAll(hwnd HWND) {
	item := LVITEM{
		State:     LVIS_SELECTED,
		StateMask: LVIS_SELECTED,
	}
	sendMessage(hwnd, LVM_SETITEMSTATE, ^uintptr(0), uintptr(unsafe.Pointer(&item)))
}

// listViewGetSelectedRows returns the row indices of all selected items.
func listViewGetSelectedRows(hwnd HWND) []int32 {
	var rows []int32
	row := int32(sendMessage(hwnd, LVM_GETNEXTITEM, ^uintptr(0), LVNI_SELECTED))
	for row >= 0 {
		rows = append(rows, row)
		row = int32(sendMessage(hwnd, LVM_GETNEXTITEM, uintptr(row), LVNI_SELECTED))
	}
	return rows
}

// listViewSelectedText returns the text of column col for the first selected
// row, or "" if nothing is selected.
func listViewSelectedText(hwnd HWND, col int32) string {
	row := int32(sendMessage(hwnd, LVM_GETNEXTITEM, ^uintptr(0), LVNI_SELECTED))
	if row < 0 {
		return ""
	}
	return listViewGetCellText(hwnd, row, col)
}

// listViewAllSelectedTexts returns column col text for every selected row.
func listViewAllSelectedTexts(hwnd HWND, col int32) []string {
	var out []string
	row := int32(sendMessage(hwnd, LVM_GETNEXTITEM, ^uintptr(0), LVNI_SELECTED))
	for row >= 0 {
		out = append(out, listViewGetCellText(hwnd, row, col))
		row = int32(sendMessage(hwnd, LVM_GETNEXTITEM, uintptr(row), LVNI_SELECTED))
	}
	return out
}

// listViewSelectFirst selects and focuses the first row of hwnd, if any rows
// exist. Useful after repopulating a list to prime keyboard navigation.
func listViewSelectFirst(hwnd HWND) {
	if sendMessage(hwnd, LVM_GETITEMCOUNT, 0, 0) == 0 {
		return
	}
	item := LVITEM{
		State:     LVIS_SELECTED | LVIS_FOCUSED,
		StateMask: LVIS_SELECTED | LVIS_FOCUSED,
	}
	sendMessage(hwnd, LVM_SETITEMSTATE, 0, uintptr(unsafe.Pointer(&item)))
}

// ---------------------------------------------------------------------------
// Data export formatters
// ---------------------------------------------------------------------------

// listViewFormatTSV formats rows as tab-separated values with a header row.
func listViewFormatTSV(hwnd HWND, rows []int32, numCols int32, headers []string) string {
	var sb strings.Builder
	sb.WriteString(strings.Join(headers, "\t"))
	for _, row := range rows {
		sb.WriteByte('\n')
		sb.WriteString(listViewGetRowTSV(hwnd, row, numCols))
	}
	return sb.String()
}

// listViewFormatCSV formats rows as RFC 4180 CSV with a header row.
func listViewFormatCSV(hwnd HWND, rows []int32, numCols int32, headers []string) string {
	csvQ := func(s string) string {
		if strings.ContainsAny(s, ",\"\r\n") {
			return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
		}
		return s
	}
	quotedHeaders := make([]string, len(headers))
	for i, h := range headers {
		quotedHeaders[i] = csvQ(h)
	}
	var sb strings.Builder
	sb.WriteString(strings.Join(quotedHeaders, ","))
	for _, row := range rows {
		sb.WriteString("\r\n")
		for c := int32(0); c < numCols; c++ {
			if c > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(csvQ(listViewGetCellText(hwnd, row, c)))
		}
	}
	return sb.String()
}

// listViewFormatJSON formats rows as a JSON array of objects.
// Header strings are normalised to snake_case JSON keys.
func listViewFormatJSON(hwnd HWND, rows []int32, numCols int32, headers []string) string {
	jsonQ := func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		s = strings.ReplaceAll(s, "\n", `\n`)
		s = strings.ReplaceAll(s, "\r", `\r`)
		s = strings.ReplaceAll(s, "\t", `\t`)
		return `"` + s + `"`
	}
	headerToKey := func(h string) string {
		h = strings.ToLower(h)
		var b strings.Builder
		prev := '_'
		for _, r := range h {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				b.WriteRune(r)
				prev = r
			} else if prev != '_' {
				b.WriteByte('_')
				prev = '_'
			}
		}
		return strings.Trim(b.String(), "_")
	}
	keys := make([]string, len(headers))
	for i, h := range headers {
		keys[i] = headerToKey(h)
	}
	var sb strings.Builder
	sb.WriteString("[\n")
	for i, row := range rows {
		sb.WriteString("  {")
		for c := int32(0); c < numCols; c++ {
			if c > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(jsonQ(keys[c]))
			sb.WriteString(": ")
			sb.WriteString(jsonQ(listViewGetCellText(hwnd, row, c)))
		}
		sb.WriteByte('}')
		if i < len(rows)-1 {
			sb.WriteByte(',')
		}
		sb.WriteByte('\n')
	}
	sb.WriteByte(']')
	return sb.String()
}

// ---------------------------------------------------------------------------
// Sort helpers
// ---------------------------------------------------------------------------

// lvNextSortState advances the sort state through the cycle
//
//	asc → desc → unsorted (col = −1, asc = true) → …
//
// Pass the current sortCol/sortAsc and the column index just clicked.
func lvNextSortState(curCol int32, curAsc bool, newCol int32) (col int32, asc bool) {
	if newCol == curCol {
		if curAsc {
			return curCol, false // asc → desc
		}
		return -1, true // desc → unsorted
	}
	return newCol, true // different column → ascending
}

// lvUpdateSortIndicators refreshes all column headers in hwnd to show ▲ or ▼
// on sortCol (or plain titles when sortCol < 0).
func lvUpdateSortIndicators(hwnd HWND, colTitles []string, sortCol int32, sortAsc bool) {
	for i, title := range colTitles {
		h := title
		if int32(i) == sortCol {
			if sortAsc {
				h = title + " ▲"
			} else {
				h = title + " ▼"
			}
		}
		listViewSetColumnHeader(hwnd, int32(i), h)
	}
}

// lvTextSort sorts a text-only ListView by column col (case-insensitive).
// Empty / "—" values always sort last regardless of direction.
// When col < 0 (unsorted state) this is a no-op.
//
// All numCols cell texts are read, the list is cleared, and the sorted rows
// are re-inserted.  Call any IP→row map rebuilds after this function.
func lvTextSort(hwnd HWND, numCols int32, col int32, asc bool) {
	if col < 0 {
		return
	}
	count := int32(sendMessage(hwnd, LVM_GETITEMCOUNT, 0, 0))
	if count <= 0 {
		return
	}
	rows := make([][]string, count)
	for i := int32(0); i < count; i++ {
		rows[i] = make([]string, numCols)
		for c := int32(0); c < numCols; c++ {
			rows[i][c] = listViewGetCellText(hwnd, i, c)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i][col], rows[j][col]
		emptyA := a == "" || a == "—"
		emptyB := b == "" || b == "—"
		if emptyA && emptyB {
			return false
		}
		if emptyA {
			return !asc
		}
		if emptyB {
			return asc
		}
		cmp := strings.Compare(strings.ToLower(a), strings.ToLower(b))
		if asc {
			return cmp < 0
		}
		return cmp > 0
	})
	sendMessage(hwnd, LVM_DELETEALLITEMS, 0, 0)
	for _, rowData := range rows {
		p := utf16(rowData[0])
		item := LVITEM{Mask: LVIF_TEXT, IItem: 0x7fffffff, PszText: p}
		newRow := int32(sendMessage(hwnd, LVM_INSERTITEM, 0, uintptr(unsafe.Pointer(&item))))
		for c := int32(1); c < numCols; c++ {
			setSubItem(hwnd, newRow, c, rowData[c])
		}
	}
}

// ---------------------------------------------------------------------------
// Column visibility
// ---------------------------------------------------------------------------

// setLVColumnVisible shows or hides a column by setting its width to 0 or its
// default scaled width.  colVis is mutated in-place.
func setLVColumnVisible(hwnd HWND, defWidths []int32, colVis []bool, col int32, visible bool) {
	if col < 0 || int(col) >= len(colVis) {
		return
	}
	colVis[col] = visible
	w := int32(0)
	if visible {
		w = scale(defWidths[col])
	}
	sendMessage(hwnd, LVM_SETCOLUMNWIDTH, uintptr(col), uintptr(uint32(w)))
}

// restoreLVColumns resets all columns to visible at their default scaled widths.
// colVis is mutated in-place.
func restoreLVColumns(hwnd HWND, defWidths []int32, colVis []bool) {
	for i := range colVis {
		colVis[i] = true
		sendMessage(hwnd, LVM_SETCOLUMNWIDTH, uintptr(i), uintptr(uint32(scale(defWidths[i]))))
	}
}

// ---------------------------------------------------------------------------
// Column state persistence helpers
// ---------------------------------------------------------------------------

// listViewGetColumnWidths reads the current Win32 device-pixel width of every
// column via LVM_GETCOLUMNWIDTH. Hidden columns have width 0. The returned
// slice has exactly numCols elements.
func listViewGetColumnWidths(hwnd HWND, numCols int) []int {
	widths := make([]int, numCols)
	for i := 0; i < numCols; i++ {
		widths[i] = int(sendMessage(hwnd, LVM_GETCOLUMNWIDTH, uintptr(i), 0))
	}
	return widths
}

// listViewApplyColumnWidths sets each column to its saved device-pixel width
// and updates colVis in-place: a column is considered visible iff its width > 0.
// widths and colVis must have the same length; excess widths are ignored.
func listViewApplyColumnWidths(hwnd HWND, widths []int, colVis []bool) {
	n := len(widths)
	if len(colVis) < n {
		n = len(colVis)
	}
	for i := 0; i < n; i++ {
		colVis[i] = widths[i] > 0
		sendMessage(hwnd, LVM_SETCOLUMNWIDTH, uintptr(i), uintptr(uint32(widths[i])))
	}
}

// getLVSortState returns the current sort column (-1 = unsorted) and direction
// for hwnd. Returns (-1, true) if hwnd is not a managed ListView.
func getLVSortState(hwnd HWND) (col int, asc bool) {
	if st, ok := lvManagedStates[hwnd]; ok {
		return int(st.sortCol), st.sortAsc
	}
	return -1, true
}

// applyLVSortState restores the sort column and direction on a managed ListView:
// it updates the internal managed state and redraws the column header indicators.
// col is clamped to [-1, len(colTitles)-1]; out-of-range values are treated as
// unsorted. Does nothing if hwnd is not a managed ListView.
func applyLVSortState(hwnd HWND, col int, asc bool, colTitles []string) {
	st, ok := lvManagedStates[hwnd]
	if !ok {
		return
	}
	if col < -1 || col >= len(colTitles) {
		col = -1
		asc = true
	}
	st.sortCol = int32(col)
	st.sortAsc = asc
	lvUpdateSortIndicators(hwnd, colTitles, st.sortCol, st.sortAsc)
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Managed ListView subclassing
// ---------------------------------------------------------------------------
//
// subclassListViewManaged installs a window subclass on a ListView that
// provides all standard framework behaviours in one call:
//
//   - Marquee (rubber-band) multi-selection starting on any row or empty space
//   - Ctrl+A  — select all rows
//   - Shift+click / Ctrl+click — forwarded to the native ListView for native
//     range-extension and toggle-selection
//   - Column-header click — sort by that column (asc → desc → unsorted cycle);
//     indicators (▲/▼) are updated automatically; onSort is called after
//   - Column-header right-click — "Edit Columns…" popup (only when colVis is
//     non-nil)
//
// Parameters:
//   colTitles  canonical column header strings (without sort indicators)
//   colVis     per-column visibility slice (nil = column hiding not offered)
//   defWidths  96-DPI logical widths matching colTitles (nil when colVis nil)
//   onSort     called after sort state is updated; receives (hwnd, col, asc).
//              Pass nil to use the generic text sort (lvTextSort).
//
// Must be called after the ListView has been created and all columns added.

// lvManagedState holds all per-ListView state for a managed listview.
type lvManagedState struct {
	// Marquee drag-selection.
	dragging bool
	startPt  POINT
	origProc uintptr

	// Sort.
	sortCol   int32
	sortAsc   bool
	colTitles []string
	onSort    func(hw HWND, col int32, asc bool) // nil → lvTextSort

	// Column visibility (nil → Edit Columns not offered).
	colVis    []bool
	defWidths []int32
}

// lvManagedStates maps a ListView HWND to its managed state.
// Accessed on the Windows message-loop goroutine only.
var lvManagedStates = map[HWND]*lvManagedState{}

// lvSubclassRefs holds strong references to subclass callback values to
// prevent the Go GC from collecting them while the subclass is active.
var lvSubclassRefs []uintptr

func subclassListViewManaged(hwnd HWND, colTitles []string, colVis []bool, defWidths []int32, onSort func(HWND, int32, bool)) {
	state := &lvManagedState{
		sortCol:   -1,
		sortAsc:   true,
		colTitles: colTitles,
		colVis:    colVis,
		defWidths:  defWidths,
		onSort:    onSort,
	}
	lvManagedStates[hwnd] = state

	cb := syscall.NewCallback(func(h, msg, wParam, lParam uintptr) uintptr {
		hw := HWND(h)
		s, ok := lvManagedStates[hw]
		if !ok {
			return defWindowProc(hw, uint32(msg), wParam, lParam)
		}

		switch uint32(msg) {

		// ── Ctrl+A ────────────────────────────────────────────────────────
		case WM_KEYDOWN:
			if wParam == VK_KEY_A && getKeyState(VK_CONTROL) < 0 {
				listViewSelectAll(hw)
				return 0
			}

		// ── Header notifications (sort + Edit Columns) ────────────────────
		// The header control is a direct child of the ListView. It posts
		// WM_NOTIFY to the ListView (its parent). We intercept here so that
		// the behaviours are self-contained in the subclass — the parent
		// window's WM_NOTIFY handler needs no knowledge of these listviews.
		case WM_NOTIFY:
			hdr := (*NMHDR)(unsafe.Pointer(lParam)) //nolint:govet
			headerHwnd := HWND(sendMessage(hw, LVM_GETHEADER, 0, 0))
			if HWND(hdr.HwndFrom) != headerHwnd {
				break
			}
			switch hdr.Code {
			case HDN_ITEMCLICKW:
				nm := (*NMHEADER)(unsafe.Pointer(lParam)) //nolint:govet
				s.sortCol, s.sortAsc = lvNextSortState(s.sortCol, s.sortAsc, nm.IItem)
				lvUpdateSortIndicators(hw, s.colTitles, s.sortCol, s.sortAsc)
				if s.onSort != nil {
					s.onSort(hw, s.sortCol, s.sortAsc)
				} else {
					lvTextSort(hw, int32(len(s.colTitles)), s.sortCol, s.sortAsc)
				}
				return 0

			case NM_RCLICK:
				if s.colVis != nil {
					nm := (*NMMOUSE)(unsafe.Pointer(lParam)) //nolint:govet
					showColumnHeaderMenu(getParent(hw), hw, s, int32(nm.DwItemSpec), getCursorPos())
					return 0
				}
			}

		// ── Marquee drag-selection ────────────────────────────────────────
		case WM_LBUTTONDOWN:
			// Shift/Ctrl → delegate to the ListView for native range/toggle select.
			if getKeyState(VK_SHIFT) < 0 || getKeyState(VK_CONTROL) < 0 {
				break
			}
			x := int32(int16(lParam & 0xffff))
			y := int32(int16((lParam >> 16) & 0xffff))
			ht := LVHITTESTINFO{Pt: POINT{X: x, Y: y}}
			sendMessage(hw, LVM_HITTEST, 0, uintptr(unsafe.Pointer(&ht)))
			if ht.Flags&LVHT_ONITEM == 0 {
				// Empty space — native marquee already handles this case.
				break
			}
			// Item hit: take control of drag-selection.
			procSetFocus.Call(uintptr(hw))
			// Clear all selection.
			clearAll := LVITEM{StateMask: LVIS_SELECTED | LVIS_FOCUSED}
			sendMessage(hw, LVM_SETITEMSTATE, ^uintptr(0), uintptr(unsafe.Pointer(&clearAll)))
			// Select and focus the clicked item.
			sel := LVITEM{State: LVIS_SELECTED | LVIS_FOCUSED, StateMask: LVIS_SELECTED | LVIS_FOCUSED}
			sendMessage(hw, LVM_SETITEMSTATE, uintptr(ht.IItem), uintptr(unsafe.Pointer(&sel)))
			sendMessage(hw, LVM_SETSELECTIONMARK, 0, uintptr(ht.IItem))
			// Begin drag state and capture subsequent mouse messages.
			s.dragging = true
			s.startPt = POINT{X: x, Y: y}
			setCapture(hw)
			return 0

		case WM_MOUSEMOVE:
			if !s.dragging {
				break
			}
			if wParam&MK_LBUTTON == 0 {
				// Button was released without delivering WM_LBUTTONUP — clean up.
				s.dragging = false
				releaseCapture()
				break
			}
			x := int32(int16(lParam & 0xffff))
			y := int32(int16((lParam >> 16) & 0xffff))
			// Normalise the drag rectangle so top-left ≤ bottom-right.
			selRect := RECT{Left: s.startPt.X, Top: s.startPt.Y, Right: x, Bottom: y}
			if selRect.Left > selRect.Right {
				selRect.Left, selRect.Right = selRect.Right, selRect.Left
			}
			if selRect.Top > selRect.Bottom {
				selRect.Top, selRect.Bottom = selRect.Bottom, selRect.Top
			}
			// Update selection state for every row based on rect intersection.
			count := int32(sendMessage(hw, LVM_GETITEMCOUNT, 0, 0))
			for i := int32(0); i < count; i++ {
				var ir RECT
				ir.Left = LVIR_BOUNDS
				sendMessage(hw, LVM_GETITEMRECT, uintptr(i), uintptr(unsafe.Pointer(&ir)))
				intersects := ir.Left < selRect.Right && ir.Right > selRect.Left &&
					ir.Top < selRect.Bottom && ir.Bottom > selRect.Top
				var st uint32
				if intersects {
					st = LVIS_SELECTED
				}
				upd := LVITEM{State: st, StateMask: LVIS_SELECTED}
				sendMessage(hw, LVM_SETITEMSTATE, uintptr(i), uintptr(unsafe.Pointer(&upd)))
			}
			return 0

		case WM_LBUTTONUP:
			if s.dragging {
				s.dragging = false
				releaseCapture()
				return 0
			}

		case WM_CAPTURECHANGED:
			// Capture stolen by another window — abort drag cleanly.
			s.dragging = false
		}

		return callWindowProc(s.origProc, hw, uint32(msg), wParam, lParam)
	})

	lvSubclassRefs = append(lvSubclassRefs, cb)
	state.origProc = setWindowLongPtr(hwnd, GWLP_WNDPROC, cb)
}

// ---------------------------------------------------------------------------
// Column header right-click context menu
// ---------------------------------------------------------------------------

// showColumnHeaderMenu displays the per-column context menu on a header right-click.
// col is the 0-based column index from NMMOUSE.DwItemSpec; pass -1 when no
// column was directly hit (empty area of header — only "Edit Columns…" shows).
func showColumnHeaderMenu(parent, hwndLV HWND, s *lvManagedState, col int32, pt POINT) {
	n := int32(len(s.colTitles))

	const cmdHide = 1
	const cmdEdit = 2

	menu := createPopupMenu()

	// Show "Hide 'Column'" only when a specific column was hit.
	if col >= 0 && col < n {
		// Col 0 is always visible; also guard against hiding the last visible column.
		visCount := 0
		for _, v := range s.colVis {
			if v {
				visCount++
			}
		}
		canHide := col > 0 && visCount > 1
		flags := uint32(MF_STRING)
		if !canHide {
			flags |= MF_GRAYED
		}
		appendMenu(menu, flags, cmdHide, "Hide '"+s.colTitles[col]+"'")
		appendMenu(menu, MF_SEPARATOR, 0, "")
	}
	appendMenu(menu, MF_STRING, cmdEdit, "Edit Columns\u2026")

	cmd := trackPopupMenu(menu, TPM_LEFTALIGN|TPM_TOPALIGN|TPM_RETURNCMD, pt.X, pt.Y, parent)
	destroyMenu(menu)

	switch cmd {
	case cmdHide:
		setLVColumnVisible(hwndLV, s.defWidths, s.colVis, col, false)
	case cmdEdit:
		showEditColumnsDialog(parent, hwndLV, s.colTitles, s.colVis, s.defWidths)
	}
}

// ---------------------------------------------------------------------------
// Edit Columns dialog (framework — opened by showColumnHeaderMenu)
// ---------------------------------------------------------------------------

// editColsChecks holds the HWND of each checkbox (indexed by column number).
// Col 0 has no checkbox; it is always visible.
var editColsChecks [16]HWND

// editColsDlgState holds the parameters for the currently-open Edit Columns
// dialog. Set by showEditColumnsDialog before runModal; read by the WndProc.
var editColsDlgState struct {
	hwndLV    HWND
	colTitles []string
	colVis    []bool  // slice into the listview's actual visibility array; mutated in-place
	defWidths []int32 // 96-DPI logical widths
}

// showEditColumnsDialog opens the generic Edit Columns dialog for any listview.
// colVis is mutated when the user presses OK.
func showEditColumnsDialog(parent, hwndLV HWND, colTitles []string, colVis []bool, defWidths []int32) {
	editColsDlgState.hwndLV = hwndLV
	editColsDlgState.colTitles = colTitles
	editColsDlgState.colVis = colVis
	editColsDlgState.defWidths = defWidths

	registerDialogClass("NetScopeEditCols", syscall.NewCallback(editColsWndProc))

	// Height: 12px top padding + one 26px row per checkbox (cols 1..n-1) +
	// 80px footer (title bar + button row + padding).
	n := int32(len(colTitles))
	const dlgW int32 = 360
	dlgH := 12 + (n-1)*26 + 80
	dlg, _ := createWindowEx(
		WS_EX_DLGMODALFRAME,
		"NetScopeEditCols", "Edit Columns",
		WS_POPUP|WS_CAPTION|WS_SYSMENU,
		0, 0, scale(dlgW), scale(dlgH), parent, 0, getModuleHandle(),
	)
	centerWindowOver(dlg, parent)
	runModal(dlg, parent)
}

func editColsWndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_CREATE:
		sendMessage(HWND(hwnd), WM_SETFONT, uintptr(appFont), 1)
		n := int32(len(editColsDlgState.colTitles))

		// One checkbox per column 1..n-1 (col 0 is always visible).
		for col := int32(1); col < n; col++ {
			y := scale(12) + (col-1)*scale(26)
			editColsChecks[col], _ = createWindowEx(0, "BUTTON", editColsDlgState.colTitles[col],
				WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX,
				scale(12), y, scale(240), scale(22),
				HWND(hwnd), HMENU(IDC_EDITCOLS_COL_BASE+int(col)), getModuleHandle())
			sendMessage(editColsChecks[col], WM_SETFONT, uintptr(appFont), 1)
			check := BST_UNCHECKED
			if editColsDlgState.colVis[col] {
				check = BST_CHECKED
			}
			sendMessage(editColsChecks[col], BM_SETCHECK, uintptr(check), 0)
		}
		// Clear stale handles from a previous invocation with more columns.
		for i := int(n); i < len(editColsChecks); i++ {
			editColsChecks[i] = 0
		}

		// Button row: Restore Defaults left, Cancel + OK right.
		cr := getClientRect(HWND(hwnd))
		btnY, leftXs, rightXs := dlgButtonRowSplit(cr.Right-cr.Left, cr.Bottom-cr.Top, 1, 2)
		okHwnd, _ := createWindowEx(0, "BUTTON", "OK",
			WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,
			rightXs[0], btnY, 100, 26,
			HWND(hwnd), HMENU(IDC_EDITCOLS_OK), getModuleHandle())
		sendMessage(okHwnd, WM_SETFONT, uintptr(appFont), 1)
		cancelHwnd, _ := createWindowEx(0, "BUTTON", "Cancel",
			WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
			rightXs[1], btnY, 100, 26,
			HWND(hwnd), HMENU(IDC_EDITCOLS_CANCEL), getModuleHandle())
		sendMessage(cancelHwnd, WM_SETFONT, uintptr(appFont), 1)
		restoreHwnd, _ := createWindowEx(0, "BUTTON", "Restore Defaults",
			WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
			leftXs[0], btnY, 100, 26,
			HWND(hwnd), HMENU(IDC_EDITCOLS_RESTORE), getModuleHandle())
		sendMessage(restoreHwnd, WM_SETFONT, uintptr(appFont), 1)
		return 0

	case WM_COMMAND:
		id := int32(wParam & 0xFFFF)
		n := int32(len(editColsDlgState.colTitles))
		switch id {
		case IDC_EDITCOLS_OK:
			for col := int32(1); col < n; col++ {
				if editColsChecks[col] != 0 {
					chk := sendMessage(editColsChecks[col], BM_GETCHECK, 0, 0)
					setLVColumnVisible(
						editColsDlgState.hwndLV,
						editColsDlgState.defWidths,
						editColsDlgState.colVis,
						col, chk == BST_CHECKED,
					)
				}
			}
			closeModal(HWND(hwnd))
		case IDC_EDITCOLS_CANCEL:
			closeModal(HWND(hwnd))
		case IDC_EDITCOLS_RESTORE:
			// Tick all checkboxes in the UI; actual reset happens on OK.
			for col := int32(1); col < n; col++ {
				if editColsChecks[col] != 0 {
					sendMessage(editColsChecks[col], BM_SETCHECK, BST_CHECKED, 0)
				}
			}
		}
		return 0

	case WM_CTLCOLORSTATIC:
		return ctlColorDialog(wParam)

	case WM_CLOSE:
		closeModal(HWND(hwnd))
		return 0
	}
	return defWindowProc(HWND(hwnd), uint32(msg), wParam, lParam)
}
