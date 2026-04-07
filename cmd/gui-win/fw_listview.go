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
