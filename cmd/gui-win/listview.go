//go:build windows

package main

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/demicloud/net-sweep/internal/sweep"
)

// listViewAddColumn inserts a left-aligned column at index idx.
func listViewAddColumn(hwnd HWND, idx int32, title string, width int32) {
	col := LVCOLUMN{
		Mask:    LVCF_TEXT | LVCF_WIDTH | LVCF_FMT,
		Fmt:     LVCFMT_LEFT,
		Cx:      width,
		PszText: utf16(title),
	}
	sendMessage(hwnd, LVM_INSERTCOLUMN, uintptr(idx), uintptr(unsafe.Pointer(&col)))
}

// listViewInsertPendingRow appends a row showing ip with a "…" status placeholder.
// Returns the row index, or -1 on failure.
func listViewInsertPendingRow(hwnd HWND, ip string) int32 {
	statusPtr := utf16("…")
	item := LVITEM{
		Mask:    LVIF_TEXT,
		IItem:   0x7fffffff, // append
		PszText: statusPtr,
	}
	row := int32(sendMessage(hwnd, LVM_INSERTITEM, 0, uintptr(unsafe.Pointer(&item))))
	if row < 0 {
		return row
	}
	setSubItem(hwnd, row, 1, ip)
	return row
}

// listViewUpdateRow writes all result fields into an existing row.
// Col 0 is the status indicator; col 1 is the IP (already set by InsertPendingRow).
func listViewUpdateRow(hwnd HWND, row int32, r sweep.Result) {
	status := "—"
	if r.Alive {
		status = "•"
	}
	setSubItem(hwnd, row, 0, status)

	if !r.Alive {
		// Leave the remaining columns blank — host is down.
		return
	}

	setSubItem(hwnd, row, 2, r.Hostname)

	mac := "—"
	if r.MAC != nil {
		mac = r.MAC.String()
	}
	setSubItem(hwnd, row, 3, mac)

	vendor := r.Vendor
	if vendor == "" {
		vendor = "—"
	}
	setSubItem(hwnd, row, 4, vendor)

	portStrs := make([]string, len(r.OpenPorts))
	for i, p := range r.OpenPorts {
		portStrs[i] = fmt.Sprintf("%d", p)
	}
	portStr := "—"
	if len(portStrs) > 0 {
		portStr = strings.Join(portStrs, ", ")
	}
	setSubItem(hwnd, row, 5, portStr)

	snmp := ""
	if r.SNMP != nil {
		if r.SNMP.SysName != "" {
			snmp = r.SNMP.SysName + ": "
		}
		snmp += r.SNMP.SysDescr
	}
	if snmp == "" {
		snmp = "—"
	}
	setSubItem(hwnd, row, 6, snmp)

	var svcs []string
	for _, s := range r.Services {
		name := s.Name
		if name == "" {
			name = s.Type
		}
		svcs = append(svcs, fmt.Sprintf("[%s] %s", s.Source, name))
	}
	svcStr := "—"
	if len(svcs) > 0 {
		svcStr = strings.Join(svcs, "; ")
	}
	setSubItem(hwnd, row, 7, svcStr)
}

// listViewAddBroadcastRow appends a single service entry to the Broadcast listview.
func listViewAddBroadcastRow(hwnd HWND, ip string, svc sweep.ServiceInfo) {
	ipPtr := utf16(ip)
	item := LVITEM{
		Mask:    LVIF_TEXT,
		IItem:   0x7fffffff,
		PszText: ipPtr,
	}
	row := int32(sendMessage(hwnd, LVM_INSERTITEM, 0, uintptr(unsafe.Pointer(&item))))
	if row < 0 {
		return
	}
	setSubItem(hwnd, row, 1, svc.Source)
	setSubItem(hwnd, row, 2, svc.Name)
	setSubItem(hwnd, row, 3, svc.Type)
	setSubItem(hwnd, row, 4, strings.Join(svc.Details, "; "))
}

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
