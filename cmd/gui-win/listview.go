//go:build windows

package guiwin

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/demicloud/net-sweep/internal/sweep"
)

// Column indices for the Hosts listview
const (
	colStatus   int32 = 0
	colIP       int32 = 1
	colHost     int32 = 2
	colMAC      int32 = 3
	colVendor   int32 = 4
	colOS       int32 = 5
	colLatency  int32 = 6
	colPorts    int32 = 7
	colBanner   int32 = 8
	colServices int32 = 9
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
	setSubItem(hwnd, row, colIP, ip)
	return row
}

// listViewUpdateRow writes all result fields into an existing row.
func listViewUpdateRow(hwnd HWND, row int32, r sweep.Result) {
	if r.Alive {
		setSubItem(hwnd, row, colStatus, "●")
	} else {
		setSubItem(hwnd, row, colStatus, "✕")
		return
	}

	hostname := r.Hostname
	if hostname == "" && r.NetBIOS != "" {
		hostname = r.NetBIOS + " (NetBIOS)"
	}
	if hostname == "" {
		hostname = "—"
	}
	setSubItem(hwnd, row, colHost, hostname)

	mac := "—"
	if r.MAC != nil {
		mac = r.MAC.String()
	}
	setSubItem(hwnd, row, colMAC, mac)

	vendor := r.Vendor
	if vendor == "" {
		vendor = "—"
	}
	setSubItem(hwnd, row, colVendor, vendor)

	osStr := string(r.OS)
	if osStr == "" {
		osStr = "—"
	}
	setSubItem(hwnd, row, colOS, osStr)

	latency := "—"
	if r.Latency > 0 {
		latency = r.Latency.Round(time.Millisecond).String()
	}
	setSubItem(hwnd, row, colLatency, latency)

	portStrs := make([]string, len(r.OpenPorts))
	for i, p := range r.OpenPorts {
		portStrs[i] = fmt.Sprintf("%d", p)
	}
	portStr := "—"
	if len(portStrs) > 0 {
		portStr = strings.Join(portStrs, ", ")
	}
	setSubItem(hwnd, row, colPorts, portStr)

	// Banner column: SSH/HTTP/HTTPS/FTP/SMTP + SNMP identity
	var bannerParts []string
	for _, b := range []struct{ label, val string }{
		{"SSH", r.Banner.SSH}, {"HTTP", r.Banner.HTTP}, {"HTTPS", r.Banner.HTTPS},
		{"FTP", r.Banner.FTP}, {"SMTP", r.Banner.SMTP}, {"Telnet", r.Banner.Telnet},
	} {
		if b.val != "" {
			bannerParts = append(bannerParts, b.label+": "+b.val)
		}
	}
	if r.SNMP != nil {
		snmpStr := r.SNMP.SysDescr
		if r.SNMP.SysName != "" {
			snmpStr = r.SNMP.SysName + ": " + snmpStr
		}
		if snmpStr != "" {
			bannerParts = append(bannerParts, "SNMP: "+snmpStr)
		}
	}
	bannerStr := "—"
	if len(bannerParts) > 0 {
		bannerStr = strings.Join(bannerParts, "  |  ")
	}
	setSubItem(hwnd, row, colBanner, bannerStr)

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
	setSubItem(hwnd, row, colServices, svcStr)
}

// listViewAddMDNSRow appends a single mDNS service entry.
// Columns: IP | Name | Service Type | Friendly Name | Model | Ver | Status | Extra
func listViewAddMDNSRow(hwnd HWND, ip string, svc sweep.ServiceInfo) {
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
	txt := parseTXTMap(svc.Details)
	setSubItem(hwnd, row, 1, svc.Name)
	setSubItem(hwnd, row, 2, svc.Type)
	setSubItem(hwnd, row, 3, txtOr(txt, "fn", ""))
	setSubItem(hwnd, row, 4, txtOr(txt, "md", txtOr(txt, "model", "")))
	setSubItem(hwnd, row, 5, txtOr(txt, "ve", txtOr(txt, "srcvers", "")))
	setSubItem(hwnd, row, 6, txtOr(txt, "st", ""))
	setSubItem(hwnd, row, 7, extraTXT(txt, "fn", "md", "model", "ve", "srcvers", "st",
		"id", "cd", "rm", "nf", "pk", "pi", "psi", "ic", "ca", "bs"))
}

// listViewAddSSDPRow appends a single SSDP entry.
// Columns: IP | Name | Device Type | Location | Server
func listViewAddSSDPRow(hwnd HWND, ip string, svc sweep.ServiceInfo) {
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
	loc := ""
	server := ""
	for _, d := range svc.Details {
		if strings.HasPrefix(d, "location:") {
			loc = strings.TrimPrefix(d, "location:")
		} else if strings.HasPrefix(d, "server:") {
			server = strings.TrimPrefix(d, "server:")
		}
	}
	setSubItem(hwnd, row, 1, svc.Name)
	setSubItem(hwnd, row, 2, svc.Type)
	setSubItem(hwnd, row, 3, loc)
	setSubItem(hwnd, row, 4, server)
}

// parseTXTMap converts a slice of "key=value" TXT records into a lowercase-keyed map.
func parseTXTMap(records []string) map[string]string {
	m := make(map[string]string, len(records))
	for _, r := range records {
		eq := strings.IndexByte(r, '=')
		if eq < 0 {
			continue
		}
		m[strings.ToLower(r[:eq])] = r[eq+1:]
	}
	return m
}

// txtOr returns the value for key from m, or fallback if missing/empty.
func txtOr(m map[string]string, key, fallback string) string {
	if v, ok := m[key]; ok && v != "" {
		return v
	}
	return fallback
}

// extraTXT returns key: value pairs for all keys not in the skip list,
// suppressing opaque hex values.
func extraTXT(m map[string]string, skip ...string) string {
	skipSet := make(map[string]bool, len(skip))
	for _, s := range skip {
		skipSet[s] = true
	}
	var parts []string
	for k, v := range m {
		if skipSet[k] || v == "" || isOpaqueHex(v) {
			continue
		}
		parts = append(parts, k+": "+v)
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, "  ·  ")
}

// isOpaqueHex returns true if v is a pure hex string longer than 8 characters
// (likely a hash, token, or device UUID with no display value).
func isOpaqueHex(v string) bool {
	if len(v) <= 8 {
		return false
	}
	for _, c := range v {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
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

// listViewGetCellText reads the text of a single cell via LVM_GETITEMTEXT.
func listViewGetCellText(hwnd HWND, row, col int32) string {
	buf := make([]uint16, 512)
	item := LVITEM{
		ISubItem: col,
		PszText:  &buf[0],
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
