//go:build windows

package guiwin

import (
	"fmt"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/demicloud/net-scope/internal/sweep"
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

// ---------------------------------------------------------------------------
// mDNS / SSDP display-layer state
// ---------------------------------------------------------------------------

var (
	// mdnsRaw stores the original TXT records for each mDNS row so the
	// right-click "Copy raw data" option can reproduce the full record.
	mdnsRaw = map[int32][]string{}

	// ssdpIPRow maps an IP address to the row index in the SSDP listview.
	// Used to deduplicate: one row per physical device.
	ssdpIPRow = map[string]int32{}

	// ssdpBestST tracks the highest-scoring ST (service type) seen per IP so
	// we only overwrite the Type column when we find something more descriptive.
	ssdpBestST = map[string]string{}

	// ssdpRawData accumulates every raw ServiceInfo received for each IP,
	// used to build the Services column and for "Copy raw data".
	ssdpRawData = map[string][]sweep.ServiceInfo{}

	// wsdIPRow maps an IP address to the row index in the WSD listview.
	// Used to deduplicate: one row per physical device.
	wsdIPRow = map[string]int32{}

	// wsdRawData accumulates every WSD ServiceInfo received for each IP.
	wsdRawData = map[string][]sweep.ServiceInfo{}
)

// ---------------------------------------------------------------------------
// mDNS row rendering
// ---------------------------------------------------------------------------

// listViewAddMDNSRow appends a single mDNS service entry.
// Columns: IP | Name | Service | Device/Model | Capabilities | Notes
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
	mdnsRaw[row] = svc.Details // store for "copy raw data"

	txt := parseTXTMap(svc.Details)

	// col 1: instance name with DNS label escapes removed
	setSubItem(hwnd, row, 1, mdnsUnescapeName(svc.Name))

	// col 2: service type prettified ("_ipp._tcp" → "IPP Printer")
	setSubItem(hwnd, row, 2, mdnsPrettyType(svc.Type))

	// col 3: best device/model label: fn → ty → md/model
	device := txtOr(txt, "fn", txtOr(txt, "ty", txtOr(txt, "md", txtOr(txt, "model", "—"))))
	setSubItem(hwnd, row, 3, device)

	// col 4: decoded capabilities (Color · Scan · Duplex · …)
	setSubItem(hwnd, row, 4, mdnsCapabilities(txt))

	// col 5: remaining useful key:value pairs
	setSubItem(hwnd, row, 5, mdnsNotes(txt))
}

// mdnsUnescapeName removes DNS label backslash escapes so "EPSON\ ET-2850"
// renders as "EPSON ET-2850".
func mdnsUnescapeName(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i++ // skip backslash, write next byte literally
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

var mdnsPrettyTypes = map[string]string{
	"_http._tcp":        "Web UI",
	"_https._tcp":       "Web UI (HTTPS)",
	"_ssh._tcp":         "SSH",
	"_workstation._tcp": "Workstation",
	"_device-info._tcp": "Device Info",
	"_googlecast._tcp":  "Chromecast",
	"_airplay._tcp":     "AirPlay",
	"_raop._tcp":        "AirPlay Audio",
	"_printer._tcp":     "Printer",
	"_ipp._tcp":         "IPP Printer",
	"_smb._tcp":         "SMB Share",
	"_afp._tcp":         "AFP Share",
	"_nfs._tcp":         "NFS Share",
	"_hap._tcp":         "HomeKit",
}

// mdnsPrettyType returns a human-readable label for a mDNS service type string.
func mdnsPrettyType(serviceType string) string {
	if v, ok := mdnsPrettyTypes[serviceType]; ok {
		return v
	}
	// Generic cleanup: strip leading _ and trailing ._tcp / ._udp.
	s := strings.TrimPrefix(serviceType, "_")
	s = strings.TrimSuffix(s, "._tcp")
	s = strings.TrimSuffix(s, "._udp")
	return s
}

// mdnsCapabilities decodes boolean TXT flags into a human-readable string.
// Returns "—" when no known capabilities are set.
func mdnsCapabilities(txt map[string]string) string {
	var caps []string
	boolOn := func(key, label string) {
		v := strings.ToLower(txt[key])
		if v == "t" || v == "true" || v == "1" || v == "yes" {
			caps = append(caps, label)
		}
	}
	boolOn("color", "Color")
	boolOn("scan", "Scan")
	boolOn("duplex", "Duplex")
	boolOn("fax", "Fax")
	boolOn("print_wfds", "WSD Print")
	if m := txt["mopria-certified"]; m != "" {
		caps = append(caps, "Mopria "+m)
	}
	if len(caps) == 0 {
		return "—"
	}
	return strings.Join(caps, " · ")
}

// mdnsNotes returns the remaining useful TXT key:value pairs that aren't
// already decoded into other columns, skipping opaque/binary values.
func mdnsNotes(txt map[string]string) string {
	return extraTXT(txt,
		// decoded into Device/Model column
		"fn", "ty", "md", "model",
		// decoded into Capabilities column
		"color", "scan", "duplex", "fax", "print_wfds", "mopria-certified",
		// version / protocol boilerplate
		"ve", "srcvers", "txtvers",
		// opaque identifiers / binary blobs
		"pdl", "urf", "uuid", "pk", "psi", "ic", "ca", "bs",
		"id", "cd", "rm", "nf", "pi", "st",
	)
}

// getMDNSRawText returns a human-readable dump of the raw TXT records stored
// for row, for use in "Copy raw data".
func getMDNSRawText(row int32) string {
	records, ok := mdnsRaw[row]
	if !ok || len(records) == 0 {
		return "(no TXT records)"
	}
	return strings.Join(records, "\n")
}

// ---------------------------------------------------------------------------
// SSDP row rendering (one row per physical device / IP address)
// ---------------------------------------------------------------------------

// listViewAddSSDPRow merges an incoming SSDP service announcement into the
// SSDP listview.  Repeated announcements from the same IP are collapsed into
// a single row; the Type and Services columns are updated as more information
// arrives.  Columns: IP | Server | Type | Services | Location
func listViewAddSSDPRow(hwnd HWND, ip string, svc sweep.ServiceInfo) {
	// Always accumulate raw data so "copy raw data" is complete.
	ssdpRawData[ip] = append(ssdpRawData[ip], svc)

	loc, server := "", ""
	for _, d := range svc.Details {
		if strings.HasPrefix(d, "location:") {
			loc = strings.TrimPrefix(d, "location:")
		} else if strings.HasPrefix(d, "server:") {
			server = strings.TrimPrefix(d, "server:")
		}
	}

	if existingRow, ok := ssdpIPRow[ip]; ok {
		// Row already exists — update Type column if this entry is more descriptive.
		if ssdpDeviceScore(svc.Type) > ssdpDeviceScore(ssdpBestST[ip]) {
			ssdpBestST[ip] = svc.Type
			setSubItem(hwnd, existingRow, 2, ssdpPrettyType(svc.Type))
		}
		// Always rebuild Services column from accumulated data.
		ssdpUpdateServices(hwnd, existingRow, ip)
		return
	}

	// New device — insert row.
	ipPtr := utf16(ip)
	item := LVITEM{Mask: LVIF_TEXT, IItem: 0x7fffffff, PszText: ipPtr}
	row := int32(sendMessage(hwnd, LVM_INSERTITEM, 0, uintptr(unsafe.Pointer(&item))))
	if row < 0 {
		return
	}
	ssdpIPRow[ip] = row
	ssdpBestST[ip] = svc.Type

	// Server string: trim verbose OS bits after first comma/slash group.
	// "Samsung-Linux/4.1, UPnP/1.0, SmartTV2013" → "Samsung-Linux/4.1 · UPnP/1.0"
	serverDisplay := ssdpCleanServer(server)
	setSubItem(hwnd, row, 1, serverDisplay)
	setSubItem(hwnd, row, 2, ssdpPrettyType(svc.Type))
	ssdpUpdateServices(hwnd, row, ip)
	setSubItem(hwnd, row, 4, loc)
}

// ssdpUpdateServices rebuilds the Services column for a row from accumulated data.
func ssdpUpdateServices(hwnd HWND, row int32, ip string) {
	seen := map[string]bool{}
	var names []string
	for _, s := range ssdpRawData[ip] {
		if name := ssdpServiceName(s.Type); name != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	switch {
	case len(names) == 0:
		setSubItem(hwnd, row, 3, "—")
	case len(names) <= 3:
		setSubItem(hwnd, row, 3, strings.Join(names, ", "))
	default:
		setSubItem(hwnd, row, 3, strings.Join(names[:3], ", ")+fmt.Sprintf(" (+%d)", len(names)-3))
	}
}

// ssdpCleanServer formats a UPnP Server header for display.
// "Samsung-Linux/4.1, UPnP/1.0, SmartTV2013" → "Samsung-Linux/4.1 · UPnP/1.0"
func ssdpCleanServer(s string) string {
	parts := strings.SplitN(s, ", ", 3)
	if len(parts) >= 2 {
		return parts[0] + " · " + parts[1]
	}
	return s
}

// ssdpPrettyType converts a UPnP ST header value to a human-readable label.
// Service types (urn:…:service:…) return empty string — they are listed in
// the Services column instead.
func ssdpPrettyType(st string) string {
	switch st {
	case "upnp:rootdevice":
		return "UPnP Device"
	case "ssdp:all", "":
		return "—"
	}
	if strings.HasPrefix(st, "uuid:") {
		return "—"
	}
	if strings.Contains(st, ":device:") {
		parts := strings.Split(st, ":")
		for i, p := range parts {
			if p == "device" && i+1 < len(parts) {
				return camelToWords(parts[i+1])
			}
		}
	}
	if strings.Contains(st, ":service:") {
		return "" // service URNs go in the Services column, not Type
	}
	return st
}

// ssdpServiceName extracts the service name from a UPnP service URN.
// Returns "" for non-service ST values.
func ssdpServiceName(st string) string {
	if !strings.Contains(st, ":service:") {
		return ""
	}
	parts := strings.Split(st, ":")
	for i, p := range parts {
		if p == "service" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// ssdpDeviceScore returns a priority score for an ST value.
// Higher = more descriptive; used to pick the best entry for the Type column.
func ssdpDeviceScore(st string) int {
	switch {
	case st == "" || strings.HasPrefix(st, "uuid:") || st == "ssdp:all":
		return 0
	case strings.Contains(st, ":service:"):
		return 1
	case st == "upnp:rootdevice":
		return 2
	case strings.Contains(st, ":device:"):
		return 3
	default:
		return 1
	}
}

// camelToWords inserts spaces before uppercase letters in a CamelCase string.
func camelToWords(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 4)
	for i, c := range s {
		if i > 0 && c >= 'A' && c <= 'Z' {
			b.WriteByte(' ')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// getSSDPRawText formats all accumulated raw SSDP entries for ip as a
// multi-line string suitable for clipboard copy.
func getSSDPRawText(ip string) string {
	svcs, ok := ssdpRawData[ip]
	if !ok || len(svcs) == 0 {
		return "(no data)"
	}
	var b strings.Builder
	for _, s := range svcs {
		b.WriteString("ST: ")
		b.WriteString(s.Type)
		b.WriteByte('\n')
		for _, d := range s.Details {
			b.WriteString(d)
			b.WriteByte('\n')
		}
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}



// listViewAddWSDRow appends a single WS-Discovery device entry, deduplicating
// by IP. Columns: IP | Types | Transport URLs | Scopes | Endpoint UUID
func listViewAddWSDRow(hwnd HWND, ip string, svc sweep.ServiceInfo) {
	wsdRawData[ip] = append(wsdRawData[ip], svc)

	dev := sweep.WsdServiceInfoToDevice(svc)
	if existingRow, ok := wsdIPRow[ip]; ok {
		if len(dev.XAddrs) > 0 {
			setSubItem(hwnd, existingRow, 2, strings.Join(dev.XAddrs, "  "))
		}
		return
	}

	ipPtr := utf16(ip)
	item := LVITEM{Mask: LVIF_TEXT, IItem: 0x7fffffff, PszText: ipPtr}
	row := int32(sendMessage(hwnd, LVM_INSERTITEM, 0, uintptr(unsafe.Pointer(&item))))
	if row < 0 {
		return
	}
	wsdIPRow[ip] = row
	setSubItem(hwnd, row, 1, dev.FriendlyTypes())
	xaddrs := strings.Join(dev.XAddrs, "  ")
	if xaddrs == "" {
		xaddrs = "—"
	}
	setSubItem(hwnd, row, 2, xaddrs)
	scopes := dev.FriendlyScopes()
	if scopes == "" {
		scopes = "—"
	}
	setSubItem(hwnd, row, 3, scopes)
	ep := strings.TrimPrefix(dev.EndpointAddr, "urn:uuid:")
	if ep == "" {
		ep = "—"
	}
	setSubItem(hwnd, row, 4, ep)
}

// getWSDRawText formats all accumulated WSD raw data for ip for clipboard copy.
func getWSDRawText(ip string) string {
	svcs, ok := wsdRawData[ip]
	if !ok || len(svcs) == 0 {
		return "(no data)"
	}
	var b strings.Builder
	for _, s := range svcs {
		b.WriteString("Type: ")
		b.WriteString(s.Type)
		b.WriteByte('\n')
		for _, d := range s.Details {
			b.WriteString(d)
			b.WriteByte('\n')
		}
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}



// Columns: Time | Type | Client MAC | Hostname | Client IP | Requested IP | Offered IP | Server IP
func listViewAddDHCPRow(hwnd HWND, evt sweep.DHCPEvent) {
	ts := evt.Time.Format("15:04:05")
	tsPtr := utf16(ts)
	item := LVITEM{Mask: LVIF_TEXT, IItem: 0x7fffffff, PszText: tsPtr}
	row := int32(sendMessage(hwnd, LVM_INSERTITEM, 0, uintptr(unsafe.Pointer(&item))))
	if row < 0 {
		return
	}
	setSubItem(hwnd, row, 1, evt.Type.String())
	setSubItem(hwnd, row, 2, evt.ClientMAC)
	host := evt.Hostname
	if host == "" {
		host = "—"
	}
	setSubItem(hwnd, row, 3, host)
	ip := evt.ClientIP
	if ip == "" {
		ip = "—"
	}
	setSubItem(hwnd, row, 4, ip)
	req := evt.RequestedIP
	if req == "" {
		req = "—"
	}
	setSubItem(hwnd, row, 5, req)
	offered := evt.OfferedIP
	if offered == "" {
		offered = "—"
	}
	setSubItem(hwnd, row, 6, offered)
	srv := evt.ServerIP
	if srv == "" {
		srv = "—"
	}
	setSubItem(hwnd, row, 7, srv)
}


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

// ---------------------------------------------------------------------------
// Hosts ListView — sortable columns
// ---------------------------------------------------------------------------

// sortCol is the column currently sorted (-1 = no sort applied).
// sortAsc is true for ascending, false for descending.
var (
	sortCol int32 = -1
	sortAsc bool  = true
)

// hostsColTitles holds the canonical (indicator-free) header text per column,
// indexed by the colXxx constants defined above.
var hostsColTitles = [10]string{
	"●",              // colStatus   0
	"IP Address",     // colIP       1
	"Hostname",       // colHost     2
	"MAC",            // colMAC      3
	"Vendor",         // colVendor   4
	"OS",             // colOS       5
	"Latency",        // colLatency  6
	"Ports",          // colPorts    7
	"Banners / SNMP", // colBanner   8
	"Services",       // colServices 9
}

// listViewSetColumnHeader updates the header text for a single column.
func listViewSetColumnHeader(hwnd HWND, idx int32, title string) {
	col := LVCOLUMN{
		Mask:    LVCF_TEXT,
		PszText: utf16(title),
	}
	sendMessage(hwnd, LVM_SETCOLUMN, uintptr(idx), uintptr(unsafe.Pointer(&col)))
}

// updateSortIndicators refreshes all column headers in hwndList to show ▲/▼
// on the current sortCol and plain titles on all others.
func updateSortIndicators() {
	for i, title := range hostsColTitles {
		h := title
		if int32(i) == sortCol {
			if sortAsc {
				h = title + " ▲"
			} else {
				h = title + " ▼"
			}
		}
		listViewSetColumnHeader(hwndList, int32(i), h)
	}
}

// applyHostsSort re-sorts hwndList rows by sortCol/sortAsc, rebuilding
// ipRowMap and rowResultMap. No-op if sortCol < 0.
func applyHostsSort() {
	if sortCol < 0 {
		return
	}

	// Collect results (alive rows recorded in rowResultMap).
	results := make([]sweep.Result, 0, len(rowResultMap))
	for _, r := range rowResultMap {
		results = append(results, r)
	}

	// Collect pending IPs (inserted but no result yet — still scanning or dead).
	resultIPs := make(map[string]bool, len(results))
	for _, r := range results {
		resultIPs[r.IP.String()] = true
	}
	pendingIPs := make([]string, 0)
	for ip := range ipRowMap {
		if !resultIPs[ip] {
			pendingIPs = append(pendingIPs, ip)
		}
	}

	sort.SliceStable(results, func(i, j int) bool {
		c := compareHostResult(results[i], results[j], sortCol)
		if sortAsc {
			return c < 0
		}
		return c > 0
	})

	// Rebuild the ListView.
	sendMessage(hwndList, LVM_DELETEALLITEMS, 0, 0)
	ipRowMap = make(map[string]int32, len(results)+len(pendingIPs))
	rowResultMap = make(map[int32]sweep.Result, len(results))

	for _, r := range results {
		ip := r.IP.String()
		row := listViewInsertPendingRow(hwndList, ip)
		ipRowMap[ip] = row
		listViewUpdateRow(hwndList, row, r)
		rowResultMap[row] = r
	}
	for _, ip := range pendingIPs {
		row := listViewInsertPendingRow(hwndList, ip)
		ipRowMap[ip] = row
	}
}

// compareHostResult compares two Results by column col.
// Returns negative if a < b, positive if a > b, 0 if equal.
// Empty/dash values always sort last (after real values) in ascending order.
func compareHostResult(a, b sweep.Result, col int32) int {
	switch col {
	case colStatus:
		// Alive first.
		if a.Alive == b.Alive {
			return 0
		}
		if a.Alive {
			return -1
		}
		return 1

	case colIP:
		ai := a.IP.To4()
		bi := b.IP.To4()
		if ai == nil || bi == nil {
			return strings.Compare(a.IP.String(), b.IP.String())
		}
		for k := 0; k < 4; k++ {
			if ai[k] != bi[k] {
				if ai[k] < bi[k] {
					return -1
				}
				return 1
			}
		}
		return 0

	case colHost:
		ha, hb := a.Hostname, b.Hostname
		if ha == "" {
			ha = a.NetBIOS
		}
		if hb == "" {
			hb = b.NetBIOS
		}
		return cmpStrDash(ha, hb)

	case colMAC:
		ma, mb := "", ""
		if a.MAC != nil {
			ma = a.MAC.String()
		}
		if b.MAC != nil {
			mb = b.MAC.String()
		}
		return cmpStrDash(ma, mb)

	case colVendor:
		return cmpStrDash(a.Vendor, b.Vendor)

	case colOS:
		return cmpStrDash(string(a.OS), string(b.OS))

	case colLatency:
		if a.Latency == b.Latency {
			return 0
		}
		// Zero latency (unknown) sorts last.
		if a.Latency == 0 {
			return 1
		}
		if b.Latency == 0 {
			return -1
		}
		if a.Latency < b.Latency {
			return -1
		}
		return 1

	case colPorts:
		if len(a.OpenPorts) == len(b.OpenPorts) {
			return 0
		}
		if len(a.OpenPorts) < len(b.OpenPorts) {
			return -1
		}
		return 1
	}
	// colBanner, colServices — no structural comparison; preserve insertion order.
	return 0
}

// cmpStrDash compares two strings case-insensitively, treating empty strings
// as greater than all real values so unknowns sort last ascending.
func cmpStrDash(a, b string) int {
	emptyA := a == ""
	emptyB := b == ""
	if emptyA && emptyB {
		return 0
	}
	if emptyA {
		return 1
	}
	if emptyB {
		return -1
	}
	return strings.Compare(strings.ToLower(a), strings.ToLower(b))
}
