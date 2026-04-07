//go:build windows

package guiwin

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
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

	// col 1: instance name with DNS label escapes and RAOP MAC-prefix removed
	setSubItem(hwnd, row, 1, mdnsCleanName(svc.Name))

	// col 2: service type prettified ("_ipp._tcp" → "IPP Printer")
	setSubItem(hwnd, row, 2, mdnsPrettyType(svc.Type))

	// col 3: best device/model label.
	// Note: RAOP (_raop._tcp) uses md= for metadata types ("0,1,2"), not model;
	// the correct model key for RAOP/AirPlay devices is am= (Apple model).
	deviceName := txtOr(txt, "fn", txtOr(txt, "ty", txtOr(txt, "am", txtOr(txt, "md", txtOr(txt, "model", "")))))
	device := "—"
	if deviceName != "" {
		mfr := txtOr(txt, "manufacturer", txtOr(txt, "integrator", ""))
		// Only prepend manufacturer when the device name doesn't already start with it.
		if mfr != "" && !strings.HasPrefix(strings.ToLower(deviceName), strings.ToLower(mfr)) {
			device = mfr + " " + deviceName
		} else {
			device = deviceName
		}
	}
	setSubItem(hwnd, row, 3, device)

	// col 4: decoded capabilities (Color · Scan · Duplex · …)
	setSubItem(hwnd, row, 4, mdnsCapabilities(txt))

	// col 5: remaining useful key:value pairs
	setSubItem(hwnd, row, 5, mdnsNotes(txt))
}

// mdnsCleanName removes DNS label backslash escapes and strips the leading
// MAC-address prefix used in RAOP instance names ("AABBCCDDEEFF@Name" → "Name").
func mdnsCleanName(s string) string {
	// Strip RAOP MAC prefix: 12 hex digits followed by '@'.
	if len(s) > 13 && s[12] == '@' {
		allHex := true
		for _, c := range s[:12] {
			if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
				allHex = false
				break
			}
		}
		if allHex {
			s = s[13:]
		}
	}
	// Remove DNS label backslash escapes so "EPSON\ ET-2850" → "EPSON ET-2850".
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
		"fn", "ty", "am", "md", "model", "manufacturer", "integrator", "serialnumber", "fv",
		// decoded into Capabilities column
		"color", "scan", "duplex", "fax", "print_wfds", "mopria-certified",
		// version / protocol boilerplate
		"ve", "srcvers", "txtvers",
		// AirPlay protocol fields — opaque hex or internal protocol state
		"features", "flags", "rsf", "gcgl", "acl", "fex", "at",
		"protovers", "gid", "deviceid",
		// opaque identifiers / binary blobs
		"pdl", "urf", "uuid", "pk", "psi", "ic", "ca", "bs",
		"id", "cd", "rm", "nf", "pi", "st",
	)
}

// mdnsRawClipboardText builds a JSON array of {"ip":"...","data":{...}} objects
// for the selected mDNS rows, for use in "Copy raw data".
func mdnsRawClipboardText(hwndSrc HWND, rows []int32) string {
	type entry struct {
		IP   string            `json:"ip"`
		Data map[string]string `json:"data"`
	}
	entries := make([]entry, 0, len(rows))
	for _, r := range rows {
		ip := listViewGetCellText(hwndSrc, r, 0)
		entries = append(entries, entry{
			IP:   ip,
			Data: parseTXTMap(mdnsRaw[r]),
		})
	}
	b, _ := json.MarshalIndent(entries, "", "    ")
	return string(b)
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

// (setSubItem, listViewGetCellText, listViewGetRowTSV, listViewSelectAll,
// listViewGetSelectedRows, listViewFormatTSV/CSV/JSON — moved to fw_listview.go)

// handleCopyAsCmd executes an IDM_COPY_AS_* command for a ListView.
// Returns true if cmd was a recognised copy-as command, false otherwise.
// If rows is empty the copy is skipped silently.
func handleCopyAsCmd(parent, hwnd HWND, cmd int32, rows []int32, numCols int32, headers []string) bool {
	if len(rows) == 0 {
		return cmd == IDM_COPY_AS_TSV || cmd == IDM_COPY_AS_CSV || cmd == IDM_COPY_AS_JSON
	}
	switch cmd {
	case IDM_COPY_AS_TSV:
		copyToClipboard(parent, listViewFormatTSV(hwnd, rows, numCols, headers))
	case IDM_COPY_AS_CSV:
		copyToClipboard(parent, listViewFormatCSV(hwnd, rows, numCols, headers))
	case IDM_COPY_AS_JSON:
		copyToClipboard(parent, listViewFormatJSON(hwnd, rows, numCols, headers))
	default:
		return false
	}
	return true
}

// appendCopyAsSubmenu appends a "Copy as…" MF_POPUP submenu carrying
// IDM_COPY_AS_TSV / IDM_COPY_AS_CSV / IDM_COPY_AS_JSON to menu.
// The returned HMENU is owned by menu and must not be destroyed separately.
func appendCopyAsSubmenu(menu HMENU) {
	hSub := createPopupMenu()
	appendMenu(hSub, MF_STRING, IDM_COPY_AS_TSV,  "Tab Delimited")
	appendMenu(hSub, MF_STRING, IDM_COPY_AS_CSV,  "CSV")
	appendMenu(hSub, MF_STRING, IDM_COPY_AS_JSON, "JSON")
	appendMenu(menu, MF_POPUP, uintptr(hSub), "Copy as\u2026")
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

// updateSortIndicators refreshes column headers in hwndList to show ▲/▼
// on the current sortCol and plain titles on all others.
func updateSortIndicators() {
	lvUpdateSortIndicators(hwndList, hostsColTitles[:], sortCol, sortAsc)
}

// applyHostsSort re-sorts hwndList rows by sortCol/sortAsc, rebuilding
// ipRowMap and rowResultMap. When sortCol < 0 (unsorted), restores natural
// IP-numeric order (the order results arrive from the scanner).
func applyHostsSort() {
	// Collect results recorded in rowResultMap.
	results := make([]sweep.Result, 0, len(rowResultMap))
	for _, r := range rowResultMap {
		results = append(results, r)
	}

	// Collect pending IPs (inserted but no result yet).
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

	if sortCol < 0 {
		// Unsorted: restore natural IP-numeric order.
		sort.SliceStable(results, func(i, j int) bool {
			return compareHostResult(results[i], results[j], colIP) < 0
		})
		sort.Strings(pendingIPs)
	} else {
		sort.SliceStable(results, func(i, j int) bool {
			c := compareHostResult(results[i], results[j], sortCol)
			if sortAsc {
				return c < 0
			}
			return c > 0
		})
	}

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

// ---------------------------------------------------------------------------
// Hosts ListView — column visibility
// ---------------------------------------------------------------------------

// colDefaultLogicalWidths holds the 96-DPI logical pixel width for each column.
// Must match the widths passed to listViewAddColumn/Fmt in createControls.
var colDefaultLogicalWidths = [10]int32{40, 120, 160, 145, 140, 90, 70, 110, 300, 200}

// colVisible tracks whether each column is visible; all true by default.
var colVisible = [10]bool{true, true, true, true, true, true, true, true, true, true}

// setColumnVisible shows or hides a Hosts-tab column. col 0 (Status) should
// not be hidden. Delegates to the generic framework helper.
func setColumnVisible(col int32, visible bool) {
	setLVColumnVisible(hwndList, colDefaultLogicalWidths[:], colVisible[:], col, visible)
}

// restoreAllColumns resets all Hosts-tab columns to visible at default widths.
func restoreAllColumns() {
	restoreLVColumns(hwndList, colDefaultLogicalWidths[:], colVisible[:])
}

// ---------------------------------------------------------------------------
// Per-tab column definitions (mDNS / SSDP / WSD / DHCP)
// ---------------------------------------------------------------------------

// Column titles — these are the single source of truth: createControls uses
// them for header text, listViewInfoFor uses them for copy-as headers, and the
// Edit Columns dialog uses them for checkbox labels.

var (
	mdnsColTitles = []string{"IP", "Name", "Service", "Device/Model", "Capabilities", "Notes"}
	mdnsDefWidths = []int32{120, 210, 130, 180, 170, 300}
	mdnsColVis    = []bool{true, true, true, true, true, true}
	mdnsSortCol   int32 = -1
	mdnsSortAsc         = true

	ssdpColTitles = []string{"IP", "Server", "Type", "Services", "Location"}
	ssdpDefWidths = []int32{120, 220, 160, 280, 300}
	ssdpColVis    = []bool{true, true, true, true, true}
	ssdpSortCol   int32 = -1
	ssdpSortAsc         = true

	wsdColTitles = []string{"IP", "Types", "Transport URLs", "Scopes", "Endpoint UUID"}
	wsdDefWidths = []int32{120, 180, 300, 200, 280}
	wsdColVis    = []bool{true, true, true, true, true}
	wsdSortCol   int32 = -1
	wsdSortAsc         = true

	dhcpColTitles = []string{"Time", "Type", "Client MAC", "Hostname", "Client IP", "Requested IP", "Offered IP", "Server IP"}
	dhcpDefWidths = []int32{75, 90, 140, 160, 120, 120, 120, 120}
	dhcpColVis    = []bool{true, true, true, true, true, true, true, true}
	dhcpSortCol   int32 = -1
	dhcpSortAsc         = true
)

// ---------------------------------------------------------------------------
// Per-tab sort-apply functions
// ---------------------------------------------------------------------------

// applyMDNSSort sorts the mDNS listview by the current mdnsSortCol/mdnsSortAsc,
// then rebuilds mdnsRaw so that "copy raw data" remains accurate.
func applyMDNSSort() {
	if mdnsSortCol < 0 {
		return
	}
	numCols := int32(len(mdnsColTitles))
	// Snapshot raw data keyed by (IP, instance name) before rows are reordered.
	type rowKey struct{ ip, name string }
	keyedRaw := make(map[rowKey][]string, len(mdnsRaw))
	for row, records := range mdnsRaw {
		ip := listViewGetCellText(hwndListMDNS, row, 0)
		name := listViewGetCellText(hwndListMDNS, row, 1)
		keyedRaw[rowKey{ip, name}] = records
	}
	lvTextSort(hwndListMDNS, numCols, mdnsSortCol, mdnsSortAsc)
	// Rebuild mdnsRaw with new row indices.
	count := int32(sendMessage(hwndListMDNS, LVM_GETITEMCOUNT, 0, 0))
	mdnsRaw = make(map[int32][]string, count)
	for i := int32(0); i < count; i++ {
		ip := listViewGetCellText(hwndListMDNS, i, 0)
		name := listViewGetCellText(hwndListMDNS, i, 1)
		if records, ok := keyedRaw[rowKey{ip, name}]; ok {
			mdnsRaw[i] = records
		}
	}
}

// applySSDPSort sorts the SSDP listview and rebuilds ssdpIPRow.
func applySSDPSort() {
	if ssdpSortCol < 0 {
		return
	}
	lvTextSort(hwndListSSDP, int32(len(ssdpColTitles)), ssdpSortCol, ssdpSortAsc)
	count := int32(sendMessage(hwndListSSDP, LVM_GETITEMCOUNT, 0, 0))
	ssdpIPRow = make(map[string]int32, count)
	for i := int32(0); i < count; i++ {
		ip := listViewGetCellText(hwndListSSDP, i, 0)
		ssdpIPRow[ip] = i
	}
}

// applyWSDSort sorts the WSD listview and rebuilds wsdIPRow.
func applyWSDSort() {
	if wsdSortCol < 0 {
		return
	}
	lvTextSort(hwndListWSD, int32(len(wsdColTitles)), wsdSortCol, wsdSortAsc)
	count := int32(sendMessage(hwndListWSD, LVM_GETITEMCOUNT, 0, 0))
	wsdIPRow = make(map[string]int32, count)
	for i := int32(0); i < count; i++ {
		ip := listViewGetCellText(hwndListWSD, i, 0)
		wsdIPRow[ip] = i
	}
}

// applyDHCPSort sorts the DHCP listview. DHCP rows have no deduplication maps.
func applyDHCPSort() {
	if dhcpSortCol < 0 {
		return
	}
	lvTextSort(hwndListDHCP, int32(len(dhcpColTitles)), dhcpSortCol, dhcpSortAsc)
}

// handleListColumnClick dispatches an LVN_COLUMNCLICK event to the correct
// sort handler. Returns true if the event was consumed.
func handleListColumnClick(idFrom uintptr, col int32) bool {
	switch idFrom {
	case IDC_LIST:
		sortCol, sortAsc = lvNextSortState(sortCol, sortAsc, col)
		updateSortIndicators()
		applyHostsSort()
		return true
	case IDC_LIST_MDNS:
		mdnsSortCol, mdnsSortAsc = lvNextSortState(mdnsSortCol, mdnsSortAsc, col)
		lvUpdateSortIndicators(hwndListMDNS, mdnsColTitles, mdnsSortCol, mdnsSortAsc)
		applyMDNSSort()
		return true
	case IDC_LIST_SSDP:
		ssdpSortCol, ssdpSortAsc = lvNextSortState(ssdpSortCol, ssdpSortAsc, col)
		lvUpdateSortIndicators(hwndListSSDP, ssdpColTitles, ssdpSortCol, ssdpSortAsc)
		applySSDPSort()
		return true
	case IDC_LIST_WSD:
		wsdSortCol, wsdSortAsc = lvNextSortState(wsdSortCol, wsdSortAsc, col)
		lvUpdateSortIndicators(hwndListWSD, wsdColTitles, wsdSortCol, wsdSortAsc)
		applyWSDSort()
		return true
	case IDC_LIST_DHCP:
		dhcpSortCol, dhcpSortAsc = lvNextSortState(dhcpSortCol, dhcpSortAsc, col)
		lvUpdateSortIndicators(hwndListDHCP, dhcpColTitles, dhcpSortCol, dhcpSortAsc)
		applyDHCPSort()
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// lvHeaderInfo maps a listview header HWND to its Edit Columns parameters.
// Built in createControls; consumed by WM_NOTIFY NM_RCLICK on header.
// ---------------------------------------------------------------------------

type lvHeaderInfo struct {
	hwndLV    HWND
	colTitles []string
	colVis    []bool  // slice into the tab's actual visibility array
	defWidths []int32 // 96-DPI logical widths
}

// headerInfos maps each listview's header HWND to its lvHeaderInfo.
var headerInfos = map[HWND]*lvHeaderInfo{}
