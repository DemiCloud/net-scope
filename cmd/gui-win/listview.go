//go:build windows

package guiwin

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/demicloud/net-scope/internal/config"
	"github.com/demicloud/net-scope/internal/netinfo"
	"github.com/demicloud/net-scope/internal/scan"
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

// listViewInsertPendingRow appends a row showing ip with a "pending" status placeholder.
// Returns the row index, or -1 on failure.
func listViewInsertPendingRow(hwnd HWND, ip string) int32 {
	statusPtr := utf16("pending")
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
func listViewUpdateRow(hwnd HWND, row int32, r scan.Result) {
	if r.Alive {
		setSubItem(hwnd, row, colStatus, "alive")
	} else {
		setSubItem(hwnd, row, colStatus, "dead")
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

// mdnsBackupEntry is a single mDNS event as received from the network.
type mdnsBackupEntry struct {
	ip  string
	svc scan.ServiceInfo
}

// bcastIPLastSeen records the last time any mDNS/SSDP/WSD packet was observed
// for each IP address. Updated on real events only (not during filter repopulate).
// Used for broadcast host decay colours and the "Last Seen" column.
var bcastIPLastSeen = map[string]time.Time{}

// fmtRelativeAge returns a human-readable relative age string for a timestamp.
// Returns "—" for a zero time value.
func fmtRelativeAge(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := time.Since(t)
	switch {
	case d < 10*time.Second:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
}

// bcastDecayBg returns the COLORREF background colour for a broadcast row.
// Rows with no last-seen time or age < 2 min use the normal alternating pattern.
// 2–5 min → light yellow; 5–15 min → light orange; 15+ min → light red.
// COLORREF encoding: 0x00BBGGRR.
func bcastDecayBg(ip string, row int32) uint32 {
	t, ok := bcastIPLastSeen[ip]
	if !ok {
		return lvRowBg(row)
	}
	switch age := time.Since(t); {
	case age < 2*time.Minute:
		return lvRowBg(row)
	case age < 5*time.Minute:
		return 0x00C8FFFF // light yellow: RGB(255, 255, 200)
	case age < 15*time.Minute:
		return 0x00A0D8FF // light orange: RGB(255, 216, 160)
	default:
		return 0x00BEBEFF // light red:  RGB(255, 190, 190)
	}
}

// refreshBcastLastSeenCols updates the "Last Seen" column text for every row
// in the mDNS, SSDP, and WSD ListViews, then invalidates them so decay colours
// are repainted. Must be called on the UI thread.
func refreshBcastLastSeenCols() {
	for _, pair := range []struct {
		hwnd    HWND
		lastCol int32
	}{
		{hwndListMDNS, int32(len(mdnsColTitles) - 1)},
		{hwndListSSDP, int32(len(ssdpColTitles) - 1)},
		{hwndListWSD, int32(len(wsdColTitles) - 1)},
	} {
		n := int32(sendMessage(pair.hwnd, LVM_GETITEMCOUNT, 0, 0))
		for row := int32(0); row < n; row++ {
			ip := listViewGetCellText(pair.hwnd, row, 0)
			setSubItem(pair.hwnd, row, pair.lastCol, fmtRelativeAge(bcastIPLastSeen[ip]))
		}
		invalidateRect(pair.hwnd, nil, false)
	}
}

var (
	// mdnsRaw stores the original TXT records for each mDNS row so the
	// right-click "Copy raw data" option can reproduce the full record.
	mdnsRaw = map[int32][]string{}

	// mdnsSeen maps a dedup key (ip+type+instance) to the current row index.
	// When the same service is received again (re-announcement or scan mirror),
	// the existing row is updated in-place instead of inserting a duplicate.
	// Reset on repopulate since row indices are reassigned.
	mdnsSeen = map[string]int32{}

	// mdnsBackup holds the latest entry per dedup key, in first-seen order,
	// so that repopulateMDNS can rebuild the listview after a filter change.
	mdnsBackup []mdnsBackupEntry

	// ssdpIPRow maps an IP address to the row index in the SSDP listview.
	// Used to deduplicate: one row per physical device.
	ssdpIPRow = map[string]int32{}

	// ssdpBestST tracks the highest-scoring ST (service type) seen per IP so
	// we only overwrite the Type column when we find something more descriptive.
	ssdpBestST = map[string]string{}

	// ssdpRawData accumulates every raw ServiceInfo received for each IP,
	// used to build the Services column and for "Copy raw data".
	ssdpRawData = map[string][]scan.ServiceInfo{}

	// ssdpOrderedIPs lists SSDP device IPs in first-seen order for
	// deterministic repopulation when the search filter changes.
	ssdpOrderedIPs []string

	// ssdpKnownIPs tracks every SSDP IP ever received regardless of whether
	// it is currently visible in the listview (i.e. filtered out or not).
	ssdpKnownIPs = map[string]bool{}

	// wsdIPRow maps an IP address to the row index in the WSD listview.
	// Used to deduplicate: one row per physical device.
	wsdIPRow = map[string]int32{}

	// wsdRawData accumulates every WSD ServiceInfo received for each IP.
	wsdRawData = map[string][]scan.ServiceInfo{}

	// wsdOrderedIPs lists WSD device IPs in first-seen order.
	wsdOrderedIPs []string

	// wsdKnownIPs tracks every WSD IP ever received regardless of filter.
	wsdKnownIPs = map[string]bool{}

	// inRepopulate is set while a repopulate* function is running so that
	// the listViewAdd* functions skip backing-store appends.
	inRepopulate bool
)

// ---------------------------------------------------------------------------
// mDNS row rendering
// ---------------------------------------------------------------------------

// mdnsRowKey returns the dedup key for a mDNS entry: ip + service type + instance name.
func mdnsRowKey(ip string, svc scan.ServiceInfo) string {
	return ip + "\x00" + svc.Type + "\x00" + svc.Name
}

// listViewAddMDNSRow adds or updates a single mDNS service entry.
// If the same IP + service type + instance was already displayed, the existing
// row is refreshed in-place to avoid duplicates from re-announcements or
// scan-result mirroring. Otherwise a new row is appended.
// Columns: IP | Name | Service | Device/Model | Capabilities | Notes
func listViewAddMDNSRow(hwnd HWND, ip string, svc scan.ServiceInfo) {
	key := mdnsRowKey(ip, svc)

	if !inRepopulate {
		bcastIPLastSeen[ip] = time.Now()

		if existingRow, dup := mdnsSeen[key]; dup {
			// Re-announcement of an already-visible row: replace the backup entry
			// and refresh the row in-place. Scan from the tail since the latest
			// entry for this key is almost always near the end.
			for i := len(mdnsBackup) - 1; i >= 0; i-- {
				if mdnsRowKey(mdnsBackup[i].ip, mdnsBackup[i].svc) == key {
					mdnsBackup[i] = mdnsBackupEntry{ip, svc}
					break
				}
			}
			mdnsPopulateRow(hwnd, existingRow, ip, svc)
			return
		}

		mdnsBackup = append(mdnsBackup, mdnsBackupEntry{ip, svc})
		// Respect the active search filter: skip the listview insert if this
		// entry doesn't match.  It stays in mdnsBackup for later repopulation.
		if f := strings.ToLower(tabSearchFilter[2]); f != "" && !mdnsEntryMatchesFilter(ip, svc, f) {
			return
		}
	}

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
	mdnsSeen[key] = row
	mdnsPopulateRow(hwnd, row, ip, svc)
}

// mdnsPopulateRow writes all non-IP columns for a mDNS row (new insert or in-place update).
func mdnsPopulateRow(hwnd HWND, row int32, ip string, svc scan.ServiceInfo) {
	mdnsRaw[row] = svc.Details // store for "copy raw data"

	txt := parseTXTMap(svc.Details)

	// col 1: instance name with DNS label escapes and RAOP MAC-prefix removed.
	// For Googlecast, the mDNS instance is an opaque UUID; use fn= (friendly name) instead.
	name := mdnsCleanName(svc.Name)
	if svc.Type == "_googlecast._tcp" {
		if fn := txtOr(txt, "fn", ""); fn != "" {
			name = fn
		}
	}
	setSubItem(hwnd, row, 1, name)

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

	// col 6: last broadcast seen (relative age)
	setSubItem(hwnd, row, 6, fmtRelativeAge(bcastIPLastSeen[ip]))
}

// mdnsCleanName removes DNS label backslash escapes and strips the leading
// MAC-address prefix used in RAOP instance names ("AABBCCDDEEFF@Name" → "Name").
func mdnsCleanName(s string) string {
	// Strip RAOP MAC prefix: hex digits (no colons) followed by '@'.
	// Use IndexByte rather than a hard-coded position so varied zeroconf
	// implementations that may return 6–17 char prefixes are handled safely.
	if at := strings.IndexByte(s, '@'); at >= 6 && at <= 17 && at < len(s)-1 {
		allHex := true
		for i := 0; i < at; i++ {
			c := s[i]
			if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
				allHex = false
				break
			}
		}
		if allHex {
			s = s[at+1:]
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
		"ve", "srcvers", "txtvers", "protovers",
		// AirPlay/_airplay._tcp protocol internals — opaque hex, bitmasks, or internal state
		"features", "flags", "rsf", "gcgl", "acl", "fex", "at", "gid", "deviceid",
		"btaddr",  // Bluetooth MAC — internal Apple pairing detail
		"osvers",  // OS version (e.g. tvOS build); no clean label available
		// RAOP/_raop._tcp codec/protocol boilerplate (not useful to display)
		"cn",  // codec numbers (e.g. 0,1,2,3)
		"da",  // digest auth enabled flag
		"et",  // encryption types
		"ft",  // feature flags (hex bitmask pair)
		"ov",  // OS version (same as osvers, used in RAOP)
		"sf",  // status flags bitmask (HAP and RAOP)
		"tp",  // transport (always UDP)
		"vn",  // version integer (65537 = 1.1)
		"vs",  // AirTunes server version string
		"vv",  // AirPlay internal version flag
		"igl", // in-group-lead flag
		// HAP/_hap._tcp pairing internals
		"c#",  // configuration number (internal counter)
		"ci",  // category identifier (HAP device class)
		"s#",  // state number (internal counter)
		"ff",  // feature flags bitmask
		"pv",  // pairing protocol version (boilerplate)
		"sh",  // setup hash (opaque base64 blob)
		// opaque identifiers / binary blobs
		"pdl", "urf", "uuid", "pk", "psi", "ic", "ca", "bs",
		"id", "cd", "rm", "nf", "pi", "st",
	)
}

// mdnsRawClipboardText builds a JSON array of {"ip":"...","data":[...]} objects
// for the selected mDNS rows. Data contains the unmodified TXT record strings
// as received from the host, suitable for debugging or bug reports.
func mdnsRawClipboardText(hwndSrc HWND, rows []int32) string {
	type entry struct {
		IP   string   `json:"ip"`
		Data []string `json:"data"`
	}
	entries := make([]entry, 0, len(rows))
	for _, r := range rows {
		ip := listViewGetCellText(hwndSrc, r, 0)
		records := mdnsRaw[r]
		if records == nil {
			records = []string{}
		}
		entries = append(entries, entry{IP: ip, Data: records})
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
func listViewAddSSDPRow(hwnd HWND, ip string, svc scan.ServiceInfo) {
	// Accumulate raw data (skip during repopulate — data is already present).
	if !inRepopulate {
		ssdpRawData[ip] = append(ssdpRawData[ip], svc)
		bcastIPLastSeen[ip] = time.Now()
	}

	loc, server := "", ""
	for _, d := range svc.Details {
		if strings.HasPrefix(d, "location:") {
			loc = strings.TrimPrefix(d, "location:")
		} else if strings.HasPrefix(d, "server:") {
			server = strings.TrimPrefix(d, "server:")
		}
	}

	if existingRow, ok := ssdpIPRow[ip]; ok {
		// Row is currently visible — update Type column if more descriptive.
		if ssdpDeviceScore(svc.Type) > ssdpDeviceScore(ssdpBestST[ip]) {
			ssdpBestST[ip] = svc.Type
			setSubItem(hwnd, existingRow, 2, ssdpPrettyType(svc.Type))
		}
		// Always rebuild Services column from accumulated data.
		ssdpUpdateServices(hwnd, existingRow, ip)
		return
	}

	// Row not currently visible.
	if ssdpKnownIPs[ip] && !inRepopulate {
		// Known IP that is filtered out — update best-type metadata but
		// do not create a listview row.
		if ssdpDeviceScore(svc.Type) > ssdpDeviceScore(ssdpBestST[ip]) {
			ssdpBestST[ip] = svc.Type
		}
		return
	}

	// New device (or repopulating a cleared listview).
	if !inRepopulate {
		ssdpKnownIPs[ip] = true
		ssdpOrderedIPs = append(ssdpOrderedIPs, ip)
		// Respect the active search filter for newly arriving devices.
		if f := strings.ToLower(tabSearchFilter[3]); f != "" && !ssdpIPMatchesFilter(ip, f) {
			ssdpBestST[ip] = svc.Type // track best type even when filtered out
			return
		}
	}

	ssdpBestST[ip] = svc.Type

	// Insert row.
	ipPtr := utf16(ip)
	item := LVITEM{Mask: LVIF_TEXT, IItem: 0x7fffffff, PszText: ipPtr}
	row := int32(sendMessage(hwnd, LVM_INSERTITEM, 0, uintptr(unsafe.Pointer(&item))))
	if row < 0 {
		return
	}
	ssdpIPRow[ip] = row

	// Server string: trim verbose OS bits after first comma/slash group.
	// "Samsung-Linux/4.1, UPnP/1.0, SmartTV2013" → "Samsung-Linux/4.1 · UPnP/1.0"
	serverDisplay := ssdpCleanServer(server)
	setSubItem(hwnd, row, 1, serverDisplay)
	setSubItem(hwnd, row, 2, ssdpPrettyType(svc.Type))
	ssdpUpdateServices(hwnd, row, ip)
	setSubItem(hwnd, row, 4, loc)
	setSubItem(hwnd, row, 5, fmtRelativeAge(bcastIPLastSeen[ip]))
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
func listViewAddWSDRow(hwnd HWND, ip string, svc scan.ServiceInfo) {
	// Accumulate raw data (skip during repopulate — data is already present).
	if !inRepopulate {
		wsdRawData[ip] = append(wsdRawData[ip], svc)
		bcastIPLastSeen[ip] = time.Now()
	}

	dev := scan.WsdServiceInfoToDevice(svc)
	if existingRow, ok := wsdIPRow[ip]; ok {
		// Row visible — update transport URLs if we have new ones.
		if len(dev.XAddrs) > 0 {
			setSubItem(hwnd, existingRow, 2, strings.Join(dev.XAddrs, "  "))
		}
		return
	}

	// Row not currently visible.
	if wsdKnownIPs[ip] && !inRepopulate {
		// Known IP that is filtered out — nothing to update visually.
		return
	}

	// New device (or repopulating a cleared listview).
	if !inRepopulate {
		wsdKnownIPs[ip] = true
		wsdOrderedIPs = append(wsdOrderedIPs, ip)
		// Respect the active search filter for newly arriving devices.
		if f := strings.ToLower(tabSearchFilter[4]); f != "" && !wsdIPMatchesFilter(ip, f) {
			return
		}
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
	setSubItem(hwnd, row, 5, fmtRelativeAge(bcastIPLastSeen[ip]))
}

// ---------------------------------------------------------------------------
// Search-filter helpers and repopulate functions
// ---------------------------------------------------------------------------

// mdnsEntryMatchesFilter reports whether an mDNS entry matches filter
// (which must already be lower-cased).
func mdnsEntryMatchesFilter(ip string, svc scan.ServiceInfo, filter string) bool {
	return strings.Contains(strings.ToLower(ip), filter) ||
		strings.Contains(strings.ToLower(svc.Name), filter) ||
		strings.Contains(strings.ToLower(svc.Type), filter) ||
		strings.Contains(strings.ToLower(mdnsPrettyType(svc.Type)), filter)
}

// repopulateMDNS clears hwnd and re-inserts mDNS rows matching filter.
// An empty filter restores all rows.
func repopulateMDNS(hwnd HWND, filter string) {
	filter = strings.ToLower(filter)
	sendMessage(hwnd, LVM_DELETEALLITEMS, 0, 0)
	mdnsRaw = map[int32][]string{}  // row indices change — reset
	mdnsSeen = map[string]int32{}   // row indices change — reset
	inRepopulate = true
	defer func() { inRepopulate = false }()
	for _, e := range mdnsBackup {
		if filter != "" && !mdnsEntryMatchesFilter(e.ip, e.svc, filter) {
			continue
		}
		listViewAddMDNSRow(hwnd, e.ip, e.svc)
	}
}

// ssdpIPMatchesFilter reports whether an SSDP IP matches filter (lower-cased).
// Searches the IP and all accumulated raw service data for that IP.
func ssdpIPMatchesFilter(ip, filter string) bool {
	if strings.Contains(strings.ToLower(ip), filter) {
		return true
	}
	for _, svc := range ssdpRawData[ip] {
		if strings.Contains(strings.ToLower(svc.Type), filter) ||
			strings.Contains(strings.ToLower(ssdpPrettyType(svc.Type)), filter) {
			return true
		}
		for _, d := range svc.Details {
			if strings.Contains(strings.ToLower(d), filter) {
				return true
			}
		}
	}
	return false
}

// repopulateSSDP clears hwnd and re-inserts SSDP rows matching filter.
func repopulateSSDP(hwnd HWND, filter string) {
	filter = strings.ToLower(filter)
	sendMessage(hwnd, LVM_DELETEALLITEMS, 0, 0)
	for ip := range ssdpIPRow {
		delete(ssdpIPRow, ip)
	}
	for ip := range ssdpBestST {
		delete(ssdpBestST, ip)
	}
	inRepopulate = true
	defer func() { inRepopulate = false }()
	for _, ip := range ssdpOrderedIPs {
		if filter != "" && !ssdpIPMatchesFilter(ip, filter) {
			continue
		}
		for _, svc := range ssdpRawData[ip] {
			listViewAddSSDPRow(hwnd, ip, svc)
		}
	}
}

// wsdIPMatchesFilter reports whether a WSD IP matches filter (lower-cased).
func wsdIPMatchesFilter(ip, filter string) bool {
	if strings.Contains(strings.ToLower(ip), filter) {
		return true
	}
	for _, svc := range wsdRawData[ip] {
		if strings.Contains(strings.ToLower(svc.Type), filter) {
			return true
		}
		for _, d := range svc.Details {
			if strings.Contains(strings.ToLower(d), filter) {
				return true
			}
		}
	}
	return false
}

// repopulateWSD clears hwnd and re-inserts WSD rows matching filter.
func repopulateWSD(hwnd HWND, filter string) {
	filter = strings.ToLower(filter)
	sendMessage(hwnd, LVM_DELETEALLITEMS, 0, 0)
	for ip := range wsdIPRow {
		delete(wsdIPRow, ip)
	}
	inRepopulate = true
	defer func() { inRepopulate = false }()
	for _, ip := range wsdOrderedIPs {
		if filter != "" && !wsdIPMatchesFilter(ip, filter) {
			continue
		}
		for _, svc := range wsdRawData[ip] {
			listViewAddWSDRow(hwnd, ip, svc)
		}
	}
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
func listViewAddDHCPRow(hwnd HWND, evt netinfo.DHCPEvent) {
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
// suppressing opaque hex/binary values.
func extraTXT(m map[string]string, skip ...string) string {
	skipSet := make(map[string]bool, len(skip))
	for _, s := range skip {
		skipSet[s] = true
	}
	var parts []string
	for k, v := range m {
		if skipSet[k] || v == "" || isOpaqueBlob(v) {
			continue
		}
		parts = append(parts, k+": "+v)
	}
	if len(parts) == 0 {
		return "—"
	}
	sort.Strings(parts)
	return strings.Join(parts, " · ")
}

// isOpaqueBlob returns true if v appears to be an opaque binary value with no
// human-readable meaning — either a long pure-hex string or a base64 blob.
func isOpaqueBlob(v string) bool {
	if len(v) <= 8 {
		return false
	}
	allHex := true
	allB64 := true
	padding := 0
	for i, c := range v {
		isHexChar := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHexChar {
			allHex = false
		}
		isB64Char := isHexChar || (c >= 'g' && c <= 'z') || (c >= 'G' && c <= 'Z') || c == '+' || c == '/'
		if c == '=' {
			// Padding is only valid at the end of a base64 string.
			if i < len(v)-2 {
				allB64 = false
			}
			padding++
		} else if !isB64Char {
			allB64 = false
		}
	}
	if allHex {
		return true
	}
	// Accept as base64 only when it has padding or is long enough to be a hash/token.
	return allB64 && (padding > 0 || len(v) >= 20)
}

// (setSubItem, listViewGetCellText, listViewGetRowTSV, listViewSelectAll,
// listViewGetSelectedRows, listViewFormatTSV/CSV/JSON — moved to fw_listview.go)

// handleCopyAsCmd executes an IDM_COPY_AS_* command for a ListView.
// Returns true if cmd was a recognised copy-as command, false otherwise.
// If rows is empty the copy is skipped silently.
// keyOverrides, when non-nil, supplies explicit JSON keys per column index;
// pass hostsColKeys (or similar) for ListViews whose header text is not suitable
// as a JSON key (e.g. the "●" status column).
func handleCopyAsCmd(parent, hwnd HWND, cmd int32, rows []int32, numCols int32, headers []string, keyOverrides []string) bool {
	if len(rows) == 0 {
		return cmd == IDM_COPY_AS_TSV || cmd == IDM_COPY_AS_CSV || cmd == IDM_COPY_AS_JSON
	}
	switch cmd {
	case IDM_COPY_AS_TSV:
		copyToClipboard(parent, listViewFormatTSV(hwnd, rows, numCols, headers))
	case IDM_COPY_AS_CSV:
		copyToClipboard(parent, listViewFormatCSV(hwnd, rows, numCols, headers))
	case IDM_COPY_AS_JSON:
		copyToClipboard(parent, listViewFormatJSON(hwnd, rows, numCols, headers, keyOverrides))
	default:
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Hosts ListView — sortable columns
// ---------------------------------------------------------------------------

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

// applyHostsSort re-sorts hwndList rows by col/asc, rebuilding ipRowMap and
// rowResultMap. When col < 0 (unsorted), restores natural IP-numeric order.
func applyHostsSort(col int32, asc bool) {
	// Collect results recorded in rowResultMap.
	results := make([]scan.Result, 0, len(rowResultMap))
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

	if col < 0 {
		// Unsorted: restore natural IP-numeric order.
		sort.SliceStable(results, func(i, j int) bool {
			return compareHostResult(results[i], results[j], colIP) < 0
		})
		sort.Strings(pendingIPs)
	} else {
		sort.SliceStable(results, func(i, j int) bool {
			c := compareHostResult(results[i], results[j], col)
			if asc {
				return c < 0
			}
			return c > 0
		})
	}

	// Rebuild the ListView.
	sendMessage(hwndList, LVM_DELETEALLITEMS, 0, 0)
	ipRowMap = make(map[string]int32, len(results)+len(pendingIPs))
	rowResultMap = make(map[int32]scan.Result, len(results))

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
func compareHostResult(a, b scan.Result, col int32) int {
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
	mdnsColTitles = []string{"IP", "Name", "Service", "Device/Model", "Capabilities", "Notes", "Last Seen"}
	mdnsDefWidths = []int32{120, 210, 130, 180, 170, 260, 80}
	mdnsColVis    = []bool{true, true, true, true, true, true, true}

	ssdpColTitles = []string{"IP", "Server", "Type", "Services", "Location", "Last Seen"}
	ssdpDefWidths = []int32{120, 220, 160, 280, 260, 80}
	ssdpColVis    = []bool{true, true, true, true, true, true}

	wsdColTitles = []string{"IP", "Types", "Transport URLs", "Scopes", "Endpoint UUID", "Last Seen"}
	wsdDefWidths = []int32{120, 180, 300, 200, 240, 80}
	wsdColVis    = []bool{true, true, true, true, true, true}

	dhcpColTitles = []string{"Time", "Type", "Client MAC", "Hostname", "Client IP", "Requested IP", "Offered IP", "Server IP"}
	dhcpDefWidths = []int32{75, 90, 140, 160, 120, 120, 120, 120}
	dhcpColVis    = []bool{true, true, true, true, true, true, true, true}
)

// ---------------------------------------------------------------------------
// Per-tab sort-apply callbacks (passed to subclassListViewManaged as onSort)
// ---------------------------------------------------------------------------

// applyMDNSSort sorts the mDNS listview and rebuilds mdnsRaw.
func applyMDNSSort(_ HWND, col int32, asc bool) {
	if col < 0 {
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
	lvTextSort(hwndListMDNS, numCols, col, asc)
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
func applySSDPSort(_ HWND, col int32, asc bool) {
	if col < 0 {
		return
	}
	lvTextSort(hwndListSSDP, int32(len(ssdpColTitles)), col, asc)
	count := int32(sendMessage(hwndListSSDP, LVM_GETITEMCOUNT, 0, 0))
	ssdpIPRow = make(map[string]int32, count)
	for i := int32(0); i < count; i++ {
		ip := listViewGetCellText(hwndListSSDP, i, 0)
		ssdpIPRow[ip] = i
	}
}

// applyWSDSort sorts the WSD listview and rebuilds wsdIPRow.
func applyWSDSort(_ HWND, col int32, asc bool) {
	if col < 0 {
		return
	}
	lvTextSort(hwndListWSD, int32(len(wsdColTitles)), col, asc)
	count := int32(sendMessage(hwndListWSD, LVM_GETITEMCOUNT, 0, 0))
	wsdIPRow = make(map[string]int32, count)
	for i := int32(0); i < count; i++ {
		ip := listViewGetCellText(hwndListWSD, i, 0)
		wsdIPRow[ip] = i
	}
}

// applyDHCPSort sorts the DHCP listview. DHCP rows have no deduplication maps.
func applyDHCPSort(_ HWND, col int32, asc bool) {
	if col < 0 {
		return
	}
	lvTextSort(hwndListDHCP, int32(len(dhcpColTitles)), col, asc)
}

// applySvcTabSort sorts the Services listview and rebuilds svcTabIDToRow and
// svcTabRowEntry so that upsert and double-click remain correct after a sort.
func applySvcTabSort(_ HWND, col int32, asc bool) {
	if col < 0 {
		return
	}
	// Snapshot name+ip → service before row indices change.
	type nameIPKey struct{ name, ip string }
	keyToSvc := make(map[nameIPKey]scan.Service, len(svcTabRowEntry))
	for _, s := range svcTabRowEntry {
		keyToSvc[nameIPKey{svcFriendlyName(s), s.IP}] = s
	}
	lvTextSort(hwndListServices, int32(len(svcTabColTitles)), col, asc)
	count := int32(sendMessage(hwndListServices, LVM_GETITEMCOUNT, 0, 0))
	newIDToRow := make(map[string]int32, count)
	newRowEntry := make(map[int32]scan.Service, count)
	for i := int32(0); i < count; i++ {
		name := listViewGetCellText(hwndListServices, i, 0)
		ip := listViewGetCellText(hwndListServices, i, 1)
		if s, ok := keyToSvc[nameIPKey{name, ip}]; ok {
			newIDToRow[s.ID] = i
			newRowEntry[i] = s
		}
	}
	svcTabIDToRow = newIDToRow
	svcTabRowEntry = newRowEntry
}

// ---------------------------------------------------------------------------
// Column-state persistence (snapshot → State / State → restore)
// ---------------------------------------------------------------------------

// colKeys maps each tab's stable column key (persisted to disk) to its
// column index. Keys are derived from column titles, lowercased and
// whitespace-collapsed; they must never change after release 1.0.
// Separate maps per tab to avoid collisions (e.g. "ip" appears in several).

var hostsColKeys = []string{
	"status",   // colStatus 0
	"ip",       // colIP     1
	"hostname", // colHost   2
	"mac",      // colMAC    3
	"vendor",   // colVendor 4
	"os",       // colOS     5
	"latency",  // colLatency 6
	"ports",    // colPorts  7
	"banner",   // colBanner 8
	"services", // colServices 9
}

var mdnsColKeys = []string{"ip", "name", "service", "device_model", "capabilities", "notes", "last_seen"}
var ssdpColKeys = []string{"ip", "server", "type", "services", "location", "last_seen"}
var wsdColKeys  = []string{"ip", "types", "transport_urls", "scopes", "endpoint_uuid", "last_seen"}
var dhcpColKeys = []string{"time", "type", "client_mac", "hostname", "client_ip", "requested_ip", "offered_ip", "server_ip"}

// snapshotColState builds a TabColumnState for one listview using named column
// keys. Any column key in keys[] becomes a Cols entry. Only called on the UI thread.
func snapshotColState(hwnd HWND, vis []bool, keys []string) config.TabColumnState {
	widths := listViewGetColumnWidths(hwnd, len(keys))
	cols := make(map[string]config.ColumnState, len(keys))
	for i, key := range keys {
		v := i < len(vis) && vis[i]
		w := 0
		if i < len(widths) {
			w = widths[i]
		}
		cols[key] = config.ColumnState{Visible: v, Width: w}
	}
	sortCol, sortAsc := getLVSortState(hwnd)
	var sortColKey *string
	if sortCol >= 0 && sortCol < len(keys) {
		k := keys[sortCol]
		sortColKey = &k
	}
	return config.TabColumnState{
		Cols: cols,
		Sort: config.SortState{Column: sortColKey, Asc: sortAsc},
	}
}

// applyColState restores a TabColumnState onto a listview using named column
// keys. Unknown keys in st are ignored; missing keys keep their current state.
// Only called on the UI thread, after columns have been added.
func applyColState(hwnd HWND, vis []bool, keys []string, colTitles []string, st config.TabColumnState) {
	if len(st.Cols) > 0 {
		for i, key := range keys {
			if i >= len(vis) {
				break
			}
			cs, ok := st.Cols[key]
			if !ok {
				continue // missing key → keep default
			}
			vis[i] = cs.Visible
			w := cs.Width
			if !cs.Visible {
				w = 0
			}
			sendMessage(hwnd, LVM_SETCOLUMNWIDTH, uintptr(i), uintptr(uint32(w)))
		}
	}
	// Restore sort: look up the key → index, then apply.
	sortCol := -1
	if st.Sort.Column != nil {
		for i, key := range keys {
			if key == *st.Sort.Column {
				sortCol = i
				break
			}
		}
	}
	applyLVSortState(hwnd, sortCol, st.Sort.Asc, colTitles)
}

// snapshotAllColumnStates collects column visibility, pixel widths, and sort
// state for every tab that has configurable columns, keyed by stable column names.
func snapshotAllColumnStates() map[string]config.TabColumnState {
	return map[string]config.TabColumnState{
		ViewHosts:    snapshotColState(hwndList, colVisible[:], hostsColKeys),
		ViewMDNS:     snapshotColState(hwndListMDNS, mdnsColVis, mdnsColKeys),
		ViewSSDP:     snapshotColState(hwndListSSDP, ssdpColVis, ssdpColKeys),
		ViewWSD:      snapshotColState(hwndListWSD, wsdColVis, wsdColKeys),
		ViewDHCP:     snapshotColState(hwndListDHCP, dhcpColVis, dhcpColKeys),
		ViewServices: snapshotColState(hwndListServices, svcTabColVis, svcTabColKeys),
	}
}

// restoreAllColumnStates applies persisted column state for every tab.
// Unknown keys in the file are silently ignored; missing tabs keep defaults.
func restoreAllColumnStates(m map[string]config.TabColumnState) {
	if st, ok := m[ViewHosts]; ok {
		applyColState(hwndList, colVisible[:], hostsColKeys, hostsColTitles[:], st)
	}
	if st, ok := m[ViewMDNS]; ok {
		applyColState(hwndListMDNS, mdnsColVis, mdnsColKeys, mdnsColTitles, st)
	}
	if st, ok := m[ViewSSDP]; ok {
		applyColState(hwndListSSDP, ssdpColVis, ssdpColKeys, ssdpColTitles, st)
	}
	if st, ok := m[ViewWSD]; ok {
		applyColState(hwndListWSD, wsdColVis, wsdColKeys, wsdColTitles, st)
	}
	if st, ok := m[ViewDHCP]; ok {
		applyColState(hwndListDHCP, dhcpColVis, dhcpColKeys, dhcpColTitles, st)
	}
	if st, ok := m[ViewServices]; ok {
		applyColState(hwndListServices, svcTabColVis, svcTabColKeys, svcTabColTitles, st)
	}
}

// ---------------------------------------------------------------------------
// Services tab
// ---------------------------------------------------------------------------

// svcTabColTitles are the column headings for the Services tab.
var svcTabColTitles = []string{"Service Name", "IP", "Hostname", "Version", "Port"}

// svcTabDefWidths are the default column widths (logical px).
var svcTabDefWidths = []int32{180, 120, 160, 110, 70}

// svcTabColVis tracks per-column visibility (all visible by default).
var svcTabColVis = []bool{true, true, true, true, true}

// svcTabColKeys are the stable persistence keys for state.json.
// Never rename these.
var svcTabColKeys = []string{"service_name", "ip", "hostname", "version", "port"}

// svcTabData is the ordered backing store for the Services tab.
// Written and read only on the UI thread. Contains unified scan.Service objects
// from the sensor service registry. Never cleared by a scan.
var svcTabData []scan.Service

// svcTabRowEntry maps the current listview row index to the scan.Service it
// represents. Rebuilt whenever the listview is repopulated.
var svcTabRowEntry = map[int32]scan.Service{}

// svcTabIDToRow maps service ID → listview row for O(1) upsert lookups.
var svcTabIDToRow = map[string]int32{}

// svcTabMinConf is the current minimum confidence threshold for banner-detected
// services. Refreshed from appConfig when a scan starts or settings change.
var svcTabMinConf uint8 = 60

// svcEntryDisplayName returns the base service name without host context.
func svcEntryDisplayName(s scan.Service) string {
	if s.Name != "" {
		return s.Name
	}
	if s.Port > 0 {
		return "port/" + strconv.Itoa(s.Port)
	}
	return "—"
}

// svcFriendlyName returns the display name in "service@shortname" format.
// shortname is the first DNS label of the resolved hostname, or the IP.
func svcFriendlyName(s scan.Service) string {
	base := svcEntryDisplayName(s)
	short := s.IP
	if en, ok := hostRegistry[s.IP]; ok {
		if h := en.Result.Hostname; h != "" {
			if dot := strings.IndexByte(h, byte(0x2e)); dot > 0 {
				short = h[:dot]
			} else {
				short = h
			}
		}
	}
	return base + "@" + short
}

// svcEntryVersion returns a display string for the version column.
func svcEntryVersion(s scan.Service) string {
	if s.Version != "" {
		return s.Version
	}
	return "—"
}

// svcEntryPortStr returns a display string for the port / source column.
func svcEntryPortStr(s scan.Service) string {
	if s.Port > 0 {
		return strconv.Itoa(s.Port)
	}
	// Derive source label from the first observation's source.
	for _, obs := range s.Obs {
		return strings.ToUpper(obs.Source) // "BANNER", "MDNS", "SSDP", "WSD"
	}
	return "—"
}

// svcDisplayHostname derives the hostname to show for a service from the
// host registry. Pure read — no mutation.
func svcDisplayHostname(s scan.Service) string {
	if en, ok := hostRegistry[s.IP]; ok {
		if h := en.Result.Hostname; h != "" {
			return h
		}
		if h := en.Result.NetBIOS; h != "" {
			return h + " (NetBIOS)"
		}
	}
	return ""
}

// clearServicesTab removes all rows from the Services listview and resets the
// backing store. Called only on a full session reset.
func clearServicesTab() {
	svcTabData = svcTabData[:0]
	svcTabRowEntry = map[int32]scan.Service{}
	svcTabIDToRow = map[string]int32{}
	sendMessage(hwndListServices, LVM_DELETEALLITEMS, 0, 0)
}

// svcTabInsertRow appends one row to hwndListServices for s.
// Columns: Service Name | IP | Hostname | Version | Port
func svcTabInsertRow(s scan.Service) {
	hn := svcDisplayHostname(s)
	if hn == "" {
		hn = "—"
	}
	row := listViewAppendRow(hwndListServices, []string{
		svcFriendlyName(s),
		s.IP,
		hn,
		svcEntryVersion(s),
		svcEntryPortStr(s),
	})
	if row < 0 {
		return
	}
	svcTabRowEntry[row] = s
	svcTabIDToRow[s.ID] = row
}

// svcTabRefreshRow updates every column of an existing Services tab row in-place.
func svcTabRefreshRow(row int32, s scan.Service) {
	svcTabRowEntry[row] = s
	setSubItem(hwndListServices, row, 0, svcFriendlyName(s))
	setSubItem(hwndListServices, row, 1, s.IP)
	hn := svcDisplayHostname(s)
	if hn == "" {
		hn = "—"
	}
	setSubItem(hwndListServices, row, 2, hn)
	setSubItem(hwndListServices, row, 3, svcEntryVersion(s))
	setSubItem(hwndListServices, row, 4, svcEntryPortStr(s))
}

// servicesTabUpsert inserts or enriches a service in the Services tab.
// If a service with the same ID already has a row, its row is refreshed in-place.
// Discovery-only services (Port == 0) are always shown.
// Port-based services are shown only when Confidence > svcTabMinConf.
// Called on the UI thread from the WM_SVC_UPDATE handler.
func servicesTabUpsert(s scan.Service) {
	// Update backing store (or add if new).
	found := false
	for i := range svcTabData {
		if svcTabData[i].ID == s.ID {
			svcTabData[i] = s
			found = true
			break
		}
	}
	if !found {
		svcTabData = append(svcTabData, s)
	}

	// Apply confidence filter for banner-only services.
	if s.Port > 0 && s.Confidence < svcTabMinConf {
		// Below threshold: store in backing store for View All, but keep hidden
		// in the main listview unless it already has a row (meaning confidence rose).
		if _, exists := svcTabIDToRow[s.ID]; !exists {
			return
		}
		// Confidence may have been boosted by discovery evidence — fall through
		// to update the existing row.
	}

	if row, exists := svcTabIDToRow[s.ID]; exists {
		svcTabRefreshRow(row, s)
	} else {
		svcTabInsertRow(s)
		if len(svcTabIDToRow) == 1 {
			showWindow(hwndServicesPlaceholder, SW_HIDE)
		}
	}
}

// servicesTabUpdateHostname refreshes the Service Name and Hostname columns
// for all rows belonging to ip when a PTR (or NetBIOS) result arrives.
// The friendly name uses @shortname derived from the hostname, so it must
// be re-evaluated here — it was previously stuck at @<ip>.
// Called from WM_HOST_ENRICH on the UI thread.
func servicesTabUpdateHostname(ip string) {
	for row, s := range svcTabRowEntry {
		if s.IP == ip {
			// Name column: friendly name may now have a resolved shortname.
			setSubItem(hwndListServices, row, 0, svcFriendlyName(s))
			// Hostname column.
			hn := svcDisplayHostname(s)
			if hn == "" {
				hn = "—"
			}
			setSubItem(hwndListServices, row, 2, hn)
		}
	}
}

// repopulateServicesTab rebuilds hwndListServices from svcTabData, applying
// filter (case-insensitive substring across service name, IP, hostname, version).
func repopulateServicesTab(filter string) {
	filter = strings.ToLower(filter)
	svcTabRowEntry = map[int32]scan.Service{}
	svcTabIDToRow = map[string]int32{}
	sendMessage(hwndListServices, LVM_DELETEALLITEMS, 0, 0)
	for _, s := range svcTabData {
		if filter != "" && !svcTabEntryMatchesFilter(s, filter) {
			continue
		}
		svcTabInsertRow(s)
	}
}

func svcTabEntryMatchesFilter(s scan.Service, filter string) bool {
	return strings.Contains(strings.ToLower(svcEntryDisplayName(s)), filter) ||
		strings.Contains(strings.ToLower(s.IP), filter) ||
		strings.Contains(strings.ToLower(svcDisplayHostname(s)), filter) ||
		strings.Contains(strings.ToLower(svcEntryVersion(s)), filter) ||
		strings.Contains(strings.ToLower(svcEntryPortStr(s)), filter)
}

// svcDetailSummary formats PortService.Details into a compact one-line string.
// Used by the host detail dialog for the observations section.
func svcDetailSummary(d map[string]string) string {
	if len(d) == 0 {
		return ""
	}
	var parts []string
	if v := d["smb_dialect"]; v != "" {
		s := v
		if d["smb1"] == "true" {
			s += " (v1: on)"
		}
		parts = append(parts, s)
	}
	if v := d["dns_server"]; v != "" {
		parts = append(parts, v)
	} else if d["dns_recursion"] != "" {
		rec := "no"
		if d["dns_recursion"] == "true" {
			rec = "yes"
		}
		parts = append(parts, "recursion: "+rec)
	}
	if v := d["ldap_domain"]; v != "" {
		parts = append(parts, v)
	}
	if v := d["mqtt_anon"]; v != "" {
		parts = append(parts, "anon: "+v)
	}
	return strings.Join(parts, " · ")
}
