//go:build windows

// Application-specific Win32 constants and helpers for NetScope.
//
// Pure Win32 plumbing (types, structs, DLL procs, generic wrappers) lives in
// fw_win32.go.  Only NetScope-specific constants and functions belong here.

package guiwin

import "unsafe"

// ---------------------------------------------------------------------------
// Application message IDs  (WM_APP + N, unique to this process)
// ---------------------------------------------------------------------------

const (
	WM_SCAN_RESULT   = WM_APP + 1  // scan goroutine: single host result ready
	WM_SCAN_COMPLETE = WM_APP + 2  // scan goroutine: scan finished
	WM_SCAN_STATS    = WM_APP + 3  // scan goroutine: progress stats
	WM_BCAST_SVC     = WM_APP + 4  // broadcast listener: ServiceInfo arrived
	WM_FIRST_RUN     = WM_APP + 5  // trigger first-run config-location dialog
	WM_SERVICE_UP    = WM_APP + 6  // scan service connected and ready
	WM_SERVICE_DOWN  = WM_APP + 7  // scan service disconnected
	WM_DHCP_EVENT    = WM_APP + 8  // DHCP packet from elevated service
	WM_HOST_ENRICH   = WM_APP + 9  // background enrichment: NetBIOS / ARP arrived
	WM_PROBE_RESULT  = WM_APP + 10 // host detail dialog: on-demand probe finished
	WM_PROXY_VALID   = WM_APP + 11 // proxy connectivity test succeeded
	WM_PROXY_FAIL    = WM_APP + 12 // proxy connectivity test failed (wParam = error index)
	WM_LISTENER_STATUS = WM_APP + 13 // broadcast listener probe result (wParam = msg index)
	WM_HOST_REFRESH    = WM_APP + 14 // request full host-list repaint (no payload)
	WM_RESOLVE_HOST    = WM_APP + 15 // hostname→IP resolution finished (wParam = index into pendingResolveHosts)
	WM_OUI_FAIL        = WM_APP + 20 // OUI download failed (posted to active databases dialog)
	WM_OUI_SUCCESS     = WM_APP + 21 // OUI download succeeded (posted to active databases dialog)
	WM_HOST_RESCAN     = WM_APP + 22 // host detail dialog: re-scan a single host without clearing the Scanner tab
	WM_SVC_UPDATE      = WM_APP + 23 // sensor service: unified Service registry update (SvcUpdate message)
	WM_WORK_UPDATE     = WM_APP + 24 // sensor service: host probe work-item state change (WorkUpdate message)
	WM_WORKER_STATUS   = WM_APP + 25 // sensor service: named background worker started or stopped
	WM_WORK_EXPIRE     = WM_APP + 26 // timer: remove a finished scan-queue item after its display window
)

// ---------------------------------------------------------------------------
// Timer IDs
// ---------------------------------------------------------------------------

const (
	IDT_DECAY uintptr = 1 // 30-second tick for broadcast host decay colours
)

// ---------------------------------------------------------------------------
// Main-window control IDs
// ---------------------------------------------------------------------------

const (
	IDC_TARGET       = 101
	IDC_SCAN         = 103
	IDC_STOP         = 104 // kept for compat; no longer a visible button
	IDC_LIST         = 105
	IDC_STATUS       = 106
	IDC_TABS         = 107
	IDC_LIST_MDNS    = 108
	IDC_LIST_SSDP    = 110
	IDC_LIST_WSD     = 116
	IDC_LIST_DHCP    = 111
	IDC_ELEV_LABEL   = 112 // service status strip
	IDC_SERVICE_BTN  = 113 // "Elevate scan service" button
	IDC_LIST_NETWORK  = 114 // Network tab text pane
	IDC_DETECT        = 115 // detect local subnet button
	IDC_PROXY_CHECK   = 117 // "Proxy Mode" checkbox in global options bar
	IDC_ACTIVE_ONLY   = 118 // "Active only" checkbox in scan bar
	IDC_SEARCH_EDIT   = 119 // Ctrl+F find bar — text input
	IDC_SEARCH_CLOSE  = 120 // Ctrl+F find bar — "×" dismiss button
	IDC_LIST_SERVICES = 121 // Services tab listview
)

// ---------------------------------------------------------------------------
// Menu command IDs
// ---------------------------------------------------------------------------

const (
	IDM_FILE_EXIT             = 201
	IDM_FILE_EXPORT_JSON      = 205 // File > Export All Hosts as JSON…
	IDM_FILE_EXPORT_CSV       = 206 // File > Export All Hosts as CSV…
	IDM_FILE_EXPORT_SCAN_JSON = 213 // File > Export Current Scan as JSON…
	IDM_FILE_EXPORT_SCAN_CSV  = 214 // File > Export Current Scan as CSV…
	IDM_OPT_SETTINGS          = 202
	IDM_OPT_DATABASES         = 209 // Options > Databases...
	IDM_HOSTS_VIEW_ALL        = 210 // Tools > View All Hosts...
	IDM_HOSTS_VIEW_HOST       = 211 // Tools > Query Host...
	IDM_SERVICES_VIEW_ALL     = 215 // Tools > View All Services…
	IDM_HELP_ABOUT            = 203
	IDM_HELP_FAQ              = 204
	IDM_HELP_VERSION          = 207
	IDM_HELP_CRASHLOG         = 208 // Help > View Crash Log
	IDM_HELP_CONN_HANDLERS    = 212 // Help > Connection Handlers…
	IDM_TOOLS_WORKER_QUEUE    = 216 // Tools > Background Workers…
	IDM_TOOLS_MAC_LOOKUP      = 217 // Tools > MAC Vendor Lookup…
)

// ---------------------------------------------------------------------------
// Context-menu command IDs  (right-click on host row)
// ---------------------------------------------------------------------------

const (
	IDM_CTX_OPEN_HTTP    = 3001
	IDM_CTX_OPEN_HTTPS   = 3002
	IDM_CTX_OPEN_SSH     = 3003
	IDM_CTX_OPEN_RDP     = 3004
	IDM_CTX_OPEN_FTP     = 3005
	IDM_CTX_OPEN_TELNET  = 3006
	IDM_CTX_OPEN_SMB     = 3007
	IDM_CTX_PING         = 3010
	IDM_CTX_PING_CONT    = 3011
	IDM_CTX_COPY_IP      = 3020
	IDM_CTX_COPY_MAC     = 3021
	IDM_CTX_COPY_HOST    = 3022
	IDM_CTX_COPY_ROW     = 3023
	IDM_BCAST_COPY_ROW   = 3030
	IDM_BCAST_COPY_IP    = 3031
	IDM_BCAST_COPY_RAW   = 3032
	IDM_CTX_VIEW_DETAILS = 3040
	IDM_CTX_COPY_ICON    = 3050 // right-click icon in About dialog

	// Base for the detect-subnet popup (up to 16 interfaces supported).
	IDM_DETECT_BASE = 3100

	// "Copy as…" context-menu IDs — used on every list-view tab.
	IDM_COPY_AS_TSV  = 3210 // tab-separated with header row
	IDM_COPY_AS_CSV  = 3211 // RFC 4180 CSV with header row
	IDM_COPY_AS_JSON = 3212 // JSON array of objects

	// Status bar part indices (2 parts: Listener | Service)
	statusPartListener = 0 // passive broadcast listener state
	statusPartService  = 1 // service / elevation state (rightmost, fixed width)

	// Additional button style (plain push, no default border)
	BS_PUSHBUTTON = 0x0000
)

// ---------------------------------------------------------------------------
// Stable view identifiers (used in state.json active_view and column keys)
// ---------------------------------------------------------------------------

// These strings are persisted to disk; do not rename them.
const (
	ViewHosts    = "hosts"
	ViewMDNS     = "mdns"
	ViewSSDP     = "ssdp"
	ViewWSD      = "wsd"
	ViewDHCP     = "dhcp"
	ViewNetwork  = "network"
	ViewHealth   = "health"
	ViewServices = "services"
)

// tabIndexToView maps a tab control index to its stable view identifier.
// Index must be kept in sync with the TCM_INSERTITEM calls in createControls.
var tabIndexToView = []string{
	ViewHosts,    // 0
	ViewServices, // 1
	ViewMDNS,     // 2
	ViewSSDP,     // 3
	ViewWSD,      // 4
	ViewDHCP,     // 5
	ViewNetwork,  // 6
	ViewHealth,   // 7
}

// viewToTabIndex is the reverse map, built once at init time.
var viewToTabIndex map[string]int32

func init() {
	viewToTabIndex = make(map[string]int32, len(tabIndexToView))
	for i, v := range tabIndexToView {
		viewToTabIndex[v] = int32(i)
	}
}

// ---------------------------------------------------------------------------
// Elevation helper
// ---------------------------------------------------------------------------

// isElevated reports whether the current process has administrator privileges.
func isElevated() bool {
	proc, _, _ := procGetCurrentProcess.Call()
	var token uintptr
	r, _, _ := procOpenProcessToken.Call(proc, TOKEN_QUERY, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return false
	}
	defer procCloseHandle.Call(token)

	var elevation uint32
	var retLen uint32
	const tokenElevation = 20 // TokenElevation enum value
	r, _, _ = procGetTokenInformation.Call(
		token,
		tokenElevation,
		uintptr(unsafe.Pointer(&elevation)),
		unsafe.Sizeof(elevation),
		uintptr(unsafe.Pointer(&retLen)),
	)
	return r != 0 && elevation != 0
}
