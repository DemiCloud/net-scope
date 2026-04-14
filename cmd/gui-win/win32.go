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
	WM_SERVICE_UP    = WM_APP + 6  // sensor service connected and ready
	WM_SERVICE_DOWN  = WM_APP + 7  // sensor service disconnected
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
	WM_ARP_SNAP_ENTRY  = WM_APP + 27 // sensor service: one ARP snapshot entry arrived
	WM_ARP_SNAP_DONE   = WM_APP + 28 // sensor service: ARP snapshot stream complete
	WM_DNS_SNAP_ENTRY  = WM_APP + 29 // sensor service: one DNS cache entry arrived
	WM_DNS_SNAP_DONE   = WM_APP + 30 // sensor service: DNS snapshot stream complete
	WM_CACHE_OP        = WM_APP + 31 // sensor service: cache operation result (arp-delete/clear, dns-delete/clear, route-delete)
	WM_ROUTE_SNAP_ENTRY = WM_APP + 32 // sensor service: one routing-table entry arrived
	WM_ROUTE_SNAP_DONE  = WM_APP + 33 // sensor service: route-snapshot stream complete
	WM_SOCKET_SNAP_ENTRY = WM_APP + 34 // sensor service: one socket entry arrived
	WM_SOCKET_SNAP_DONE  = WM_APP + 35 // sensor service: socket-snapshot stream complete
	WM_HOSTS_SNAP_ENTRY  = WM_APP + 36 // sensor service: one hosts-file entry arrived
	WM_HOSTS_SNAP_DONE   = WM_APP + 37 // sensor service: hosts-snapshot stream complete
	WM_IF_SNAP_ENTRY     = WM_APP + 38 // sensor service: one local-interface entry arrived
	WM_IF_SNAP_DONE      = WM_APP + 39 // sensor service: interface-snapshot stream complete
	WM_PROBE_EVENT       = WM_APP + 40 // probe dialog: streaming text line from a deep probe run
	WM_PROBE_DONE        = WM_APP + 41 // probe dialog: deep probe run finished (wParam = error flag)
	WM_PROBE_HOST        = WM_APP + 42 // probe dialog: successful probe → add IP to Hosts tab
	WM_WOL_RESULT        = WM_APP + 43 // sensor service: Wake-on-LAN send result
	WM_EVT_SNAP_ENTRY    = WM_APP + 44 // sensor service: one event-log entry arrived
	WM_EVT_SNAP_DONE     = WM_APP + 45 // sensor service: event-log snapshot stream complete
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
	IDC_SERVICE_BTN  = 113 // "Elevate Sensor" button
	IDC_LIST_NETWORK    = 114 // Network tab header pane
	IDC_NET_EVENTLOG    = 122 // Network tab event-log ListView
	IDC_DETECT          = 115 // detect local subnet button
	IDC_PROXY_CHECK   = 117 // "Proxy Mode" checkbox in global options bar
	IDC_ACTIVE_ONLY   = 118 // "Active only" checkbox in scan bar
	IDC_SEARCH_EDIT   = 119 // Ctrl+F find bar — text input
	IDC_SEARCH_CLOSE  = 120 // Ctrl+F find bar — "×" dismiss button
	IDC_LIST_SERVICES = 121 // Services tab listview
	IDC_THROTTLE      = 123 // scan throttle preset dropdown in scan bar
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
	IDM_TOOLS_ARP_CACHE       = 218 // Tools > ARP Cache…
	IDM_TOOLS_DNS_CACHE       = 219 // Tools > DNS Cache…
	IDM_TOOLS_ROUTE_TABLE     = 220 // Tools > Route Table…
	IDM_TOOLS_CONNECTIONS     = 221 // Tools > Active Connections…
	IDM_TOOLS_HOSTS           = 222 // Tools > Hosts File…
	IDM_TOOLS_INTERFACES      = 223 // Tools > Local Interfaces…
	IDM_TOOLS_PROBE           = 224 // Tools > Probe…
	IDM_TOOLS_WOL             = 225 // Tools > Wake on LAN…
	IDM_TOOLS_EVENT_LOG       = 226 // Tools > Network Event Log…
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
// Application error codes
// ---------------------------------------------------------------------------

// AppErrCode is a numbered error identifier shown in error dialogs.
// The code appears as "[NS-Exxx]" so users can reference it when reporting
// issues even without a crash log.
type AppErrCode int

const (
	ErrRegisterClass  AppErrCode = 1  // RegisterClassEx failed on startup
	ErrCreateWindow   AppErrCode = 2  // CreateWindowEx failed on startup
	ErrFindExe        AppErrCode = 10 // could not locate own executable
	ErrCreateListener AppErrCode = 11 // could not create TLS service listener
	ErrSendCommand    AppErrCode = 20 // IPC send to sensor service failed
	ErrProxy          AppErrCode = 30 // cannot reach configured proxy
	ErrSaveSettings   AppErrCode = 40 // config file write failed
	ErrCreateFile     AppErrCode = 50 // could not create export file
	ErrExport         AppErrCode = 51 // export write failed
	ErrWriteFile      AppErrCode = 52 // could not write host-detail export file
	ErrCacheOp        AppErrCode = 60 // cache operation (ARP/DNS/route) failed
	ErrCrash          AppErrCode = 90 // unhandled panic / unexpected error
)

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
