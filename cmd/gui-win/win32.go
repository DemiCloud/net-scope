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
	WM_FP_RESULT     = WM_APP + 13 // fingerprint dialog: scan complete
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
)

// ---------------------------------------------------------------------------
// Menu command IDs
// ---------------------------------------------------------------------------

const (
	IDM_FILE_EXIT        = 201
	IDM_FILE_EXPORT_JSON = 205
	IDM_FILE_EXPORT_CSV  = 206
	IDM_OPT_SETTINGS     = 202
	IDM_OPT_DATABASES    = 209 // Options > Databases...
	IDM_HOSTS_VIEW_ALL   = 210 // Tools > View All Hosts...
	IDM_HOSTS_VIEW_HOST  = 211 // Tools > Query Host...
	IDM_TOOLS_FINGERPRINT = 213 // Tools > Fingerprint Host...
	IDM_HELP_ABOUT          = 203
	IDM_HELP_FAQ            = 204
	IDM_HELP_VERSION        = 207
	IDM_HELP_CRASHLOG       = 208 // Help > View Crash Log
	IDM_HELP_CONN_HANDLERS  = 212 // Help > Connection Handlers…
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

	// Header right-click menu
	IDM_HEADER_EDIT_COLS = 3200

	// "Copy as…" context-menu IDs — used on every list-view tab.
	IDM_COPY_AS_TSV  = 3210 // tab-separated with header row
	IDM_COPY_AS_CSV  = 3211 // RFC 4180 CSV with header row
	IDM_COPY_AS_JSON = 3212 // JSON array of objects

	// Edit Columns dialog control IDs
	IDC_EDITCOLS_OK      = 451
	IDC_EDITCOLS_CANCEL  = 452
	IDC_EDITCOLS_RESTORE = 453
	// Checkbox IDs: IDC_EDITCOLS_COL_BASE + col, for col 1..9
	IDC_EDITCOLS_COL_BASE = 460

	// Status bar part indices
	statusPartHosts   = 0 // "Ready" / "Hosts: N found"
	statusPartScan    = 1 // scan state / progress
	statusPartService = 2 // service / elevation state (rightmost, fixed width)

	// Additional button style (plain push, no default border)
	BS_PUSHBUTTON = 0x0000
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
