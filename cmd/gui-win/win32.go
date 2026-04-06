//go:build windows

package guiwin

import (
	"syscall"
	"unsafe"
)

// ---------------------------------------------------------------------------
// Handle types
// ---------------------------------------------------------------------------

type (
	HWND      uintptr
	HINSTANCE uintptr
	HMENU     uintptr
	HBRUSH    uintptr
	HCURSOR   uintptr
	HICON     uintptr
	HANDLE    uintptr
	HFONT     uintptr
	HGDIOBJ   uintptr
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	// Window styles
	WS_OVERLAPPED       = 0x00000000
	WS_CAPTION          = 0x00C00000
	WS_SYSMENU          = 0x00080000
	WS_THICKFRAME       = 0x00040000
	WS_MINIMIZEBOX      = 0x00020000
	WS_MAXIMIZEBOX      = 0x00010000
	WS_OVERLAPPEDWINDOW = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX
	WS_CHILD            = 0x40000000
	WS_VISIBLE          = 0x10000000
	WS_VSCROLL          = 0x00200000
	WS_BORDER           = 0x00800000
	WS_TABSTOP          = 0x00010000

	// Class styles
	CS_HREDRAW = 0x0002
	CS_VREDRAW = 0x0001

	// Edit styles
	ES_AUTOHSCROLL = 0x0080
	ES_MULTILINE   = 0x0004
	ES_AUTOVSCROLL = 0x0040
	ES_READONLY    = 0x0800

	// Static styles
	SS_LEFT        = 0x0000
	SS_CENTER      = 0x0001 // horizontally centered text
	SS_CENTERIMAGE = 0x0200

	// Button styles / messages
	BS_DEFPUSHBUTTON = 0x0001
	BS_AUTOCHECKBOX  = 0x0003
	BM_GETCHECK     = 0x00F0
	BM_SETCHECK     = 0x00F1
	BST_UNCHECKED   = 0
	BST_CHECKED     = 1

	// System
	CW_USEDEFAULT = ^int32(0x7fffffff) // 0x80000000
	SW_SHOWNORMAL = 1
	COLOR_WINDOW  = 5
	COLOR_BTNFACE = 15 // system dialog/button background (light gray)

	// Messages
	WM_CREATE      = 0x0001
	WM_DESTROY     = 0x0002
	WM_SIZE        = 0x0005
	WM_CLOSE       = 0x0010
	WM_KEYDOWN     = 0x0100
	WM_COMMAND     = 0x0111
	WM_DPICHANGED  = 0x02E0 // sent when window moves to a different-DPI monitor
	WM_APP         = 0x8000

	// DPI awareness context value for Per-Monitor V2 (Windows 10 1703+)
	// Passed to SetProcessDpiAwarenessContext as a pseudo-handle.
	DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = ^uintptr(3) // -4

	// SetWindowPos flags
	SWP_NOZORDER   = 0x0004
	SWP_NOACTIVATE = 0x0010

	// Custom messages
	WM_SCAN_RESULT   = WM_APP + 1
	WM_SCAN_COMPLETE = WM_APP + 2
	WM_SCAN_STATS    = WM_APP + 3
	WM_BCAST_SVC     = WM_APP + 4 // background broadcast: single ServiceInfo arrived
	WM_FIRST_RUN     = WM_APP + 5 // posted to trigger first-run settings dialog
	WM_SERVICE_UP    = WM_APP + 6 // sweep service connected and ready
	WM_SERVICE_DOWN  = WM_APP + 7 // sweep service disconnected
	WM_DHCP_EVENT    = WM_APP + 8 // DHCP packet observed by elevated service
	WM_HOST_ENRICH   = WM_APP + 9 // background enrichment: NetBIOS name or ARP MAC arrived
	WM_PROBE_RESULT  = WM_APP + 10 // host detail dialog: on-demand probe finished

	// Control IDs
	IDC_TARGET       = 101
	IDC_SCAN         = 103
	IDC_STOP         = 104 // kept for compat; no longer a visible button
	IDC_LIST         = 105
	IDC_STATUS       = 106
	IDC_TABS         = 107
	IDC_LIST_MDNS    = 108
	IDC_LIST_SSDP    = 110
	IDC_LIST_WSD     = 116 // WS-Discovery tab
	IDC_LIST_DHCP    = 111
	IDC_ELEV_LABEL   = 112 // service status label
	IDC_SERVICE_BTN  = 113 // "Elevate sweep service" button
	IDC_LIST_NETWORK = 114 // Network tab — live broadcast stats text pane
	IDC_DETECT       = 115 // "⟲" detect local subnet button

	// Menu command IDs
	IDM_FILE_EXIT        = 201
	IDM_FILE_EXPORT_JSON = 205
	IDM_FILE_EXPORT_CSV  = 206
	IDM_OPT_SETTINGS     = 202
	IDM_OPT_DATABASES    = 209 // Options > Databases…
	IDM_HOSTS_VIEW_ALL  = 210 // Hosts > View All Hosts…
	IDM_HOSTS_VIEW_HOST = 211 // Hosts > View Host…
	IDM_HELP_ABOUT       = 203
	IDM_HELP_FAQ         = 204
	IDM_HELP_VERSION     = 207
	IDM_HELP_CRASHLOG    = 208 // Help > View Crash Log

	// Context menu command ID range (right-click actions)
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
	// Host detail dialog
	IDM_CTX_VIEW_DETAILS = 3040

	// Detect-subnet popup menu item base (up to 16 interfaces supported)
	IDM_DETECT_BASE = 3100

	// Null message (used to wake up a modal message loop)
	WM_NULL = 0x0000

	// MessageBox flags and return values
	MB_OK          = 0x00000000
	MB_YESNO       = 0x00000004
	MB_ICONWARNING  = 0x00000030
	MB_ICONQUESTION = 0x00000020
	MB_ICONERROR    = 0x00000010

	IDYES = 6
	IDNO  = 7

	// Owner-draw / custom-draw
	// NM_CUSTOMDRAW = NM_FIRST(0) - 12 = -12 = 0xFFFFFFF4
	NM_CUSTOMDRAW    = uint32(0xFFFFFFF4)
	CDDS_PREPAINT    = 0x00000001
	CDDS_ITEMPREPAINT = 0x00010001
	CDDS_SUBITEM     = 0x00020000 // OR'd with CDDS_ITEMPREPAINT for per-subitem notifications
	CDRF_DODEFAULT   = 0x00000000
	CDRF_NOTIFYITEMDRAW = 0x00000020 // also CDRF_NOTIFYSUBITEMDRAW — same value
	CDRF_NEWFONT     = 0x00000002

	// WM_CTLCOLORSTATIC — sent by a STATIC (or read-only EDIT) to its parent
	// before painting; parent returns an HBRUSH and can set text/background colours.
	WM_CTLCOLORSTATIC = 0x0138

	// ComboBox window class and styles
	CBS_SIMPLE       = 0x0001 // always-open list
	CBS_DROPDOWN     = 0x0002 // editable text + drop-down list
	CBS_DROPDOWNLIST = 0x0003 // non-editable (fixed choices)
	CBS_AUTOHSCROLL  = 0x0040 // auto-scroll the edit field horizontally
	CBS_SORT         = 0x0100 // sort list items alphabetically

	// ComboBox messages
	CB_ADDSTRING      = 0x0143
	CB_RESETCONTENT   = 0x014B
	CB_GETCURSEL      = 0x0147
	CB_GETLBTEXT      = 0x0148
	CB_GETLBTEXTLEN   = 0x0149
	CB_SETCURSEL      = 0x014E
	CB_FINDSTRINGEXACT = 0x0158

	// ComboBox notification (HIWORD of wParam in WM_COMMAND)
	CBN_SELCHANGE = 1

	// GDI
	SRCCOPY      = 0x00CC0020
	TRANSPARENT  = 1
	OPAQUE       = 2

	// File open dialog (GetSaveFileName)
	OFN_OVERWRITEPROMPT = 0x00000002
	OFN_PATHMUSTEXIST   = 0x00000800

	// Token access
	TOKEN_QUERY = 0x0008

	// System cursors / icons
	IDC_ARROW = 32512

	// Common controls init flags
	ICC_LISTVIEW_CLASSES = 0x00000001
	ICC_BAR_CLASSES      = 0x00000004

	// ListView window class and styles
	WC_LISTVIEW      = "SysListView32"
	LVS_REPORT        = 0x0001
	LVS_SINGLESEL     = 0x0004
	LVS_SHOWSELALWAYS = 0x0008

	// ListView extended styles
	LVS_EX_FULLROWSELECT = 0x00000020
	LVS_EX_GRIDLINES     = 0x00000001
	LVS_EX_DOUBLEBUFFER  = 0x00010000

	// ListView messages — always use the W (Unicode) variants.
	// The ANSI variants (+6, +7) interpret pszText as single-byte and will
	// truncate UTF-16 strings to their first byte (e.g. "10.x.x.x" → "1").
	LVM_FIRST                    = 0x1000
	LVM_INSERTCOLUMN             = LVM_FIRST + 97 // LVM_INSERTCOLUMNW
	LVM_INSERTITEM               = LVM_FIRST + 77 // LVM_INSERTITEMW  (NOT +7 which is ANSI)
	LVM_SETITEM                  = LVM_FIRST + 76 // LVM_SETITEMW     (NOT +6 which is ANSI)
	LVM_DELETEALLITEMS           = LVM_FIRST + 9  // no ANSI/W split
	LVM_SETEXTENDEDLISTVIEWSTYLE = LVM_FIRST + 54 // no ANSI/W split
	LVM_HITTEST                  = LVM_FIRST + 18 // hit-test (no ANSI/W split)
	LVM_GETITEMTEXT              = LVM_FIRST + 115 // LVM_GETITEMTEXTW
	LVM_GETNEXTITEM              = LVM_FIRST + 12  // find next item matching flags
	LVNI_SELECTED                = 0x0002          // only selected items
	// LVCOLUMN flags
	LVCF_FMT   = 0x0001
	LVCF_WIDTH = 0x0002
	LVCF_TEXT  = 0x0004
	LVCFMT_LEFT   = 0
	LVCFMT_RIGHT  = 1
	LVCFMT_CENTER = 2

	// LVITEM flags
	LVIF_TEXT = 0x0001

	// StatusBar messages
	SB_SETTEXT  = 0x040B // SB_SETTEXTW — Unicode; lParam = *uint16
	SB_SETPARTS = 0x0404

	// Button notification
	BN_CLICKED = 0

	// Edit messages
	EM_SETSEL = 0x00B1

	// Virtual keys
	VK_CONTROL = 0x11
	VK_RETURN  = 0x0D
	VK_ESCAPE  = 0x1B
	VK_KEY_A   = 0x41

	// Tab control
	WC_TABCONTROL   = "SysTabControl32"
	TCS_FLATBUTTONS = 0x0008 // flat push-button tabs (more modern)
	TCM_FIRST       = 0x1300
	TCM_INSERTITEM = TCM_FIRST + 62 // TCM_INSERTITEMW
	TCM_GETCURSEL  = TCM_FIRST + 11
	TCM_ADJUSTRECT = TCM_FIRST + 40
	TCIF_TEXT      = 0x0001

	// WM_NOTIFY and tab notifications
	WM_NOTIFY     = 0x004E
	TCN_SELCHANGE = 0xFFFFFDD9 // (uint32)(-551)

	// Menu flags
	MF_STRING    = 0x00000000
	MF_POPUP     = 0x00000010
	MF_SEPARATOR = 0x00000800
	MF_GRAYED    = 0x00000001
	MF_ENABLED   = 0x00000000

	// Track popup menu flags
	TPM_LEFTALIGN    = 0x0000
	TPM_TOPALIGN     = 0x0000
	TPM_RETURNCMD    = 0x0100

	// NM_RCLICK notification: NM_FIRST(0) - 5 = -5 = 0xFFFFFFFB
	NM_RCLICK  = uint32(0xFFFFFFFB)
	// NM_DBLCLK: NM_FIRST(0) - 3 = -3 = 0xFFFFFFFD
	NM_DBLCLK  = uint32(0xFFFFFFFD)

	// Window styles (popup dialogs)
	WS_POPUP        = 0x80000000
	WS_CLIPCHILDREN = 0x02000000

	// Extended window styles
	WS_EX_DLGMODALFRAME = 0x00000001
	WS_EX_CLIENTEDGE    = 0x00000200
	WS_EX_TOPMOST       = 0x00000008

	// ShowWindow extras
	SW_SHOW = 5
	SW_HIDE = 0

	// Font / GDI
	WM_SETFONT       = 0x0030
	FW_NORMAL        = 400
	CLEARTYPE_QUALITY = 5

	// Icon IDs (for LoadIconW with NULL hInstance)
	IDI_APPLICATION = 32512

	// LoadImage / CreateIconFromResourceEx flags
	LR_DEFAULTCOLOR = 0x00000000
)

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

type WNDCLASSEX struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     HINSTANCE
	HIcon         HICON
	HCursor       HCURSOR
	HbrBackground HBRUSH
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       HICON
}

type MSG struct {
	HWnd    HWND
	Message uint32
	_       [4]byte // pad to align WParam on x64
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      POINT
}

type POINT struct {
	X, Y int32
}

// NMHDR is the header common to all WM_NOTIFY messages.
type NMHDR struct {
	HwndFrom uintptr
	IdFrom   uintptr
	Code     uint32
	_        [4]byte // trailing pad
}

// TCITEM is used to insert/query tab control items.
// Fields after the three uint32s get 4-byte padding before the pointer (x64).
type TCITEM struct {
	Mask        uint32
	DwState     uint32
	DwStateMask uint32
	PszText     *uint16 // offset 16 after compiler padding
	CchTextMax  int32
	IImage      int32
	LParam      uintptr
}

type RECT struct {
	Left, Top, Right, Bottom int32
}

type INITCOMMONCONTROLSEX struct {
	DwSize uint32
	DwICC  uint32
}

type LVCOLUMN struct {
	Mask       uint32
	Fmt        int32
	Cx         int32
	PszText    *uint16
	CchTextMax int32
	ISubItem   int32
	IImage     int32
	IOrder     int32
}

type LVITEM struct {
	Mask       uint32
	IItem      int32
	ISubItem   int32
	State      uint32
	StateMask  uint32
	PszText    *uint16
	CchTextMax int32
	IImage     int32
	LParam     uintptr
}

// NMLVCUSTOMDRAW is the structure sent with NM_CUSTOMDRAW for list views.
// Layout: NMHDR (20 bytes) + NMCUSTOMDRAW fields + clrText + clrTextBk + iSubItem + dwItemType + clrFace + ...
// We only need the parts up to clrTextBk.
type NMLVCUSTOMDRAW struct {
	Hdr         NMHDR
	DwDrawStage uint32
	Hdc         uintptr
	Rc          RECT
	DwItemSpec  uintptr
	UItemState  uint32
	_           [4]byte // pad
	LItemlParam uintptr
	ClrText     uint32
	ClrTextBk   uint32
	ISubItem    int32
}

// ---------------------------------------------------------------------------
// DLL references
// ---------------------------------------------------------------------------

var (
	modUser32   = syscall.NewLazyDLL("user32.dll")
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")
	modComctl32 = syscall.NewLazyDLL("comctl32.dll")

	procRegisterClassExW        = modUser32.NewProc("RegisterClassExW")
	procCreateWindowExW         = modUser32.NewProc("CreateWindowExW")
	procDefWindowProcW          = modUser32.NewProc("DefWindowProcW")
	procGetMessageW             = modUser32.NewProc("GetMessageW")
	procTranslateMessage        = modUser32.NewProc("TranslateMessage")
	procDispatchMessageW        = modUser32.NewProc("DispatchMessageW")
	procPostQuitMessage         = modUser32.NewProc("PostQuitMessage")
	procLoadCursorW             = modUser32.NewProc("LoadCursorW")
	procShowWindow              = modUser32.NewProc("ShowWindow")
	procUpdateWindow            = modUser32.NewProc("UpdateWindow")
	procGetClientRect           = modUser32.NewProc("GetClientRect")
	procMoveWindow              = modUser32.NewProc("MoveWindow")
	procSendMessageW            = modUser32.NewProc("SendMessageW")
	procPostMessageW            = modUser32.NewProc("PostMessageW")
	procGetWindowTextLengthW    = modUser32.NewProc("GetWindowTextLengthW")
	procGetWindowTextW          = modUser32.NewProc("GetWindowTextW")
	procSetWindowTextW          = modUser32.NewProc("SetWindowTextW")
	procEnableWindow            = modUser32.NewProc("EnableWindow")
	procMessageBoxW             = modUser32.NewProc("MessageBoxW")
	procGetKeyState             = modUser32.NewProc("GetKeyState")
	procSetWindowPos            = modUser32.NewProc("SetWindowPos")
	procSetProcessDpiAwarenessContext = modUser32.NewProc("SetProcessDpiAwarenessContext")
	procGetDpiForWindow         = modUser32.NewProc("GetDpiForWindow")
	procGetDpiForSystem         = modUser32.NewProc("GetDpiForSystem")

	// Menu
	procCreateMenu              = modUser32.NewProc("CreateMenu")
	procCreatePopupMenu         = modUser32.NewProc("CreatePopupMenu")
	procAppendMenuW             = modUser32.NewProc("AppendMenuW")
	procSetMenu                 = modUser32.NewProc("SetMenu")
	procDrawMenuBar             = modUser32.NewProc("DrawMenuBar")

	// Shell (open files/URLs)
	modShell32          = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW   = modShell32.NewProc("ShellExecuteW")

	// Context / tracked popup menus
	procTrackPopupMenu  = modUser32.NewProc("TrackPopupMenu")
	procGetCursorPos    = modUser32.NewProc("GetCursorPos")
	procDestroyMenu     = modUser32.NewProc("DestroyMenu")
	procScreenToClient  = modUser32.NewProc("ScreenToClient")
	procGetFocus        = modUser32.NewProc("GetFocus")

	// GDI32
	modGdi32               = syscall.NewLazyDLL("gdi32.dll")
	procCreateFontW        = modGdi32.NewProc("CreateFontW")
	procCreateSolidBrush   = modGdi32.NewProc("CreateSolidBrush")
	procDeleteObject       = modGdi32.NewProc("DeleteObject")
	procSetBkColor         = modGdi32.NewProc("SetBkColor")
	procSetTextColor       = modGdi32.NewProc("SetTextColor")
	procSetBkMode          = modGdi32.NewProc("SetBkMode")

	// GetSysColorBrush returns a cached system-color brush; do not DeleteObject it.
	procGetSysColorBrush = modUser32.NewProc("GetSysColorBrush")

	// Comdlg32 (save file dialog)
	modComdlg32             = syscall.NewLazyDLL("comdlg32.dll")
	procGetSaveFileNameW    = modComdlg32.NewProc("GetSaveFileNameW")

	// Clipboard
	procOpenClipboard    = modUser32.NewProc("OpenClipboard")
	procCloseClipboard   = modUser32.NewProc("CloseClipboard")
	procEmptyClipboard   = modUser32.NewProc("EmptyClipboard")
	procSetClipboardData = modUser32.NewProc("SetClipboardData")
	procGlobalAlloc      = modKernel32.NewProc("GlobalAlloc")
	procGlobalLock       = modKernel32.NewProc("GlobalLock")
	procGlobalUnlock     = modKernel32.NewProc("GlobalUnlock")
	procRtlMoveMemory    = modKernel32.NewProc("RtlMoveMemory")

	// Advapi32 (token/elevation)
	modAdvapi32             = syscall.NewLazyDLL("advapi32.dll")
	procOpenProcessToken    = modAdvapi32.NewProc("OpenProcessToken")
	procGetTokenInformation = modAdvapi32.NewProc("GetTokenInformation")

	procGetModuleHandleW  = modKernel32.NewProc("GetModuleHandleW")
	procGetCurrentProcess = modKernel32.NewProc("GetCurrentProcess")
	procCloseHandle       = modKernel32.NewProc("CloseHandle")

	procEnumChildWindows         = modUser32.NewProc("EnumChildWindows")
	procLoadIconW                = modUser32.NewProc("LoadIconW")
	procCreateIconFromResourceEx = modUser32.NewProc("CreateIconFromResourceEx")
	procGetWindowRect            = modUser32.NewProc("GetWindowRect")
	procDestroyWindow            = modUser32.NewProc("DestroyWindow")
	procSetForegroundWindow      = modUser32.NewProc("SetForegroundWindow")
	procSetFocus                 = modUser32.NewProc("SetFocus")
	procIsWindow                 = modUser32.NewProc("IsWindow")
	procIsChild                  = modUser32.NewProc("IsChild")
	procGetConsoleWindow         = modKernel32.NewProc("GetConsoleWindow")

	procInitCommonControlsEx    = modComctl32.NewProc("InitCommonControlsEx")
	procCreateStatusWindowW     = modComctl32.NewProc("CreateStatusWindowW")
)

// ---------------------------------------------------------------------------
// Wrappers
// ---------------------------------------------------------------------------

func registerClassEx(wc *WNDCLASSEX) (uint16, error) {
	r, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(wc)))
	if r == 0 {
		return 0, err
	}
	return uint16(r), nil
}

func createWindowEx(exStyle uint32, className, title string, style uint32, x, y, w, h int32, parent HWND, menu HMENU, inst HINSTANCE) (HWND, error) {
	cn, _ := syscall.UTF16PtrFromString(className)
	tn, _ := syscall.UTF16PtrFromString(title)
	r, _, err := procCreateWindowExW.Call(
		uintptr(exStyle),
		uintptr(unsafe.Pointer(cn)),
		uintptr(unsafe.Pointer(tn)),
		uintptr(style),
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		uintptr(parent),
		uintptr(menu),
		uintptr(inst),
		0,
	)
	if r == 0 {
		return 0, err
	}
	return HWND(r), nil
}

func defWindowProc(hwnd HWND, msg uint32, wParam, lParam uintptr) uintptr {
	r, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return r
}

func getMessage(msg *MSG) bool {
	r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(msg)), 0, 0, 0)
	return int32(r) != 0
}

func translateMessage(msg *MSG) {
	procTranslateMessage.Call(uintptr(unsafe.Pointer(msg)))
}

func dispatchMessage(msg *MSG) {
	procDispatchMessageW.Call(uintptr(unsafe.Pointer(msg)))
}

func postQuitMessage(code int32) {
	procPostQuitMessage.Call(uintptr(code))
}

func loadCursor(name uintptr) HCURSOR {
	r, _, _ := procLoadCursorW.Call(0, name)
	return HCURSOR(r)
}

func showWindow(hwnd HWND, cmd int32) {
	procShowWindow.Call(uintptr(hwnd), uintptr(cmd))
}

func updateWindow(hwnd HWND) {
	procUpdateWindow.Call(uintptr(hwnd))
}

func getClientRect(hwnd HWND) RECT {
	var r RECT
	procGetClientRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&r)))
	return r
}

func moveWindow(hwnd HWND, x, y, w, h int32) {
	procMoveWindow.Call(uintptr(hwnd), uintptr(x), uintptr(y), uintptr(w), uintptr(h), 1)
}

func sendMessage(hwnd HWND, msg uint32, wParam, lParam uintptr) uintptr {
	r, _, _ := procSendMessageW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return r
}

func postMessage(hwnd HWND, msg uint32, wParam, lParam uintptr) {
	procPostMessageW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
}

func getWindowText(hwnd HWND) string {
	n, _, _ := procGetWindowTextLengthW.Call(uintptr(hwnd))
	if n == 0 {
		return ""
	}
	buf := make([]uint16, n+1)
	procGetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&buf[0])), n+1)
	return syscall.UTF16ToString(buf)
}

func setWindowText(hwnd HWND, s string) {
	p, _ := syscall.UTF16PtrFromString(s)
	procSetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(p)))
}

func enableWindow(hwnd HWND, enable bool) {
	v := uintptr(0)
	if enable {
		v = 1
	}
	procEnableWindow.Call(uintptr(hwnd), v)
}

func messageBox(hwnd HWND, text, caption string, flags uint32) int32 {
	t, _ := syscall.UTF16PtrFromString(text)
	c, _ := syscall.UTF16PtrFromString(caption)
	r, _, _ := procMessageBoxW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), uintptr(flags))
	return int32(r)
}

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

func getModuleHandle() HINSTANCE {
	r, _, _ := procGetModuleHandleW.Call(0)
	return HINSTANCE(r)
}

func initCommonControls() {
	ice := INITCOMMONCONTROLSEX{
		DwSize: uint32(unsafe.Sizeof(INITCOMMONCONTROLSEX{})),
		DwICC:  ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES,
	}
	procInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&ice)))
}

func createStatusWindow(parent HWND, id uintptr, text string) HWND {
	t, _ := syscall.UTF16PtrFromString(text)
	r, _, _ := procCreateStatusWindowW.Call(
		WS_CHILD|WS_VISIBLE,
		uintptr(unsafe.Pointer(t)),
		uintptr(parent),
		id,
	)
	return HWND(r)
}

// getKeyState returns true if the given virtual key is currently held down.
func getKeyState(vk uintptr) bool {
	r, _, _ := procGetKeyState.Call(vk)
	// High bit of the int16 result means key is down.
	return uint16(r)&0x8000 != 0
}

func getWindowRect(hwnd HWND) RECT {
	var r RECT
	procGetWindowRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&r)))
	return r
}

func destroyWindow(hwnd HWND) {
	procDestroyWindow.Call(uintptr(hwnd))
}

// centerOnParent repositions dlg so it is centered over parent on screen.
func centerOnParent(dlg, parent HWND, w, h int32) {
	pr := getWindowRect(parent)
	x := (pr.Left + pr.Right - w) / 2
	y := (pr.Top + pr.Bottom - h) / 2
	moveWindow(dlg, x, y, w, h)
}

func utf16(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func hiword(x uintptr) int32 { return int32(x >> 16) }
func loword(x uintptr) int32 { return int32(x & 0xFFFF) }

func createMenu() HMENU {
	r, _, _ := procCreateMenu.Call()
	return HMENU(r)
}

func createPopupMenu() HMENU {
	r, _, _ := procCreatePopupMenu.Call()
	return HMENU(r)
}

// appendMenu adds an item to menu. For MF_POPUP, pass uintptr(subMenuHandle) as id.
// For MF_STRING, pass the command ID as id.
func appendMenu(menu HMENU, flags uint32, id uintptr, text string) {
	t, _ := syscall.UTF16PtrFromString(text)
	procAppendMenuW.Call(uintptr(menu), uintptr(flags), id, uintptr(unsafe.Pointer(t)))
}

func setMenu(hwnd HWND, menu HMENU) {
	procSetMenu.Call(uintptr(hwnd), uintptr(menu))
}

func drawMenuBar(hwnd HWND) {
	procDrawMenuBar.Call(uintptr(hwnd))
}

// trackPopupMenu displays a context menu at (x,y) in screen coordinates.
// If TPM_RETURNCMD is set, returns the selected command ID (0 = cancelled).
func trackPopupMenu(menu HMENU, flags uint32, x, y int32, hwnd HWND) int32 {
	r, _, _ := procTrackPopupMenu.Call(
		uintptr(menu), uintptr(flags),
		uintptr(x), uintptr(y),
		0, uintptr(hwnd), 0,
	)
	return int32(r)
}

// getCursorPos fills pt with the current cursor screen position.
func getCursorPos() POINT {
	var pt POINT
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	return pt
}

// destroyMenu frees a menu created with createPopupMenu.
func destroyMenu(menu HMENU) {
	procDestroyMenu.Call(uintptr(menu))
}

// getFocus returns the HWND of the currently focused control (0 if none).
func getFocus() HWND {
	r, _, _ := procGetFocus.Call()
	return HWND(r)
}

// shellExecute opens a file or URL using the shell. Use op="open", SW_SHOW for show.
func shellExecute(hwnd HWND, op, file, params, dir string, show int32) {
	opPtr, _ := syscall.UTF16PtrFromString(op)
	filePtr, _ := syscall.UTF16PtrFromString(file)
	var paramsPtr *uint16
	if params != "" {
		paramsPtr, _ = syscall.UTF16PtrFromString(params)
	}
	var dirPtr *uint16
	if dir != "" {
		dirPtr, _ = syscall.UTF16PtrFromString(dir)
	}
	procShellExecuteW.Call(
		uintptr(hwnd),
		uintptr(unsafe.Pointer(opPtr)),
		uintptr(unsafe.Pointer(filePtr)),
		uintptr(unsafe.Pointer(paramsPtr)),
		uintptr(unsafe.Pointer(dirPtr)),
		uintptr(show),
	)
}

// setProcessDpiAwarenessContext enables Per-Monitor V2 DPI awareness.
// Must be called before any window is created.
func setProcessDpiAwarenessContext(ctx uintptr) {
	procSetProcessDpiAwarenessContext.Call(ctx)
}

// getDpiForWindow returns the DPI for the monitor containing hwnd (0 on error).
func getDpiForWindow(hwnd HWND) uint32 {
	r, _, _ := procGetDpiForWindow.Call(uintptr(hwnd))
	return uint32(r)
}

// getDpiForSystem returns the system DPI (useful before any window is created).
func getDpiForSystem() uint32 {
	r, _, _ := procGetDpiForSystem.Call()
	if r == 0 {
		return 96
	}
	return uint32(r)
}

// setWindowPos repositions and resizes hwnd. Use SWP_NOZORDER|SWP_NOACTIVATE
// for a non-intrusive move/resize (e.g. on WM_DPICHANGED).
func setWindowPos(hwnd HWND, hwndInsertAfter uintptr, x, y, w, h int32, flags uint32) {
	procSetWindowPos.Call(uintptr(hwnd), hwndInsertAfter,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h), uintptr(flags))
}

// createUIFont creates a Segoe UI Variable Text font scaled to the given DPI.
// "Segoe UI Variable Text" is the Win11 system text font; Windows falls back
// to "Segoe UI" on Win10 and earlier.  10pt at 96 DPI = -13px.
func createUIFont(dpi uint32) HFONT {
	face, _ := syscall.UTF16PtrFromString("Segoe UI Variable Text")
	// Negative height = character height. 10pt at 96 DPI = -13px.
	height := -int32(13 * dpi / 96)
	r, _, _ := procCreateFontW.Call(
		uintptr(height),
		0,                           // average char width (0 = auto)
		0,                           // escapement
		0,                           // orientation
		FW_NORMAL,                   // weight
		0,                           // italic
		0,                           // underline
		0,                           // strikeout
		0,                           // charset  (ANSI_CHARSET)
		0,                           // out precision
		0,                           // clip precision
		CLEARTYPE_QUALITY,           // quality — enables ClearType rendering
		0,                           // pitch and family
		uintptr(unsafe.Pointer(face)),
	)
	return HFONT(r)
}

// setFontAllChildren sends WM_SETFONT to every descendant of parent.
func setFontAllChildren(parent HWND, font HFONT) {
	cb := syscall.NewCallback(func(hwnd, lParam uintptr) uintptr {
		sendMessage(HWND(hwnd), WM_SETFONT, lParam, 1)
		return 1 // continue enumeration
	})
	procEnumChildWindows.Call(uintptr(parent), cb, uintptr(font))
}

// loadSystemIcon loads one of the built-in Windows icons (e.g. IDI_APPLICATION).
func loadSystemIcon(id uintptr) HICON {
	r, _, _ := procLoadIconW.Call(0, id)
	return HICON(r)
}

// insertTab adds a tab item at index idx in a SysTabControl32.
func insertTab(hwnd HWND, idx int32, text string) {
	textPtr, _ := syscall.UTF16PtrFromString(text)
	item := TCITEM{
		Mask:    TCIF_TEXT,
		PszText: textPtr,
	}
	sendMessage(hwnd, TCM_INSERTITEM, uintptr(idx), uintptr(unsafe.Pointer(&item)))
	_ = textPtr // keep alive through syscall
}

// createSolidBrush creates a GDI brush for the given COLORREF (0x00BBGGRR).
func createSolidBrush(color uint32) HBRUSH {
	r, _, _ := procCreateSolidBrush.Call(uintptr(color))
	return HBRUSH(r)
}

// deleteObject releases a GDI object (brush, pen, font, bitmap, …).
func deleteObject(obj uintptr) {
	procDeleteObject.Call(obj)
}

// setTextColor sets the foreground colour for text on hdc. Returns old value.
func setTextColor(hdc uintptr, color uint32) uint32 {
	r, _, _ := procSetTextColor.Call(hdc, uintptr(color))
	return uint32(r)
}

// setBkColor sets the background colour for text on hdc. Returns old value.
func setBkColor(hdc uintptr, color uint32) uint32 {
	r, _, _ := procSetBkColor.Call(hdc, uintptr(color))
	return uint32(r)
}

// setBkMode sets the background mix mode (TRANSPARENT=1, OPAQUE=2).
func setBkMode(hdc uintptr, mode int32) {
	procSetBkMode.Call(hdc, uintptr(mode))
}

// getSysColorBrush returns a cached system-color brush for colorIndex (e.g.
// COLOR_BTNFACE).  The returned brush is owned by the system — do NOT call
// deleteObject on it.
func getSysColorBrush(colorIndex int) HBRUSH {
	r, _, _ := procGetSysColorBrush.Call(uintptr(colorIndex))
	return HBRUSH(r)
}

// LVHITTESTINFO is passed to LVM_HITTEST to find which item is at a given point
// (in list-view client coordinates).
type LVHITTESTINFO struct {
	Pt       POINT
	Flags    uint32
	IItem    int32
	ISubItem int32
	IGroup   int32
}

// OPENFILENAME is the structure passed to GetSaveFileNameW.
// Only the fields we use are populated; the rest stay zero.
type OPENFILENAME struct {
	LStructSize     uint32
	HwndOwner       HWND
	_               uintptr // hInstance
	LpstrFilter     *uint16
	LpstrCustomFilter *uint16
	NMaxCustFilter  uint32
	NFilterIndex    uint32
	LpstrFile       *uint16
	NMaxFile        uint32
	LpstrFileTitle  *uint16
	NMaxFileTitle   uint32
	LpstrInitialDir *uint16
	LpstrTitle      *uint16
	Flags           uint32
	NFileOffset     uint16
	NFileExtension  uint16
	LpstrDefExt     *uint16
	LCustData       uintptr
	LpfnHook        uintptr
	LpTemplateName  *uint16
	PvReserved      uintptr
	DwReserved      uint32
	FlagsEx         uint32
}

// getSaveFileName shows a "Save As" dialog. Returns the chosen path or "".
func getSaveFileName(owner HWND, title, defExt, filter string) string {
	buf := make([]uint16, 1024)
	titlePtr, _ := syscall.UTF16PtrFromString(title)
	extPtr, _ := syscall.UTF16PtrFromString(defExt)
	// filter is double-null-terminated: "JSON files\0*.json\0\0"
	filterRunes := syscall.StringToUTF16(filter)
	// Replace | with null byte (caller uses | as separator)
	for i, c := range filterRunes {
		if c == '|' {
			filterRunes[i] = 0
		}
	}

	ofn := OPENFILENAME{
		LStructSize: uint32(unsafe.Sizeof(OPENFILENAME{})),
		HwndOwner:   owner,
		LpstrFilter: &filterRunes[0],
		LpstrFile:   &buf[0],
		NMaxFile:    uint32(len(buf)),
		LpstrTitle:  titlePtr,
		LpstrDefExt: extPtr,
		Flags:       OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST,
	}
	r, _, _ := procGetSaveFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
	if r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf)
}

func setForegroundWindow(hwnd HWND) {
	procSetForegroundWindow.Call(uintptr(hwnd))
}

func setFocus(hwnd HWND) {
	procSetFocus.Call(uintptr(hwnd))
}

func isWindow(hwnd HWND) bool {
	r, _, _ := procIsWindow.Call(uintptr(hwnd))
	return r != 0
}

func isChild(parent, hwnd HWND) bool {
	r, _, _ := procIsChild.Call(uintptr(parent), uintptr(hwnd))
	return r != 0
}

func getConsoleWindow() HWND {
	r, _, _ := procGetConsoleWindow.Call()
	return HWND(r)
}

// createMonoFont creates a Consolas 9pt font for fixed-width text areas.
func createMonoFont() HFONT {
	face, _ := syscall.UTF16PtrFromString("Consolas")
	height := int32(-12) // 9pt at 96 DPI
	r, _, _ := procCreateFontW.Call(
		uintptr(height),
		0, 0, 0, FW_NORMAL, 0, 0, 0, 0, 0, 0,
		CLEARTYPE_QUALITY, 0,
		uintptr(unsafe.Pointer(face)),
	)
	return HFONT(r)
}
